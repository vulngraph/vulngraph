package notify

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// repo is the storage surface the service depends on.
type repo interface {
	Create(ctx context.Context, c Channel) (Channel, error)
	Update(ctx context.Context, c Channel) (Channel, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]Channel, error)
	// EnabledWithSecret returns the enabled channels whose secret opened, and
	// separately those whose secret did not (returned without one).
	EnabledWithSecret(ctx context.Context) (open, unopened []Channel, err error)
	GetWithSecret(ctx context.Context, id string) (Channel, error)
	MarkDelivered(ctx context.Context, id, status, errMsg string) error
	// SealedSecrets lists every channel's ciphertext, disabled channels included.
	SealedSecrets(ctx context.Context) ([]SealedSecret, error)
	// ResealSecret replaces a channel's ciphertext only while it still equals
	// old, so a secret edited mid-pass is never reverted. ok is false when the
	// row changed or was deleted.
	ResealSecret(ctx context.Context, id string, old, sealed []byte) (ok bool, err error)
}

// Resealer is the cipher surface the key-rotation pass needs. *connector.Cipher
// satisfies it.
type Resealer interface {
	Cipher
	// IsCurrentEnvelope reports whether ct is already sealed under the current key.
	IsCurrentEnvelope(ct []byte) bool
}

// poster delivers a notification to a Slack channel. *slackClient implements it;
// tests fake it.
type poster interface {
	post(ctx context.Context, ch Channel, n Notification, now time.Time) error
}

// DeliveryObserver records the outcome of one delivery attempt, labelled by
// channel and event type so a single broken channel (e.g. a revoked Slack
// token) is distinguishable from every channel failing at once (a real
// outbound outage). *obs.Metrics satisfies it (ObserveNotifyDelivery) —
// defined here, not imported from internal/obs, so this domain's service.go
// stays free of an infra import; the concrete metrics type is wired
// in from the composition root via WithMetrics. Nil disables the metric
// (dispatch still works — the DB last_status column is still written).
type DeliveryObserver interface {
	ObserveNotifyDelivery(channelID, channelType, eventType, status string)
}

// Service routes notifications to matching channels and manages channel config.
type Service struct {
	repo    repo
	slack   poster
	webhook poster
	metrics DeliveryObserver
	now     func() time.Time
	audit   AuditRecorder // nil: no audit rows (the worker, which edits no channel)

	// noRecipientMu guards the no-recipient warning's rate limit: an
	// undelivered finding alert is retried on every enrich, and a routing gap
	// would otherwise log once per retry. The metric still counts every one.
	noRecipientMu         sync.Mutex
	noRecipientLastWarn   time.Time
	noRecipientSuppressed int
}

// noRecipientWarnEvery bounds the no-recipient warning to one per window.
const noRecipientWarnEvery = 5 * time.Minute

func NewService(r *PGRepo) *Service {
	return &Service{repo: r, slack: newSlackClient(), webhook: newWebhookClient(), now: time.Now}
}

// AuditRecorder writes the audit_events row of an admin action that has taken
// effect, and reports its own write failures (audit.Service).
type AuditRecorder interface {
	Record(ctx context.Context, action, targetType, targetID string, details map[string]any)
}

// WithAudit records channel create, update and delete in audit_events.
func (s *Service) WithAudit(a AuditRecorder) *Service { s.audit = a; return s }

func (s *Service) record(ctx context.Context, action, id string, details map[string]any) {
	if s.audit != nil {
		s.audit.Record(ctx, action, AuditTargetChannel, id, details)
	}
}

// channelAuditDetails describes c for an audit row. The bot token and the
// webhook URL are secrets (a URL often embeds a token): only the webhook's
// host is named, the destination an alert would now leave for.
func channelAuditDetails(c Channel) map[string]any {
	d := map[string]any{"type": string(c.Type), "name": c.Name, "enabled": c.Enabled}
	if c.SlackChannel != "" {
		d["slack_channel"] = c.SlackChannel
	}
	if c.WebhookURL != "" {
		if u, err := url.Parse(c.WebhookURL); err == nil {
			d["webhook_host"] = u.Host
		}
	}
	return d
}

// WithMetrics wires the delivery-attempt observer. Call once at construction.
func (s *Service) WithMetrics(o DeliveryObserver) *Service { s.metrics = o; return s }

// observeDelivery records one delivery attempt's outcome. No-op when no
// observer is wired.
func (s *Service) observeDelivery(ch Channel, n Notification, status string) {
	if s.metrics == nil {
		return
	}
	s.metrics.ObserveNotifyDelivery(ch.ID, string(ch.Type), string(n.EventType), status)
}

// ── Channel CRUD ─────────────────────────────────────────────────────────────

func (s *Service) Create(ctx context.Context, c Channel) (Channel, error) {
	switch c.Type {
	case TypeSlack:
		if c.BotToken == "" || c.SlackChannel == "" {
			return Channel{}, ErrMissingConfig
		}
	case TypeWebhook:
		if c.WebhookURL == "" {
			return Channel{}, ErrMissingConfig
		}
		if err := validateWebhookURL(c.WebhookURL); err != nil {
			return Channel{}, fmt.Errorf("Create: %w", err)
		}
	default:
		return Channel{}, ErrUnsupported
	}
	created, err := s.repo.Create(ctx, c)
	if err != nil {
		return Channel{}, fmt.Errorf("Create: %w", err)
	}
	s.record(ctx, AuditActionChannelCreate, created.ID, channelAuditDetails(c))
	return created, nil
}

// Update replaces a channel's config. An empty WebhookURL keeps the stored
// one; a new one is checked like on Create.
func (s *Service) Update(ctx context.Context, c Channel) (Channel, error) {
	if c.WebhookURL != "" {
		if err := validateWebhookURL(c.WebhookURL); err != nil {
			return Channel{}, fmt.Errorf("Update: %w", err)
		}
	}
	updated, err := s.repo.Update(ctx, c)
	if err != nil {
		return Channel{}, fmt.Errorf("Update: %w", err)
	}
	details := channelAuditDetails(c)
	details["secret_replaced"] = c.BotToken != "" || c.WebhookURL != ""
	s.record(ctx, AuditActionChannelUpdate, c.ID, details)
	return updated, nil
}

// validateWebhookURL rejects a destination the SSRF-blocking client would
// refuse anyway (bad scheme, no host, a port other than 80/443), so the
// operator learns at save time rather than at the first failed alert.
func validateWebhookURL(raw string) error {
	if err := safenet.ValidateWebhookURL(raw); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}
	return nil
}

// Delete removes a channel. Its audit row names the channel as it was.
func (s *Service) Delete(ctx context.Context, id string) error {
	channels, err := s.repo.List(ctx)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	details := map[string]any{}
	for _, c := range channels {
		if c.ID == id {
			details = channelAuditDetails(c)
		}
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	s.record(ctx, AuditActionChannelDelete, id, details)
	return nil
}

func (s *Service) List(ctx context.Context) ([]Channel, error) {
	channels, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	return channels, nil
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

// Dispatch sends a notification to every enabled channel whose routing rules
// accept it. Delivery is best-effort and never returns an error to the caller:
// a notification failure must never fail the event that produced it (a confirmed
// phishing domain, an enriched finding, …). Failures are logged and recorded on
// the channel's last_status.
func (s *Service) Dispatch(ctx context.Context, n Notification) {
	if _, err := s.Deliver(ctx, n); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("notify: dispatch failed")
	}
}

// Deliver is Dispatch for a caller that must know whether anyone received the
// notification — one that records "this was announced" and would otherwise
// mark a notice sent that no channel delivered. It returns how many accepting
// channels delivered successfully; an error means the channel list could not
// be read at all.
func (s *Service) Deliver(ctx context.Context, n Notification) (int, error) {
	res, err := s.DeliverCounted(ctx, n)
	if err != nil {
		return 0, fmt.Errorf("Deliver: %w", err)
	}
	return res.Delivered, nil
}

// DeliverCounted is Deliver for a caller that must tell "no channel's routing
// accepts this" (nothing to retry) apart from "accepting channels exist but
// every send failed" (retry later): it reports both counts.
func (s *Service) DeliverCounted(ctx context.Context, n Notification) (DeliveryResult, error) {
	logger := log.FromContext(ctx)

	channels, unopened, err := s.repo.EnabledWithSecret(ctx)
	if err != nil {
		return DeliveryResult{}, fmt.Errorf("DeliverCounted: load channels: %w", err)
	}

	n = withOrphanedOwnerUnowned(append(append([]Channel(nil), channels...), unopened...), n)
	now := s.now()
	delivered := 0
	recipients := 0
	defer func() {
		if recipients > 0 {
			return
		}
		// Every channel rejected it: the alert reached nobody. Counted beside
		// the per-channel delivery outcomes so a routing gap is alertable, not
		// just a log line.
		if suppressed, ok := s.noRecipientWarnDue(now); ok {
			logger.Warn().Str("event", string(n.EventType)).Str("owner", n.Owner).Str("environment", n.Environment).
				Str("title", n.Title).Int("suppressed_since_last", suppressed).
				Msg("notify: no channel accepted the notification — it reached nobody")
		}
		if s.metrics != nil {
			s.metrics.ObserveNotifyDelivery("", "", string(n.EventType), StatusNoRecipient)
		}
	}()
	for _, ch := range channels {
		if !ch.accepts(n) {
			continue
		}
		recipients++
		var status, errMsg string
		if err := s.send(ctx, ch, n, now); err != nil {
			status, errMsg = "error", err.Error()
			logger.Warn().Err(err).Str("channel", ch.Name).Str("event", string(n.EventType)).
				Msg("notify: delivery failed")
		} else {
			status = "ok"
			delivered++
			logger.Info().Str("channel", ch.Name).Str("event", string(n.EventType)).
				Msg("notify: delivered")
		}
		s.observeDelivery(ch, n, status)
		if err := s.repo.MarkDelivered(ctx, ch.ID, status, errMsg); err != nil {
			logger.Error().Err(err).Str("channel", ch.ID).Msg("notify: mark delivered failed")
		}
	}
	// A channel whose secret did not open would have taken this notification:
	// it is a recipient that failed, never an absent one, so the alert stays
	// undelivered (and retried) instead of reading as "no channel wanted it",
	// and the failure lands on the channel's status and the delivery metric.
	for _, ch := range unopened {
		if !ch.accepts(n) {
			continue
		}
		recipients++
		s.observeDelivery(ch, n, "error")
		if err := s.repo.MarkDelivered(ctx, ch.ID, "error", errSecretUnopened); err != nil {
			logger.Error().Err(err).Str("channel", ch.ID).Msg("notify: mark delivered failed")
		}
	}
	return DeliveryResult{Eligible: recipients, Delivered: delivered}, nil
}

// errSecretUnopened is the last_error recorded on a channel whose stored secret
// did not open under the current GRAPH_SECRET_KEY or any retired key.
const errSecretUnopened = "stored channel secret could not be opened with GRAPH_SECRET_KEY or a retired key; re-enter the token or webhook URL"

// HasEnabledChannels reports whether any alert channel is configured and
// enabled. An install with none delivers nothing by design, which a caller
// retrying undelivered alerts must not treat as a failure to retry.
func (s *Service) HasEnabledChannels(ctx context.Context) (bool, error) {
	channels, err := s.repo.List(ctx)
	if err != nil {
		return false, fmt.Errorf("HasEnabledChannels: %w", err)
	}
	for _, ch := range channels {
		if ch.Enabled {
			return true, nil
		}
	}
	return false, nil
}

// noRecipientWarnDue reports whether the no-recipient warning may log now, and
// how many were suppressed since the last one.
func (s *Service) noRecipientWarnDue(now time.Time) (int, bool) {
	s.noRecipientMu.Lock()
	defer s.noRecipientMu.Unlock()
	if !s.noRecipientLastWarn.IsZero() && now.Sub(s.noRecipientLastWarn) < noRecipientWarnEvery {
		s.noRecipientSuppressed++
		return 0, false
	}
	n := s.noRecipientSuppressed
	s.noRecipientLastWarn, s.noRecipientSuppressed = now, 0
	return n, true
}

// StatusNoRecipient is the delivery status recorded (with an empty channel)
// when no enabled channel accepted a notification.
const StatusNoRecipient = "no_recipient"

// withOrphanedOwnerUnowned routes a notification whose owner no enabled channel
// is scoped to as unowned. An owner is often real but channel-less — an IaC
// tier "repo:org/x", a team tag nobody built a channel for — and a strict
// owner scope then dropped the alert on the floor: team channels did not list
// it, and the route_unowned default skipped it because it HAD an owner. The
// owner stays on the notification for display.
func withOrphanedOwnerUnowned(channels []Channel, n Notification) Notification {
	if n.Owner == "" || n.Unowned {
		return n
	}
	for _, ch := range channels {
		if ch.Enabled && containsFold(ch.OwnerTeams, n.Owner) {
			return n
		}
	}
	n.Unowned = true
	return n
}

// send routes to the right backend by channel type.
func (s *Service) send(ctx context.Context, ch Channel, n Notification, now time.Time) error {
	switch ch.Type {
	case TypeSlack:
		return s.slack.post(ctx, ch, n, now)
	case TypeWebhook:
		return s.webhook.post(ctx, ch, n, now)
	default:
		return ErrUnsupported
	}
}

// SendTest posts a canned message to one channel — backs the UI "Test" button.
func (s *Service) SendTest(ctx context.Context, id string) error {
	ch, err := s.repo.GetWithSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("SendTest: %w", err)
	}
	n := Notification{
		EventType: EventTest,
		Severity:  SeverityInfo,
		Title:     "Test alert from Vulngraph",
		Message:   "If you can see this, your Slack alert channel is configured correctly. 🎉",
		Fields: []Field{
			{Label: "Channel", Value: ch.Name, Short: true},
			{Label: "Type", Value: string(ch.Type), Short: true},
		},
	}
	now := s.now()
	if err := s.send(ctx, ch, n, now); err != nil {
		s.observeDelivery(ch, n, "error")
		_ = s.repo.MarkDelivered(ctx, ch.ID, "error", err.Error())
		return fmt.Errorf("SendTest: %w", err)
	}
	s.observeDelivery(ch, n, "ok")
	_ = s.repo.MarkDelivered(ctx, ch.ID, "ok", "")
	return nil
}

// RewrapSecrets re-seals every channel secret not already sealed under c's
// current key: the rows sealed under a retired key.
//
// Idempotent — a current row is skipped, so a second run re-seals nothing. A
// row is written only after its plaintext was recovered; one that cannot be
// opened is named in the error and left untouched, never overwritten.
// Returns how many rows were re-sealed.
func (s *Service) RewrapSecrets(ctx context.Context, c Resealer) (int, error) {
	sealed, err := s.repo.SealedSecrets(ctx)
	if err != nil {
		return 0, fmt.Errorf("RewrapSecrets: %w", err)
	}
	var rewrapped int
	for _, row := range sealed {
		if c.IsCurrentEnvelope(row.Ciphertext) {
			continue
		}
		plain, err := c.DecryptWithAAD(row.Ciphertext, channelAAD(row.ChannelID))
		if err != nil {
			return rewrapped, fmt.Errorf("RewrapSecrets: channel %s could not be opened (left unchanged): %w", row.ChannelID, err)
		}
		enc, err := c.EncryptWithAAD(plain, channelAAD(row.ChannelID))
		if err != nil {
			return rewrapped, fmt.Errorf("RewrapSecrets: channel %s: %w", row.ChannelID, err)
		}
		ok, err := s.repo.ResealSecret(ctx, row.ChannelID, row.Ciphertext, enc)
		if err != nil {
			return rewrapped, fmt.Errorf("RewrapSecrets: channel %s: %w", row.ChannelID, err)
		}
		if ok {
			rewrapped++
		}
	}
	return rewrapped, nil
}
