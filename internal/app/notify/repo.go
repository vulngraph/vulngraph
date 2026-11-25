package notify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// Cipher encrypts and decrypts channel secrets (the Slack bot token, the
// webhook URL). *connector.Cipher satisfies it — passed in at construction so
// notify stays decoupled from the connector domain.
type Cipher interface {
	EncryptWithAAD(plaintext, aad []byte) ([]byte, error)
	DecryptWithAAD(ciphertext, aad []byte) ([]byte, error)
}

// channelAAD binds a sealed secret to its channel row. Without it, anyone who
// can write alert_channels could copy one channel's ciphertext over another's
// and route that channel's alerts to the other's Slack workspace or webhook.
//
// The id is canonicalised first: alert_channels.id is a UUID column, so an
// update addressed as "{ABC…}" or in upper case matches the row, while every
// read seals against the lowercase id Postgres returns. Sealing the raw form
// would leave a secret that never opens again.
func channelAAD(id string) []byte {
	if u, err := uuid.Parse(id); err == nil {
		id = u.String()
	}
	return []byte("graph/alert_channels.config_encrypted/" + id)
}

// secretConfig is the JSON shape stored encrypted in config_encrypted. It holds
// every channel type's secret; only the field relevant to the channel's type is
// set (Slack → BotToken, Webhook → WebhookURL).
type secretConfig struct {
	BotToken   string `json:"bot_token,omitempty"`
	WebhookURL string `json:"webhook_url,omitempty"`
}

// PGRepo persists alert channels in Postgres, with the bot token encrypted.
type PGRepo struct {
	pool   *pgxpool.Pool
	cipher Cipher
}

func NewPGRepo(pool *pgxpool.Pool, cipher Cipher) *PGRepo {
	return &PGRepo{pool: pool, cipher: cipher}
}

const channelCols = `id, type, name, channel, enabled, event_types, severities,
	min_score, owner_teams, environments, route_unowned,
	last_delivered_at, last_status, last_error, created_at, updated_at`

// scannable is satisfied by both pgx.Row and pgx.Rows.
type scannable interface{ Scan(dest ...any) error }

// scanChannel reads channelCols (optionally followed by config_encrypted) into
// a Channel, converting the TEXT/TEXT[] columns to their typed equivalents.
func scanChannel(row scannable, withSecret bool) (Channel, []byte, error) {
	var (
		c      Channel
		typ    string
		events []string
		enc    []byte
	)
	dest := []any{
		&c.ID, &typ, &c.Name, &c.SlackChannel, &c.Enabled,
		&events, &c.Severities, &c.MinScore, &c.OwnerTeams, &c.Environments, &c.RouteUnowned,
		&c.LastDeliveredAt, &c.LastStatus, &c.LastError, &c.CreatedAt, &c.UpdatedAt,
	}
	if withSecret {
		dest = append(dest, &enc)
	}
	if err := row.Scan(dest...); err != nil {
		return Channel{}, nil, err
	}
	c.Type = ChannelType(typ)
	c.EventTypes = toEventTypes(events)
	return c, enc, nil
}

// Create inserts a channel, encrypting its secret. The id is generated here,
// not by the column default, because the secret is sealed to it.
func (r *PGRepo) Create(ctx context.Context, c Channel) (Channel, error) {
	c.ID = uuid.NewString()
	enc, err := r.encrypt(c)
	if err != nil {
		return Channel{}, fmt.Errorf("Create: %w", err)
	}
	row := r.pool.QueryRow(ctx,
		`INSERT INTO alert_channels (id, type, name, channel, config_encrypted, enabled, event_types, severities, min_score,
		                             owner_teams, environments, route_unowned)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 RETURNING `+channelCols,
		c.ID, string(c.Type), c.Name, c.SlackChannel, enc, c.Enabled, eventStrings(c.EventTypes), c.Severities, c.MinScore,
		nonNil(c.OwnerTeams), nonNil(c.Environments), c.RouteUnowned,
	)
	out, _, err := scanChannel(row, false)
	if err != nil {
		return Channel{}, fmt.Errorf("Create: %w", err)
	}
	return out, nil
}

// Update mutates the routing/enabled fields and, when a new token is supplied,
// re-encrypts it. An empty token leaves the stored secret untouched.
func (r *PGRepo) Update(ctx context.Context, c Channel) (Channel, error) {
	events := eventStrings(c.EventTypes)
	var row pgx.Row
	if c.hasSecret() {
		enc, err := r.encrypt(c)
		if err != nil {
			return Channel{}, fmt.Errorf("Update: %w", err)
		}
		row = r.pool.QueryRow(ctx,
			`UPDATE alert_channels
			 SET name=$2, channel=$3, config_encrypted=$4, enabled=$5,
			     event_types=$6, severities=$7, min_score=$8,
			     owner_teams=$9, environments=$10, route_unowned=$11, updated_at=now()
			 WHERE id=$1
			 RETURNING `+channelCols,
			c.ID, c.Name, c.SlackChannel, enc, c.Enabled, events, c.Severities, c.MinScore,
			nonNil(c.OwnerTeams), nonNil(c.Environments), c.RouteUnowned,
		)
	} else {
		row = r.pool.QueryRow(ctx,
			`UPDATE alert_channels
			 SET name=$2, channel=$3, enabled=$4, event_types=$5, severities=$6, min_score=$7,
			     owner_teams=$8, environments=$9, route_unowned=$10, updated_at=now()
			 WHERE id=$1
			 RETURNING `+channelCols,
			c.ID, c.Name, c.SlackChannel, c.Enabled, events, c.Severities, c.MinScore,
			nonNil(c.OwnerTeams), nonNil(c.Environments), c.RouteUnowned,
		)
	}
	out, _, err := scanChannel(row, false)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Channel{}, ErrNotFound
		}
		return Channel{}, fmt.Errorf("Update: %w", err)
	}
	return out, nil
}

func (r *PGRepo) Delete(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM alert_channels WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns all channels (secrets omitted — BotToken stays empty).
func (r *PGRepo) List(ctx context.Context) ([]Channel, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+channelCols+` FROM alert_channels ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		c, _, err := scanChannel(rows, false)
		if err != nil {
			return nil, fmt.Errorf("List scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// EnabledWithSecret returns every enabled channel with its secret opened — the
// dispatch path — and, separately, the enabled channels whose secret did not
// open (GRAPH_SECRET_KEY replaced instead of rotated, or a damaged row). Those
// come back without a secret instead of failing the call, so one bad row cannot
// mute every other channel, and the dispatcher records the failure on each of
// them where an admin sees it.
func (r *PGRepo) EnabledWithSecret(ctx context.Context) (open, unopened []Channel, err error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+channelCols+`, config_encrypted FROM alert_channels WHERE enabled = TRUE`)
	if err != nil {
		return nil, nil, fmt.Errorf("EnabledWithSecret: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		c, enc, err := scanChannel(rows, true)
		if err != nil {
			return nil, nil, fmt.Errorf("EnabledWithSecret scan: %w", err)
		}
		if c, ok := r.openSecret(ctx, c, enc); ok {
			open = append(open, c)
		} else {
			unopened = append(unopened, c)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("EnabledWithSecret rows: %w", err)
	}
	return open, unopened, nil
}

// openSecret fills c's secret from its sealed config. ok is false, and the
// failure logged by channel id, when the secret does not open.
func (r *PGRepo) openSecret(ctx context.Context, c Channel, enc []byte) (Channel, bool) {
	cfg, err := r.decrypt(c.ID, enc)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).Str("channel_id", c.ID).Str("channel_type", string(c.Type)).
			Msg("notify: channel secret did not open; the channel cannot deliver until its secret is re-entered")
		return c, false
	}
	c.BotToken, c.WebhookURL = cfg.BotToken, cfg.WebhookURL
	return c, true
}

// GetWithSecret returns one channel with its token decrypted — used by SendTest.
func (r *PGRepo) GetWithSecret(ctx context.Context, id string) (Channel, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+channelCols+`, config_encrypted FROM alert_channels WHERE id=$1`, id)
	c, enc, err := scanChannel(row, true)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Channel{}, ErrNotFound
		}
		return Channel{}, fmt.Errorf("GetWithSecret: %w", err)
	}
	cfg, err := r.decrypt(c.ID, enc)
	if err != nil {
		return Channel{}, fmt.Errorf("GetWithSecret: decrypt: %w", err)
	}
	c.BotToken, c.WebhookURL = cfg.BotToken, cfg.WebhookURL
	return c, nil
}

// MarkDelivered records the outcome of a dispatch attempt. Best-effort.
func (r *PGRepo) MarkDelivered(ctx context.Context, id, status, errMsg string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE alert_channels SET last_delivered_at=now(), last_status=$2, last_error=$3 WHERE id=$1`,
		id, status, errMsg)
	return err
}

// SealedSecrets lists every channel's ciphertext for the key-rotation pass.
func (r *PGRepo) SealedSecrets(ctx context.Context) ([]SealedSecret, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, config_encrypted FROM alert_channels ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("SealedSecrets: %w", err)
	}
	defer rows.Close()
	var out []SealedSecret
	for rows.Next() {
		var s SealedSecret
		if err := rows.Scan(&s.ChannelID, &s.Ciphertext); err != nil {
			return nil, fmt.Errorf("SealedSecrets scan: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("SealedSecrets: %w", err)
	}
	return out, nil
}

// ResealSecret swaps a channel's ciphertext only while it still equals old.
func (r *PGRepo) ResealSecret(ctx context.Context, id string, old, sealed []byte) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE alert_channels SET config_encrypted=$3 WHERE id=$1 AND config_encrypted=$2`,
		id, old, sealed)
	if err != nil {
		return false, fmt.Errorf("ResealSecret: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (r *PGRepo) encrypt(c Channel) ([]byte, error) {
	raw, err := json.Marshal(secretConfig{BotToken: c.BotToken, WebhookURL: c.WebhookURL})
	if err != nil {
		return nil, fmt.Errorf("encrypt marshal: %w", err)
	}
	enc, err := r.cipher.EncryptWithAAD(raw, channelAAD(c.ID))
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return enc, nil
}

func (r *PGRepo) decrypt(id string, enc []byte) (secretConfig, error) {
	raw, err := r.cipher.DecryptWithAAD(enc, channelAAD(id))
	if err != nil {
		return secretConfig{}, fmt.Errorf("decrypt: %w", err)
	}
	var cfg secretConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return secretConfig{}, fmt.Errorf("decrypt unmarshal: %w", err)
	}
	return cfg, nil
}

// hasSecret reports whether the channel carries a new secret to (re-)encrypt.
func (c Channel) hasSecret() bool { return c.BotToken != "" || c.WebhookURL != "" }

func eventStrings(events []EventType) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = string(e)
	}
	return out
}

func toEventTypes(ss []string) []EventType {
	if len(ss) == 0 {
		return nil
	}
	out := make([]EventType, len(ss))
	for i, s := range ss {
		out[i] = EventType(s)
	}
	return out
}

// nonNil keeps a TEXT[] NOT NULL column from receiving NULL for an unset scope.
func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}
