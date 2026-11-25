import { useState, type FormEvent } from "react";
import { Bell, Plus, Send, CheckCircle2, XCircle, MessageSquare, Webhook } from "lucide-react";
import {
  useAlertChannels, useCreateAlertChannel, useUpdateAlertChannel,
  useDeleteAlertChannel, useTestAlertChannel, useIsAdmin,
  type AlertChannel, type AlertChannelInput,
} from "../lib/queries";
import type { EventType } from "../lib/api";
import { Button, Card, Empty, ErrorNote, Loading } from "../components/ui";
import { FormField, FormActions, ConfirmButton } from "../components/form";
import { ChannelRoutingFields, RoutingScopeSummary } from "../components/ChannelRoutingScope";
import { timeAgo as timeAgoBase } from "../lib/format";

const timeAgo = (iso?: string) => timeAgoBase(iso, "compact");

// Event types offered for per-channel routing. Ids/values come straight from
// the generated OpenAPI schema (the EventType alias in lib/api.ts) — this
// Record is `satisfies`-checked against that union, so a backend addition
// fails the build here instead of silently missing from the UI.
type EventTypeId = EventType;

const EVENT_TYPE_COPY = {
  phishing:    { label: "Confirmed phishing",         hint: "A domain-monitor candidate confirmed as phishing" },
  finding:     { label: "New high/critical finding",  hint: "A newly surfaced high or critical finding" },
  decision:    { label: "Decision executed/queued",   hint: "An agent decision was executed or parked for approval" },
  approval:    { label: "Decision approved",          hint: "A human approved a queued decision" },
  drift:       { label: "Inventory drift",            hint: "New exposure or asset detected at sync" },
  connector:   { label: "Connector failure",          hint: "A connector sync failed permanently" },
  query_match: { label: "Saved query match",          hint: "A scheduled saved query matched on its most recent run" },
  suppression_expiry: { label: "Suppression expiring", hint: "A finding suppression expires within 14 days and needs review" },
} satisfies Record<EventTypeId, { label: string; hint: string }>;

const EVENT_TYPES: { id: EventTypeId; label: string; hint: string }[] = (
  Object.keys(EVENT_TYPE_COPY) as EventTypeId[]
).map((id) => ({ id, ...EVENT_TYPE_COPY[id] }));

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

// The backend lists routable event types that nothing emits yet
// (unwired_event_types); they stay selectable so a channel can be pre-routed,
// but are labelled so nobody relies on an alert that never fires.
const NOT_EMITTED = "not emitted yet";

const eventLabel = (id: string) => EVENT_TYPES.find((t) => t.id === id)?.label ?? id;

const EMPTY_FORM: AlertChannelInput = {
  type: "slack",
  name: "",
  channel: "",
  bot_token: "",
  webhook_url: "",
  enabled: true,
  event_types: [],
  severities: [],
  min_score: 0,
  owner_teams: [],
  environments: [],
  route_unowned: false,
};

function StatusPill({ ch }: { ch: AlertChannel }) {
  if (!ch.last_status) {
    return <span className="text-[11px] text-text-3">never sent</span>;
  }
  if (ch.last_status === "ok") {
    return (
      <span className="flex items-center gap-1 text-[11px] text-emerald">
        <CheckCircle2 className="h-3 w-3" /> delivered {ch.last_delivered_at ? timeAgo(ch.last_delivered_at) : ""}
      </span>
    );
  }
  return (
    <div className="flex items-start gap-1 text-[11px] text-red">
      <XCircle className="mt-[1px] h-3 w-3 shrink-0" />
      <span>failed{ch.last_error ? `: ${ch.last_error}` : ""}</span>
    </div>
  );
}

// destinationLabel shows the actual, meaningful target for a channel's type —
// never the raw `channel` field, which is Slack-only and empty for webhooks.
function destinationLabel(ch: AlertChannel): string {
  if (ch.type === "webhook") {
    return ch.has_token ? "Webhook configured" : "Webhook (no URL set)";
  }
  return ch.channel || "(no channel set)";
}

function ChannelForm({
  initial, onSubmit, onCancel, submitting, isEdit, unwired,
}: {
  initial: AlertChannelInput;
  unwired: string[];
  onSubmit: (v: AlertChannelInput) => void;
  onCancel: () => void;
  submitting: boolean;
  isEdit: boolean;
}) {
  const [form, setForm] = useState<AlertChannelInput>(initial);
  const [submitAttempted, setSubmitAttempted] = useState(false);

  const toggleEvent = (id: string) =>
    setForm((f) => ({
      ...f,
      event_types: f.event_types.includes(id)
        ? f.event_types.filter((e) => e !== id)
        : [...f.event_types, id],
    }));
  const toggleSeverity = (s: string) =>
    setForm((f) => ({
      ...f,
      severities: f.severities.includes(s)
        ? f.severities.filter((x) => x !== s)
        : [...f.severities, s],
    }));

  const isWebhook = form.type === "webhook";
  const nameMissing = !form.name.trim();
  const webhookMissing = isWebhook && !isEdit && !form.webhook_url?.trim();
  const channelMissing = !isWebhook && !form.channel.trim();
  const tokenMissing = !isWebhook && !isEdit && !form.bot_token?.trim();
  const canSubmit = !nameMissing && !webhookMissing && !channelMissing && !tokenMissing;

  const missingLabels = [
    nameMissing && "name",
    webhookMissing && "webhook URL",
    channelMissing && "Slack channel",
    tokenMissing && "bot token",
  ].filter(Boolean) as string[];
  const disabledReason = missingLabels.length > 0 ? `Missing: ${missingLabels.join(", ")}` : undefined;

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitAttempted(true);
    if (canSubmit) onSubmit(form);
  }

  function clampScore(raw: string): number {
    // Guard against Number("") -> NaN being written into form state, and clamp
    // to the valid 0-100 range so an out-of-range value can't be POSTed.
    const n = Number(raw);
    if (raw === "" || Number.isNaN(n)) return 0;
    return Math.min(100, Math.max(0, Math.round(n)));
  }

  return (
    <Card>
      <form className="space-y-4 p-1" onSubmit={handleSubmit}>
        {/* Type + name */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <FormField
            as="select"
            label="Type"
            value={form.type}
            disabled={isEdit}
            onChange={(e) => setForm({ ...form, type: e.target.value })}
          >
            <option value="slack">Slack</option>
            <option value="webhook">Webhook</option>
          </FormField>
          <FormField
            label="Name"
            value={form.name}
            placeholder="Security alerts"
            required
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            error={submitAttempted && nameMissing ? "Name is required." : undefined}
          />
        </div>

        {isWebhook ? (
          /* Webhook URL */
          <FormField
            label={`Webhook URL${isEdit ? " (leave blank to keep current)" : ""}`}
            type="password"
            value={form.webhook_url}
            placeholder="https://hooks.example.com/services/…"
            required={!isEdit}
            onChange={(e) => setForm({ ...form, webhook_url: e.target.value })}
            error={submitAttempted && webhookMissing ? "Webhook URL is required." : undefined}
            help="A JSON alert is POSTed here per matching event. Point it at your bridge to Jira/PagerDuty/Teams, or a generic receiver."
          />
        ) : (
          <>
            {/* Slack channel */}
            <FormField
              label="Slack channel"
              value={form.channel}
              placeholder="#security-alerts"
              required
              onChange={(e) => setForm({ ...form, channel: e.target.value })}
              error={submitAttempted && channelMissing ? "Slack channel is required." : undefined}
            />
            {/* Bot token */}
            <FormField
              label={`Bot token${isEdit ? " (leave blank to keep current)" : ""}`}
              type="password"
              value={form.bot_token}
              placeholder="xoxb-…"
              required={!isEdit}
              onChange={(e) => setForm({ ...form, bot_token: e.target.value })}
              error={submitAttempted && tokenMissing ? "Bot token is required." : undefined}
              help="A Slack bot token with chat:write. Invite the bot to the channel."
            />
          </>
        )}

        {/* Event routing */}
        <div>
          <span className="mb-1.5 block text-[11px] font-medium text-text-2">
            Send for events <span className="text-text-3">(none selected = all events)</span>
          </span>
          <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {EVENT_TYPES.map((ev) => {
              const on = form.event_types.includes(ev.id);
              const notEmitted = unwired.includes(ev.id);
              return (
                <button
                  key={ev.id}
                  type="button"
                  onClick={() => toggleEvent(ev.id)}
                  title={notEmitted ? `${ev.hint}. Nothing emits this event yet, so this channel will not receive it.` : ev.hint}
                  className={`rounded border px-2 py-1.5 text-left text-[11px] transition-colors ${
                    on ? "border-teal/40 bg-teal/10 text-teal" : "border-border-subtle text-text-3 hover:bg-surface"
                  }`}
                >
                  {ev.label}
                  {notEmitted && <span className="ml-1 text-amber">({NOT_EMITTED})</span>}
                </button>
              );
            })}
          </div>
        </div>

        {/* Severity routing */}
        <div>
          <span className="mb-1.5 block text-[11px] font-medium text-text-2">
            Severities <span className="text-text-3">(none = all)</span>
          </span>
          <div className="flex flex-wrap gap-1.5">
            {SEVERITIES.map((s) => {
              const on = form.severities.includes(s);
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleSeverity(s)}
                  className={`rounded border px-2 py-1 text-[11px] capitalize transition-colors ${
                    on ? "border-teal/40 bg-teal/10 text-teal" : "border-border-subtle text-text-3 hover:bg-surface"
                  }`}
                >
                  {s}
                </button>
              );
            })}
          </div>
        </div>

        {/* Owner / environment scope */}
        <ChannelRoutingFields
          value={{ owner_teams: form.owner_teams, environments: form.environments, route_unowned: form.route_unowned }}
          onChange={(scope) => setForm((f) => ({ ...f, ...scope }))}
        />

        {/* Min score */}
        <div className="max-w-[200px]">
          <FormField
            label="Minimum score"
            type="number"
            min={0}
            max={100}
            value={form.min_score}
            onChange={(e) => setForm({ ...form, min_score: clampScore(e.target.value) })}
            help="Only alert when the event's score ≥ this (0 = all)."
          />
        </div>

        {/* Enabled */}
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            className="h-4 w-4 accent-teal"
          />
          <span className="text-[12px] text-text-2">Enabled</span>
        </label>

        <div className="pt-1">
          <FormActions
            submitLabel={isEdit ? "Save changes" : "Create channel"}
            onCancel={onCancel}
            isPending={submitting}
            disabled={!canSubmit}
            disabledReason={disabledReason}
            type="submit"
          />
        </div>
      </form>
    </Card>
  );
}

function ChannelRow({ ch, isAdmin, unwired }: { ch: AlertChannel; isAdmin: boolean; unwired: string[] }) {
  const [editing, setEditing] = useState(false);
  const update = useUpdateAlertChannel();
  const del = useDeleteAlertChannel();
  const test = useTestAlertChannel();
  const [testMsg, setTestMsg] = useState<string>("");

  function startEdit() {
    update.reset();
    setTestMsg("");
    setEditing(true);
  }

  if (editing) {
    return (
      <>
        <ChannelForm
          isEdit
          unwired={unwired}
          initial={{
            type: ch.type, name: ch.name, channel: ch.channel, bot_token: "", webhook_url: "",
            enabled: ch.enabled, event_types: ch.event_types, severities: ch.severities, min_score: ch.min_score,
            owner_teams: ch.owner_teams ?? [], environments: ch.environments ?? [], route_unowned: ch.route_unowned ?? false,
          }}
          submitting={update.isPending}
          onCancel={() => setEditing(false)}
          onSubmit={(input) =>
            update.mutate({ id: ch.id, input }, { onSuccess: () => setEditing(false) })
          }
        />
        {update.isError && (
          <div className="mt-2">
            <ErrorNote message={(update.error as Error)?.message ?? "Could not save changes."} />
          </div>
        )}
      </>
    );
  }

  const runTest = () => {
    setTestMsg("");
    test.mutate(ch.id, {
      onSuccess: (res) =>
        setTestMsg(res.ok ? "Test sent ✓" : "Test failed — the channel rejected the message. Check its configuration."),
      onError: (e) => setTestMsg(`Test failed: ${(e as Error).message}`),
    });
  };

  // An "all events" channel shows no per-event chips, so name the events it
  // will never receive in a line of its own.
  const allEventsUnwired = ch.event_types.length === 0 ? (ch.unwired_event_types ?? []) : [];

  return (
    <div className="rounded-xl border border-border-subtle bg-surface p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            {ch.type === "webhook" ? (
              <Webhook className="h-4 w-4 text-text-2" />
            ) : (
              <MessageSquare className="h-4 w-4 text-text-2" />
            )}
            <span className="truncate text-[13px] font-medium text-text">{ch.name}</span>
            <span className="rounded border border-border-subtle px-1.5 py-0.5 text-[10px] font-medium uppercase text-text-3">
              {ch.type}
            </span>
            <span className="font-mono text-[12px] text-text-3">{destinationLabel(ch)}</span>
            {!ch.enabled && (
              <span className="rounded border border-border-subtle px-1.5 py-0.5 text-[11px] font-medium uppercase text-text-3">
                disabled
              </span>
            )}
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-1">
            {ch.event_types.length === 0 ? (
              <span className="text-[11px] text-text-3">all events</span>
            ) : (
              ch.event_types.map((e) => (
                <span key={e} className="rounded border border-border-subtle bg-surface-2 px-1.5 py-0.5 text-[11px] text-text-2">
                  {eventLabel(e)}
                  {ch.unwired_event_types?.includes(e) && <span className="ml-1 text-amber">({NOT_EMITTED})</span>}
                </span>
              ))
            )}
            {ch.severities.length > 0 && (
              <span className="ml-1 text-[11px] text-text-3">· {ch.severities.join("/")}</span>
            )}
            {ch.min_score > 0 && <span className="text-[11px] text-text-3">· score ≥ {ch.min_score}</span>}
            <RoutingScopeSummary
              scope={{ owner_teams: ch.owner_teams ?? [], environments: ch.environments ?? [], route_unowned: !!ch.route_unowned }}
            />
          </div>
          {allEventsUnwired.length > 0 && (
            <div className="mt-1 text-[11px] text-amber">
              {allEventsUnwired.map(eventLabel).join(", ")}: {NOT_EMITTED}, so this channel never receives them.
            </div>
          )}
          <div className="mt-1.5"><StatusPill ch={ch} /></div>
          {testMsg && <div className="mt-1 text-[11px] text-text-2">{testMsg}</div>}
        </div>

        {isAdmin && (
          <div className="flex shrink-0 gap-1.5">
            <Button onClick={runTest} disabled={test.isPending} title="Send a test message">
              <Send className="mr-1 h-3 w-3" /> Test
            </Button>
            <Button onClick={startEdit}>Edit</Button>
            <ConfirmButton
              label="Delete"
              verb="delete"
              onConfirm={() => del.mutate(ch.id)}
              isPending={del.isPending}
            />
          </div>
        )}
      </div>
      {del.isError && (
        <div className="mt-2">
          <ErrorNote message={(del.error as Error)?.message ?? "Could not delete channel."} />
        </div>
      )}
    </div>
  );
}

export function AlertsSection() {
  const isAdmin = useIsAdmin();
  const { data, isLoading } = useAlertChannels();
  const create = useCreateAlertChannel();
  const [adding, setAdding] = useState(false);

  const channels = data?.channels ?? [];
  const unwired = data?.unwired_event_types ?? [];

  function startAdding() {
    create.reset();
    setAdding(true);
  }

  return (
    <div>
      <div className="mb-5 flex items-center justify-between">
        <div>
          <h2 className="flex items-center gap-2 text-[15px] font-semibold text-text">
            <Bell className="h-4 w-4 text-teal" /> Alerts
          </h2>
          <p className="mt-0.5 text-[12px] text-text-3">
            Push events to Slack or a webhook — confirmed phishing, new findings, agent decisions, saved query matches and expiring suppressions.
            Each channel routes only the events you choose.
          </p>
        </div>
        {isAdmin && !adding && (
          <Button variant="primary" className="flex shrink-0 items-center whitespace-nowrap" onClick={startAdding}>
            <Plus className="mr-1 h-4 w-4" /> Add channel
          </Button>
        )}
      </div>

      {adding && (
        <div className="mb-4">
          <ChannelForm
            isEdit={false}
            unwired={unwired}
            initial={EMPTY_FORM}
            submitting={create.isPending}
            onCancel={() => setAdding(false)}
            onSubmit={(input) => create.mutate(input, { onSuccess: () => setAdding(false) })}
          />
          {create.isError && (
            <div className="mt-2">
              <ErrorNote message={(create.error as Error)?.message ?? "Could not create channel."} />
            </div>
          )}
        </div>
      )}

      {isLoading && <Loading />}

      {!isLoading && channels.length === 0 && !adding && (
        <Empty message="No alert channels yet. Add a Slack or webhook channel to start receiving security alerts." />
      )}

      {channels.length > 0 && (
        <div className="space-y-3">
          {channels.map((ch) => (
            <ChannelRow key={ch.id} ch={ch} isAdmin={isAdmin} unwired={unwired} />
          ))}
        </div>
      )}
    </div>
  );
}
