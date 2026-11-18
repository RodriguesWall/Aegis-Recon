import { useEffect, useState } from "react"
import { api } from "../api/client"
import type { SettingsData } from "../types"

// Keys that are plain string settings (not the secret password, not toggles).
const TEXT_KEYS = [
  "smtp_host",
  "smtp_port",
  "smtp_user",
  "smtp_from",
  "smtp_to",
  "webhook_url",
  "retention_keep",
] as const

export function Settings() {
  const [data, setData] = useState<SettingsData | null>(null)
  const [vals, setVals] = useState<Record<string, string>>({})
  const [emailOn, setEmailOn] = useState(false)
  const [webhookOn, setWebhookOn] = useState(false)
  const [scope, setScope] = useState("scheduled")
  const [security, setSecurity] = useState("starttls")
  const [pass, setPass] = useState("")
  const [status, setStatus] = useState("")
  const [busy, setBusy] = useState(false)

  function hydrate(d: SettingsData) {
    setData(d)
    const s = d.settings
    setVals(s)
    setEmailOn(s.notify_email_enabled === "true")
    setWebhookOn(s.notify_webhook_enabled === "true")
    setScope(s.notify_scope || "scheduled")
    setSecurity(s.smtp_security || "starttls")
    setPass("")
  }

  useEffect(() => {
    void api
      .getSettings()
      .then(hydrate)
      .catch((e) => setStatus(String(e)))
  }, [])

  function field(key: string) {
    return {
      value: vals[key] ?? "",
      onChange: (e: React.ChangeEvent<HTMLInputElement>) =>
        setVals((v) => ({ ...v, [key]: e.target.value })),
    }
  }

  async function save() {
    setBusy(true)
    setStatus("")
    try {
      const body: Record<string, string> = {
        notify_email_enabled: emailOn ? "true" : "false",
        notify_webhook_enabled: webhookOn ? "true" : "false",
        notify_scope: scope,
        smtp_security: security,
        smtp_pass: pass, // empty keeps the stored password
      }
      for (const k of TEXT_KEYS) body[k] = vals[k] ?? ""
      hydrate(await api.updateSettings(body))
      setStatus("Saved.")
    } catch (e) {
      setStatus(String(e))
    } finally {
      setBusy(false)
    }
  }

  if (!data) return <p className="text-muted">Loading…</p>

  const passSet = data.secrets_set.smtp_pass

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-3xl">
          <span className="gradient-text">Settings</span>
        </h1>
        <p className="text-muted">Notifications sent when a scan completes.</p>
      </div>

      <div className="glass-card space-y-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-muted">Notifications</p>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={emailOn} onChange={(e) => setEmailOn(e.target.checked)} />
          Email (SMTP)
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={webhookOn} onChange={(e) => setWebhookOn(e.target.checked)} />
          Webhook
        </label>
        <label className="flex items-center gap-2 text-sm text-muted">
          Scope
          <select
            className="input w-48"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
          >
            <option value="scheduled">Scheduled scans only</option>
            <option value="all">All scans</option>
          </select>
        </label>
      </div>

      <div className="glass-card space-y-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-muted">SMTP</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <Input label="Host" placeholder="smtp.example.com" {...field("smtp_host")} />
          <Input label="Port" placeholder="587" {...field("smtp_port")} />
          <Input label="User" {...field("smtp_user")} />
          <label className="flex flex-col gap-1 text-xs text-muted">
            Security
            <select className="input" value={security} onChange={(e) => setSecurity(e.target.value)}>
              <option value="starttls">STARTTLS</option>
              <option value="ssl">SSL/TLS</option>
              <option value="none">None</option>
            </select>
          </label>
          <Input label="From" placeholder="aegis@example.com" {...field("smtp_from")} />
          <Input label="To" placeholder="you@example.com, team@example.com" {...field("smtp_to")} />
          <label className="flex flex-col gap-1 text-xs text-muted">
            Password {passSet ? "(set — leave blank to keep)" : "(not set)"}
            <input
              className="input"
              type="password"
              placeholder={passSet ? "••••••••" : ""}
              value={pass}
              onChange={(e) => setPass(e.target.value)}
            />
          </label>
        </div>
      </div>

      <div className="glass-card space-y-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-muted">Webhook</p>
        <Input label="URL" placeholder="https://hooks.slack.com/..." {...field("webhook_url")} />
      </div>

      <div className="glass-card space-y-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-muted">Retention</p>
        <Input
          label="Keep last N scans per service (0 = unlimited; default 30)"
          placeholder="30"
          {...field("retention_keep")}
        />
      </div>

      <div className="flex items-center gap-3">
        <button className="btn-primary" disabled={busy} onClick={() => void save()}>
          Save
        </button>
        {status && <span className="text-sm text-muted">{status}</span>}
      </div>
    </div>
  )
}

function Input({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string
  value: string
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void
  placeholder?: string
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted">
      {label}
      <input className="input" value={value} onChange={onChange} placeholder={placeholder} />
    </label>
  )
}
