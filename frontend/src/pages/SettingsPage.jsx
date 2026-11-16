import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  CheckCircle2,
  CircleAlert,
  Database,
  FolderLock,
  Globe,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  Settings2,
  ShieldCheck,
} from 'lucide-react'
import {
  checkApiHealth,
  checkApiReadiness,
  getApiBaseUrl,
  getApiConfiguration,
  resetApiBaseUrl,
  setApiBaseUrl,
} from '../api/client'

function StatusIndicator({ result, label }) {
  if (result === null) {
    return <span className="settings-status pending">Not checked</span>
  }

  if (result) {
    return (
      <span className="settings-status connected">
        <CheckCircle2 size={14} /> Connected
      </span>
    )
  }

  return (
    <span className="settings-status disconnected">
      <CircleAlert size={14} /> Unavailable
    </span>
  )
}

function SettingsPage() {
  const [apiUrl, setApiUrl] = useState(getApiBaseUrl())
  const [draftUrl, setDraftUrl] = useState(getApiBaseUrl())
  const [health, setHealth] = useState(null)
  const [readiness, setReadiness] = useState(null)
  const [configuration, setConfiguration] = useState(null)
  const [checking, setChecking] = useState(false)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [lastChecked, setLastChecked] = useState(null)

  const runDiagnostics = useCallback(async () => {
    setChecking(true)
    setError('')

    const [healthResult, readinessResult, configResult] =
      await Promise.allSettled([
        checkApiHealth(),
        checkApiReadiness(),
        getApiConfiguration(),
      ])

    setHealth(
      healthResult.status === 'fulfilled' &&
      healthResult.value?.status === 'ok'
    )

    setReadiness(
      readinessResult.status === 'fulfilled' &&
      readinessResult.value?.status === 'ok' &&
      readinessResult.value?.database === 'ok'
    )

    setConfiguration(
      configResult.status === 'fulfilled'
        ? configResult.value
        : null
    )

    if (
      healthResult.status === 'rejected' &&
      readinessResult.status === 'rejected'
    ) {
      setError(
        healthResult.reason?.response?.data?.detail ||
        healthResult.reason?.message ||
        'Unable to connect to the DepRisk API.'
      )
    } else if (configResult.status === 'rejected') {
      setError('Connection is available, but workspace configuration could not be retrieved.')
    }

    setLastChecked(new Date())
    setChecking(false)
  }, [])

  useEffect(() => {
    runDiagnostics()
  }, [runDiagnostics])

  const handleSave = async (event) => {
    event.preventDefault()
    setSaving(true)
    setMessage('')
    setError('')

    try {
      const savedUrl = setApiBaseUrl(draftUrl)
      setApiUrl(savedUrl)
      setDraftUrl(savedUrl)
      setMessage('API connection URL saved successfully.')
      await runDiagnostics()
    } catch (err) {
      setError(err.message || 'Unable to save API URL.')
    } finally {
      setSaving(false)
    }
  }

  const handleReset = async () => {
    setSaving(true)
    setMessage('')
    setError('')

    try {
      const defaultUrl = resetApiBaseUrl()
      setApiUrl(defaultUrl)
      setDraftUrl(defaultUrl)
      setMessage('API URL restored to its default value.')
      await runDiagnostics()
    } catch (err) {
      setError(err.message || 'Unable to reset API URL.')
    } finally {
      setSaving(false)
    }
  }

  const isDirty = draftUrl.trim() !== apiUrl

  return (
    <section className="settings-page">
      <div className="settings-header">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" /> SYSTEM CONFIGURATION
          </div>
          <h1>Settings<span className="heading-period">.</span></h1>
          <p>Manage your local analysis connection and inspect system readiness.</p>
        </div>

        <button
          className="settings-refresh-button"
          onClick={runDiagnostics}
          disabled={checking}
        >
          <RefreshCw size={15} className={checking ? 'settings-spinning' : ''} />
          {checking ? 'Checking...' : 'Refresh status'}
        </button>
      </div>

      {(message || error) && (
        <div className={`settings-feedback ${error ? 'error' : 'success'}`}>
          {error ? <CircleAlert size={16} /> : <CheckCircle2 size={16} />}
          <span>{error || message}</span>
        </div>
      )}

      <div className="settings-status-grid">
        <article className="panel settings-status-card">
          <div className="settings-card-icon"><Server size={18} /></div>
          <div className="settings-card-copy">
            <span>API SERVICE</span>
            <strong>{health === null ? 'Checking' : health ? 'Online' : 'Offline'}</strong>
          </div>
          <StatusIndicator result={health} label="API" />
        </article>

        <article className="panel settings-status-card">
          <div className="settings-card-icon"><Database size={18} /></div>
          <div className="settings-card-copy">
            <span>DATABASE</span>
            <strong>{readiness === null ? 'Checking' : readiness ? 'Ready' : 'Unavailable'}</strong>
          </div>
          <StatusIndicator result={readiness} label="Database" />
        </article>

        <article className="panel settings-status-card">
          <div className="settings-card-icon"><FolderLock size={18} /></div>
          <div className="settings-card-copy">
            <span>LOCAL SCANNING</span>
            <strong>
              {configuration === null
                ? 'Unknown'
                : configuration.local_scanning_enabled
                  ? 'Enabled'
                  : 'Disabled'}
            </strong>
          </div>
          <span className={`settings-status ${
            configuration?.local_scanning_enabled ? 'connected' : 'pending'
          }`}>
            {configuration === null
              ? 'Not available'
              : configuration.local_scanning_enabled
                ? 'Configured'
                : 'Not configured'}
          </span>
        </article>
      </div>

      <div className="settings-sections">
        <section className="panel settings-section">
          <div className="settings-section-heading">
            <div className="settings-section-icon"><Globe size={18} /></div>
            <div>
              <h2>API connection</h2>
              <p>Configure the backend endpoint used by this application.</p>
            </div>
          </div>

          <form onSubmit={handleSave} className="settings-form">
            <label htmlFor="settings-api-url">Backend API base URL</label>
            <input
              id="settings-api-url"
              type="url"
              value={draftUrl}
              onChange={(event) => setDraftUrl(event.target.value)}
              placeholder="http://127.0.0.1:8000"
              required
            />
            <p className="settings-help">
              All scan, report, repository and diagnostic requests use this URL.
              Changing it updates the connection for the current application session
              and saves the preference in this browser.
            </p>

            <div className="settings-form-actions">
              <button
                className="settings-primary-button"
                type="submit"
                disabled={saving || !isDirty || !draftUrl.trim()}
              >
                <Save size={15} />
                {saving ? 'Saving...' : 'Save connection'}
              </button>

              <button
                className="settings-secondary-button"
                type="button"
                onClick={handleReset}
                disabled={saving || apiUrl === (
                  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'
                )}
              >
                <RotateCcw size={15} />
                Reset default
              </button>
            </div>
          </form>

          <div className="settings-current-url">
            <span>ACTIVE CONNECTION</span>
            <code>{apiUrl}</code>
          </div>
        </section>

        <section className="panel settings-section">
          <div className="settings-section-heading">
            <div className="settings-section-icon"><ShieldCheck size={18} /></div>
            <div>
              <h2>Workspace security</h2>
              <p>Read-only information provided by the backend.</p>
            </div>
          </div>

          <div className="settings-detail-row">
            <div>
              <span>Local scanning</span>
              <small>Whether the backend has a valid local scan workspace</small>
            </div>
            <strong>
              {configuration === null
                ? 'Unknown'
                : configuration.local_scanning_enabled
                  ? 'Enabled'
                  : 'Disabled'}
            </strong>
          </div>

          <div className="settings-workspace-path">
            <span>CONFIGURED WORKSPACE ROOT</span>
            <code>{configuration?.workspace_root || 'Not configured or unavailable'}</code>
          </div>

          <div className="settings-security-note">
            <ShieldCheck size={16} />
            <span>
              Workspace restrictions are controlled by the backend environment.
              They cannot be changed from this browser.
            </span>
          </div>
        </section>

        <section className="panel settings-section">
          <div className="settings-section-heading">
            <div className="settings-section-icon"><Activity size={18} /></div>
            <div>
              <h2>System diagnostics</h2>
              <p>Latest health and readiness verification.</p>
            </div>
          </div>

          <div className="settings-detail-row">
            <div>
              <span>API liveness</span>
              <small>GET /health</small>
            </div>
            <StatusIndicator result={health} label="API" />
          </div>

          <div className="settings-detail-row">
            <div>
              <span>Database readiness</span>
              <small>GET /health/ready</small>
            </div>
            <StatusIndicator result={readiness} label="Database" />
          </div>

          <div className="settings-detail-row">
            <div>
              <span>Last checked</span>
              <small>Local browser time</small>
            </div>
            <strong>
              {lastChecked ? lastChecked.toLocaleString() : 'Not checked'}
            </strong>
          </div>
        </section>

        <section className="panel settings-section settings-about">
          <div className="settings-section-heading">
            <div className="settings-section-icon"><Settings2 size={18} /></div>
            <div>
              <h2>Application information</h2>
              <p>Current DepRisk frontend environment.</p>
            </div>
          </div>

          <div className="settings-detail-row">
            <span>Application</span>
            <strong>DepRisk</strong>
          </div>
          <div className="settings-detail-row">
            <span>Environment</span>
            <strong>Local development</strong>
          </div>
          <div className="settings-detail-row">
            <span>Frontend version</span>
            <strong>0.1.0</strong>
          </div>
        </section>
      </div>
    </section>
  )
}

export default SettingsPage