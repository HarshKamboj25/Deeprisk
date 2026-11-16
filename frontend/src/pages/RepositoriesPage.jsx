import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertCircle,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  FolderGit2,
  Globe,
  RefreshCw,
  Search,
  ShieldAlert,
} from 'lucide-react'
import { getRepositories, getScanHistory } from '../api/client'

function formatDate(value) {
  if (!value) return 'Not available'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Not available'
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function LatestStatus({ status }) {
  if (!status) return <span className="repository-no-scan">No scans yet</span>

  const icons = {
    succeeded: CheckCircle2,
    failed: AlertCircle,
    running: RefreshCw,
    pending: Clock3,
  }
  const Icon = icons[status] || Clock3

  return (
    <span className={`history-status ${status}`}>
      <Icon size={13} />
      {status}
    </span>
  )
}

export default function RepositoriesPage({ onViewScans }) {
  const [repositories, setRepositories] = useState([])
  const [scanStats, setScanStats] = useState({})
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')

  const loadRepositories = useCallback(async (isRefresh = false) => {
    const refreshStartedAt = Date.now()
    if (isRefresh) {
      setRefreshing(true)
    } else {
      setLoading(true)
    }
    setError('')

    try {
      const result = await getRepositories()
      const records = Array.isArray(result) ? result : Array.isArray(result.value) ? result.value : []
      setRepositories(records)

      const stats = await Promise.all(
        records.map(async (repository) => {
          try {
            const history = await getScanHistory({
              repository_id: repository.id,
              limit: 1,
              offset: 0,
            })

            return [
              repository.id,
              {
                total: history.total || 0,
                latest: history.items?.[0] || null,
              },
            ]
          } catch {
            return [repository.id, { total: null, latest: null }]
          }
        })
      )

      setScanStats(Object.fromEntries(stats))
    } catch (err) {
      setError(
        err.response?.data?.detail ||
        err.message ||
        'Unable to load registered repositories.'
      )
    } finally {
      setLoading(false)

      if (isRefresh) {
        const remaining = Math.max(0, 900 - (Date.now() - refreshStartedAt))

        if (remaining > 0) {
          await new Promise((resolve) => window.setTimeout(resolve, remaining))
        }

        setRefreshing(false)
      }
    }
  }, [])

  useEffect(() => {
    loadRepositories()
  }, [loadRepositories])

  const filteredRepositories = useMemo(() => {
    const term = search.trim().toLowerCase()
    if (!term) return repositories

    return repositories.filter((repository) =>
      [
        repository.name,
        repository.source_type,
        repository.canonical_source,
      ].some((value) => String(value || '').toLowerCase().includes(term))
    )
  }, [repositories, search])

  const totalScans = Object.values(scanStats).reduce(
    (sum, stats) => sum + (stats.total || 0),
    0
  )

  return (
    <section className={`repositories-page ${refreshing ? "is-refreshing" : ""}`} aria-busy={refreshing || loading}>
      <div className="eyebrow">
        <span className="eyebrow-line" /> WORKSPACE / REPOSITORIES
      </div>

      <div className="repository-heading-row">
        <div>
          <h1 className="repository-title">Repositories<span className="heading-period">.</span></h1>
          <p className="page-subtitle">
            Manage registered codebases and inspect their scan activity.
          </p>
        </div>

        <button
          className="history-refresh-button"
          onClick={() => loadRepositories(true)}
          disabled={loading || refreshing}
        >
          <RefreshCw size={15} className={refreshing ? "is-spinning" : ""} />
          Refresh
        </button>
      </div>

      <div className="history-summary">
        <div className="history-summary-card">
          <span className="history-summary-label">REGISTERED REPOSITORIES</span>
          <strong>{loading && repositories.length === 0 ? '...' : repositories.length}</strong>
          <small>Saved repository records</small>
        </div>
        <div className="history-summary-card">
          <span className="history-summary-label">TOTAL SCANS</span>
          <strong>{loading ? '...' : totalScans}</strong>
          <small>Across registered repositories</small>
        </div>
        <div className="history-summary-card">
          <span className="history-summary-label">LATEST ACTIVITY</span>
          <strong className="repository-activity-value">
            {loading ? '...' : repositories.length === 0 ? 'None' : 'Available'}
          </strong>
          <small>Latest persisted scan records</small>
        </div>
      </div>

      <div className="panel repository-panel">
        <div className="repository-toolbar">
          <div>
            <div className="panel-kicker">REPOSITORY INVENTORY</div>
            <h2>Registered codebases</h2>
          </div>

          <div className="history-search repository-search">
            <Search size={16} />
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search repositories..."
              aria-label="Search registered repositories"
            />
          </div>
        </div>

        {error && (
          <div className="history-error" role="alert">
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {loading && repositories.length === 0 ? (
          <div className="repository-empty">Loading registered repositories...</div>
        ) : filteredRepositories.length === 0 ? (
          <div className="repository-empty">
            <FolderGit2 size={27} />
            <strong>
              {repositories.length === 0
                ? 'No repositories registered'
                : 'No matching repositories'}
            </strong>
            <span>
              {repositories.length === 0
                ? 'Run your first repository scan to register a codebase.'
                : 'Try another repository name or source.'}
            </span>
          </div>
        ) : (
          <div className="repository-list">
            {filteredRepositories.map((repository) => {
              const stats = scanStats[repository.id]
              const latest = stats?.latest

              return (
                <article className="repository-card" key={repository.id}>
                  <div className="repository-card-main">
                    <div className="repository-icon">
                      {repository.source_type === 'github'
                        ? <Globe size={19} />
                        : <FolderGit2 size={19} />}
                    </div>

                    <div className="repository-identity">
                      <h3>{repository.name}</h3>
                      <span className="repository-source-label">
                        {repository.source_type === 'github' ? 'GitHub repository' : 'Local repository'}
                      </span>
                      <code title={repository.canonical_source}>
                        {repository.canonical_source}
                      </code>
                    </div>
                  </div>

                  <div className="repository-card-details">
                    <div className="repository-detail">
                      <span>REGISTERED</span>
                      <strong>{formatDate(repository.created_at)}</strong>
                    </div>
                    <div className="repository-detail">
                      <span>TOTAL SCANS</span>
                      <strong>
                        {stats?.total === null ? 'Unavailable' : stats?.total ?? '...'}
                      </strong>
                    </div>
                    <div className="repository-detail">
                      <span>LATEST SCAN</span>
                      <LatestStatus status={latest?.status} />
                      {latest && (
                        <small>{formatDate(latest.created_at)}</small>
                      )}
                    </div>
                  </div>

                  <div className="repository-card-actions">
                    <button
                      className="history-open-button"
                      onClick={() => onViewScans(repository.name)}
                    >
                      View scans <ArrowUpRight size={14} />
                    </button>
                  </div>
                </article>
              )
            })}
          </div>
        )}

        <div className="repository-footer">
          Showing {filteredRepositories.length} of {repositories.length} registered repositories
        </div>
      </div>
    </section>
  )
}