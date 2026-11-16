import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  AlertCircle,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  RefreshCw,
  Search,
  ShieldAlert,
} from 'lucide-react'
import { getScanHistory, getScanReport } from '../api/client'

const PAGE_SIZE = 20

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

function formatDuration(startedAt, finishedAt) {
  if (!startedAt || !finishedAt) return 'In progress'
  const start = new Date(startedAt).getTime()
  const finish = new Date(finishedAt).getTime()
  if (!Number.isFinite(start) || !Number.isFinite(finish)) return 'Unknown'
  return `${((finish - start) / 1000).toFixed(1)}s`
}

function StatusBadge({ status }) {
  const icons = {
    succeeded: CheckCircle2,
    failed: AlertCircle,
    running: Activity,
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

export default function ScanHistoryPage({ onOpenReport, initialSearch = '' }) {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [status, setStatus] = useState('')
  const [search, setSearch] = useState(initialSearch)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [openingId, setOpeningId] = useState(null)

  const loadHistory = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const result = await getScanHistory({
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        ...(status ? { status } : {}),
        ...(search.trim() ? { search: search.trim() } : {}),
      })

      setItems(result.items || [])
      setTotal(result.total || 0)
    } catch (err) {
      setError(
        err.response?.data?.detail ||
        err.message ||
        'Unable to load scan history.'
      )
    } finally {
      setLoading(false)
    }
  }, [page, status, search])

  useEffect(() => {
    loadHistory()
  }, [loadHistory])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const firstItem = total === 0 ? 0 : page * PAGE_SIZE + 1
  const lastItem = Math.min((page + 1) * PAGE_SIZE, total)

  const handleSearch = (event) => {
    setSearch(event.target.value)
    setPage(0)
  }

  const handleStatus = (event) => {
    setStatus(event.target.value)
    setPage(0)
  }

  const openReport = async (scan) => {
    if (scan.status !== 'succeeded' || openingId) return

    setOpeningId(scan.id)
    setError('')

    try {
      const result = await getScanReport(scan.id)
      await onOpenReport(result.report, scan, scan.id)
    } catch (err) {
      setError(
        err.response?.data?.detail ||
        err.message ||
        'Unable to retrieve this scan report.'
      )
    } finally {
      setOpeningId(null)
    }
  }

  return (
    <section className="scan-history-page">
      <div className="eyebrow">
        <span className="eyebrow-line" /> REPOSITORY ANALYSIS / HISTORY
      </div>

      <div className="history-heading-row">
        <div>
          <h1>Scan history<span className="heading-period">.</span></h1>
          <p className="page-subtitle">
            Review previous repository scans, monitor their outcomes, and reopen saved reports.
          </p>
        </div>
        <button
          className="history-refresh-button"
          onClick={loadHistory}
          disabled={loading}
        >
          <RefreshCw size={15} className={loading ? 'history-spinning' : ''} />
          Refresh
        </button>
      </div>

      <div className="history-summary">
        <div className="history-summary-card">
          <span className="history-summary-label">TOTAL SCANS</span>
          <strong>{loading && total === 0 ? '...' : total}</strong>
          <small>Matching records</small>
        </div>
        <div className="history-summary-card">
          <span className="history-summary-label">CURRENT PAGE</span>
          <strong>{page + 1}<span> / {totalPages}</span></strong>
          <small>Page navigation</small>
        </div>
        <div className="history-summary-card">
          <span className="history-summary-label">DISPLAYING</span>
          <strong>{items.length}</strong>
          <small>Records on this page</small>
        </div>
      </div>

      <div className="panel history-panel">
        <div className="history-toolbar">
          <div className="history-search">
            <Search size={16} />
            <input
              type="search"
              value={search}
              onChange={handleSearch}
              placeholder="Search repositories..."
              aria-label="Search repositories"
            />
          </div>

          <select
            className="history-status-filter"
            value={status}
            onChange={handleStatus}
            aria-label="Filter scans by status"
          >
            <option value="">All statuses</option>
            <option value="succeeded">Succeeded</option>
            <option value="failed">Failed</option>
            <option value="running">Running</option>
            <option value="pending">Pending</option>
          </select>
        </div>

        {error && (
          <div className="history-error" role="alert">
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <div className="reports-table-wrap history-table-wrap">
          <table className="reports-table history-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Source</th>
                <th>Status</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Scan ID</th>
                <th>Report</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="7" className="reports-table-empty">
                    Loading scan history...
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan="7" className="reports-table-empty history-empty">
                    <ShieldAlert size={25} />
                    <strong>No scan records found</strong>
                    <span>
                      {search || status
                        ? 'Try changing your search or status filter.'
                        : 'Your completed and future scans will appear here.'}
                    </span>
                  </td>
                </tr>
              ) : (
                items.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <span className="history-repository-name">
                        {scan.repository_name}
                      </span>
                      <small className="history-created">
                        Created {formatDate(scan.created_at)}
                      </small>
                    </td>
                    <td>
                      <span className="history-source">
                        {scan.source_type === 'github' ? 'GitHub' : 'Local'}
                      </span>
                    </td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td>{formatDate(scan.started_at)}</td>
                    <td>{formatDuration(scan.started_at, scan.finished_at)}</td>
                    <td>
                      <code className="history-scan-id" title={scan.id}>
                        {scan.id.slice(0, 8)}...
                      </code>
                    </td>
                    <td>
                      {scan.status === 'succeeded' ? (
                        <button
                          className="history-open-button"
                          onClick={() => openReport(scan)}
                          disabled={openingId !== null}
                          title="Open saved scan report"
                        >
                          {openingId === scan.id ? 'Opening...' : 'Open'}
                          <ArrowUpRight size={14} />
                        </button>
                      ) : (
                        <span className="history-unavailable">Unavailable</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="reports-pagination history-pagination">
          <span>
            Showing <strong>{firstItem}-{lastItem}</strong> of <strong>{total}</strong> scans
          </span>
          <div className="reports-pagination-controls">
            <button
              className="reports-page-button"
              disabled={page === 0 || loading}
              onClick={() => setPage((current) => Math.max(0, current - 1))}
            >
              Previous
            </button>
            <span className="reports-page-indicator">
              Page {page + 1} of {totalPages}
            </span>
            <button
              className="reports-page-button"
              disabled={page + 1 >= totalPages || loading}
              onClick={() => setPage((current) => current + 1)}
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </section>
  )
}