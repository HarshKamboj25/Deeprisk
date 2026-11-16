import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowUpRight, Bell, Boxes, Bug, History,
  ChevronDown, CircleHelp, Clock3, Command, FileBarChart, FolderGit2,
  GitBranch, Gauge, House, LayoutDashboard, LockKeyhole, Moon,
  Network, Plus, Radar, Search, Settings2, Shield,
  ShieldCheck, ShieldAlert, SlidersHorizontal, Sparkles, Sun, Terminal,
  Workflow, Zap
} from 'lucide-react'
import './App.css'
const DependencyGraph = lazy(() => import('./components/DependencyGraph'))
import { submitScan, getScanStatus, getScanReport, getRepositories, getScanHistory } from './api/client'
import FindingsPage from './pages/FindingsPage'
import RemediationPage from './pages/RemediationPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import ScanHistoryPage from './pages/ScanHistoryPage'
import RepositoriesPage from './pages/RepositoriesPage'

const navigation = [
  { label: 'Overview', icon: LayoutDashboard, section: 'WORKSPACE' },
  { label: 'Repositories', icon: FolderGit2 },
  { label: 'Scan', icon: Radar },
  { label: 'Scan history', icon: History },
  { label: 'Findings', icon: Bug },
  { label: 'Dependency graph', icon: Network },
  { label: 'Remediation', icon: ShieldCheck },
  { label: 'Reports', icon: FileBarChart },
]

const systemNavigation = [
  { label: 'Settings', icon: Settings2 },
]

function Sidebar({ activePage, onNavigate, findingsCount }) {
  const [bottomPanel, setBottomPanel] = useState('')
  return (
    <aside className="sidebar">
      <button className="brand brand-home-button" onClick={() => onNavigate("__LANDING__")} aria-label="Back to landing page">
        <div className="brand-mark"><img src="/deeprisk-crystal-emblem.png" alt="Deeprisk Logo" /></div>
        <div className="brand-copy">
          <span>Deeprisk</span>
          <small>DEPENDENCY INTELLIGENCE</small>
        </div>
      </button>

      <button className="nav-link home-nav-link" onClick={() => onNavigate("__LANDING__")}>
        <House size={17} />
        <span>Home</span>
      </button>

      <div className="workspace-switcher">
        <div className="workspace-icon"><Command size={16} /></div>
        <div className="workspace-copy">
          <span>Personal workspace</span>
          <small>Local environment</small>
        </div>
        <ChevronDown size={15} className="muted-icon" />
      </div>

      <div className="nav-group">
        <span className="nav-heading">WORKSPACE</span>
        {navigation.map(({ label, icon: Icon }) => (
          <button
            key={label}
            className={`nav-link ${activePage === label ? 'active' : ''}`}
            onClick={() => onNavigate(label)}
          >
            <Icon size={17} strokeWidth={1.8} />
            <span>{label}</span>
            {label === 'Findings' && <span className="nav-count">{findingsCount}</span>}
          </button>
        ))}
      </div>

      <div className="nav-group system-group">
        <span className="nav-heading">SYSTEM</span>
        {systemNavigation.map(({ label, icon: Icon }) => (
          <button
            key={label}
            className={`nav-link ${activePage === label ? 'active' : ''}`}
            onClick={() => onNavigate(label)}
          >
            <Icon size={17} strokeWidth={1.8} />
            <span>{label}</span>
          </button>
        ))}
      </div>

      <div className="sidebar-bottom">
        <button
          type="button"
          className={`sidebar-status ${bottomPanel === 'workspace' ? 'is-open' : ''}`}
          onClick={() => setBottomPanel(bottomPanel === 'workspace' ? '' : 'workspace')}
          aria-expanded={bottomPanel === 'workspace'}
        >
          <span className="status-dot" />
          <span>Local workspace</span>
          <span className="status-label">READY</span>
        </button>

        {bottomPanel === 'workspace' && (
          <div className="sidebar-bottom-popover">
            <span className="bottom-popover-kicker">WORKSPACE STATUS</span>
            <strong><span className="status-dot" /> Local environment</strong>
            <p>Your Deeprisk workspace session is active.</p>
            <span className="bottom-popover-meta">Environment · Local</span>
          </div>
        )}

        <button
          type="button"
          className={`profile ${bottomPanel === 'profile' ? 'is-open' : ''}`}
          onClick={() => setBottomPanel(bottomPanel === 'profile' ? '' : 'profile')}
          aria-expanded={bottomPanel === 'profile'}
        >
          <span className="profile-avatar">DR</span>
          <span className="profile-copy">
            <strong>Deeprisk Analyst</strong>
            <small>Community edition</small>
          </span>
          <CircleHelp size={16} className="muted-icon" />
        </button>

        {bottomPanel === 'profile' && (
          <div className="sidebar-bottom-popover profile-popover">
            <span className="bottom-popover-kicker">ANALYST PROFILE</span>
            <strong>Deeprisk Analyst</strong>
            <p>Community edition · Local workspace</p>
            <button
              type="button"
              className="profile-settings-action"
              onClick={() => {
                setBottomPanel('')
                onNavigate('Settings')
              }}
            >
              Open Settings <span>↗</span>
            </button>
          </div>
        )}
      </div>
    </aside>
  )
}

function Topbar({ activePage, onScan, onNavigate }) {
  const [panel, setPanel] = useState('')
  const [query, setQuery] = useState('')
  const [repositories, setRepositories] = useState([])
  const [recentScans, setRecentScans] = useState([])
  const searchPopoverRef = useRef(null)
  const notificationPopoverRef = useRef(null)

  useEffect(() => {
    if (!panel) return

    const handleOutsideClick = (event) => {
      const activeRef = panel === 'search'
        ? searchPopoverRef
        : notificationPopoverRef

      if (activeRef.current && !activeRef.current.contains(event.target)) {
        setPanel('')
      }
    }

    const handleEscape = (event) => {
      if (event.key === 'Escape') setPanel('')
    }

    document.addEventListener('pointerdown', handleOutsideClick)
    document.addEventListener('keydown', handleEscape)

    return () => {
      document.removeEventListener('pointerdown', handleOutsideClick)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [panel])

  useEffect(() => {
    let active = true

    Promise.all([
      getRepositories(),
      getScanHistory({ limit: 8, offset: 0 })
    ]).then(([repoResult, scanResult]) => {
      if (!active) return
      const repos = Array.isArray(repoResult)
        ? repoResult
        : repoResult?.items || repoResult?.value || []
      const scans = Array.isArray(scanResult)
        ? scanResult
        : scanResult?.items || scanResult?.value || []
      setRepositories(repos)
      setRecentScans(scans)
    }).catch(() => {
      if (active) {
        setRepositories([])
        setRecentScans([])
      }
    })

    return () => { active = false }
  }, [])

  const pages = [
    'Overview', 'Repositories', 'Scan', 'Scan history',
    'Findings', 'Dependency graph', 'Remediation',
    'Reports', 'Settings'
  ]

  const searchItems = [
    ...pages.map(name => ({ name, type: 'Page' })),
    ...repositories.map(repo => ({
      name: repo.name || repo.repository_name || repo.path || 'Repository',
      type: 'Repository'
    }))
  ].filter(item => item.name.toLowerCase().includes(query.toLowerCase()))

  const alertCount = recentScans.filter(scan =>
    ['failed', 'pending', 'running'].includes(
      String(scan.status || '').toLowerCase()
    )
  ).length

  const openItem = item => {
    if (item.type === 'Page') onNavigate(item.name)
    else onNavigate('Repositories')
    setPanel('')
    setQuery('')
  }

  return (
    <header className="topbar">
      <div className="breadcrumbs" aria-label="Current location">
  <span className="breadcrumb-root">Workspace</span>
  <span className="crumb-separator" aria-hidden="true">/</span>
  <strong key={activePage} className="breadcrumb-current">{activePage}</strong>
</div>

      <div className="topbar-actions">
        <div className="environment-pill"><span /> LOCAL ENVIRONMENT</div>

        <div className="topbar-popover-wrap" ref={searchPopoverRef}>
          <button
            className="icon-button"
            aria-label="Search"
            onClick={() => setPanel(panel === 'search' ? '' : 'search')}
          >
            <Search size={17} />
          </button>
          {panel === 'search' && (
            <div className="topbar-popover search-popover">
              <input
                autoFocus
                className="topbar-search-input"
                placeholder="Search pages or repositories..."
                value={query}
                onChange={event => setQuery(event.target.value)}
              />
              <div className="popover-list">
                {searchItems.slice(0, 10).map((item, index) => (
                  <button
                    key={`${item.type}-${item.name}-${index}`}
                    className="popover-item"
                    onClick={() => openItem(item)}
                  >
                    <span>{item.name}</span>
                    <small>{item.type}</small>
                  </button>
                ))}
                {searchItems.length === 0 && (
                  <p className="popover-empty">No matching results found.</p>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="topbar-popover-wrap" ref={notificationPopoverRef}>
          <button
            className="icon-button notification-trigger"
            aria-label="Notifications"
            onClick={() => setPanel(panel === 'notifications' ? '' : 'notifications')}
          >
            <Bell size={17} />
            {alertCount > 0 && <span className="notification-count">{alertCount}</span>}
          </button>
          {panel === 'notifications' && (
            <div className="topbar-popover notification-popover">
              <div className="popover-heading">Recent scan activity</div>
              {recentScans.length > 0 ? recentScans.slice(0, 8).map((scan, index) => (
                <div className="notification-item" key={scan.id || scan.scan_id || index}>
                  <span className={`notification-dot ${String(scan.status || '').toLowerCase()}`} />
                  <div>
                    <strong>{scan.repository_name || scan.repository || scan.source || 'Repository scan'}</strong>
                    <small>{scan.status || 'Unknown status'}</small>
                  </div>
                </div>
              )) : (
                <p className="popover-empty">No recent scan activity.</p>
              )}
              <button
                className="popover-footer"
                onClick={() => {
                  onNavigate('Scan history')
                  setPanel('')
                }}
              >
                View complete scan history
              </button>
            </div>
          )}
        </div>
<div className="topbar-divider" />
        <button className="new-scan-button" onClick={onScan}>
          <Plus size={16} /> New scan
        </button>
      </div>
    </header>
  )
}
function MetricCard({ icon: Icon, label, value, detail, tone = 'neutral' }) {
  return (
    <article className="metric-card">
      <div className="metric-top">
        <span>{label}</span>
        <div className={`metric-icon ${tone}`}><Icon size={17} /></div>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </article>
  )
}

function EmptyGraph({ onScan }) {
  return (
    <div className="graph-empty">
      <div className="graph-empty-orbit orbit-one" />
      <div className="graph-empty-orbit orbit-two" />
      <div className="graph-empty-core"><Network size={27} strokeWidth={1.4} /></div>
      <div className="graph-empty-title">Your dependency network starts here</div>
      <p>Run a repository scan to construct the package graph, inspect dependency paths, and identify exposed components.</p>
      <button className="graph-action" onClick={onScan}>
        <Radar size={15} /> Start your first scan <ArrowUpRight size={15} />
      </button>
      <span className="graph-empty-footnote">GRAPH DATA WILL BE GENERATED FROM YOUR LOCKFILE</span>
    </div>
  )
}

function Overview({ onScan, report, refreshKey }) {
  const [dashboard, setDashboard] = useState({
    repositories: [],
    totalScans: 0,
    succeeded: 0,
    failed: 0,
    recentScans: [],
    latestReport: null,
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    async function loadDashboard() {
      setLoading(true)
      setError('')

      try {
        const [repoResult, recentResult, successResult, failedResult] =
          await Promise.all([
            getRepositories(),
            getScanHistory({ limit: 5, offset: 0 }),
            getScanHistory({ status: 'succeeded', limit: 1, offset: 0 }),
            getScanHistory({ status: 'failed', limit: 1, offset: 0 }),
          ])

        const repositories = Array.isArray(repoResult)
          ? repoResult
          : Array.isArray(repoResult.value)
            ? repoResult.value
            : []

        const latestSuccessfulScan = successResult.items?.[0]
        let latestReport = null

        if (latestSuccessfulScan?.id) {
          try {
            const result = await getScanReport(latestSuccessfulScan.id)
            latestReport = result.report || null
          } catch {
            latestReport = null
          }
        }

        if (!cancelled) {
          setDashboard({
            repositories,
            totalScans: recentResult.total || 0,
            succeeded: successResult.total || 0,
            failed: failedResult.total || 0,
            recentScans: recentResult.items || [],
            latestReport,
          })
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err.response?.data?.detail ||
            err.message ||
            'Unable to load dashboard data.'
          )
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    loadDashboard()

    return () => {
      cancelled = true
    }
  }, [refreshKey])

  const activeReport = report || dashboard.latestReport
  const summary = activeReport?.summary || {}

  const formatDate = (value) => {
    if (!value) return 'Date unavailable'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return 'Date unavailable'
    return date.toLocaleString(undefined, {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  return (
    <>
      <section className="page-intro">
        <div>
          <div className="eyebrow"><span className="eyebrow-line" /> SECURITY INTELLIGENCE / 01</div>
          <h1 className="overview-title">
  {Array.from("Security overview").map((char, index) => (
    <span
      key={index}
      className="overview-title-char"
      style={{ "--char-index": index }}
    >
      {char === " " ? "\u00A0" : char}
    </span>
  ))}
  <span className="heading-period overview-title-period">.</span>
</h1>
          <p className="page-subtitle">
            Understand your dependency exposure. Prioritize what matters.
          </p>
        </div>
        <button className="primary-button" onClick={onScan}>
          <Plus size={17} /> Run a scan
        </button>
      </section>

      {error && (
        <div className="history-error" role="alert">
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      <section className="metrics-grid">
        <MetricCard
          icon={Boxes}
          label="REGISTERED REPOSITORIES"
          value={loading ? '...' : dashboard.repositories.length}
          detail="Saved repository records"
        />
        <MetricCard
          icon={Activity}
          label="TOTAL SCANS"
          value={loading ? '...' : dashboard.totalScans}
          detail="All recorded scan operations"
        />
        <MetricCard
          icon={ShieldCheck}
          label="SUCCESSFUL SCANS"
          value={loading ? '...' : dashboard.succeeded}
          detail="Completed successfully"
          tone="green"
        />
        <MetricCard
          icon={Bug}
          label="FAILED SCANS"
          value={loading ? '...' : dashboard.failed}
          detail="Scans requiring attention"
          tone="danger"
        />
      </section>

      <section className="main-workspace">
        <div className="panel graph-panel">
          <div className="panel-header">
            <div>
              <div className="panel-kicker"><span className="live-indicator" /> GRAPH INTELLIGENCE</div>
              <h2>Dependency network</h2>
              <p>Package relationships and exposure paths</p>
            </div>
            <div className="panel-tools">
              <span className="subtle-tag">
                {activeReport ? 'REPORT LOADED' : 'NO SCAN DATA'}
              </span>
            </div>
          </div>

          <div className="graph-stage">
            <div className="graph-grid" />
            <div className="graph-coordinate coordinate-a">DEPENDENCY ANALYSIS</div>
            <div className="graph-coordinate coordinate-b">PACKAGE TOPOLOGY</div>
            {activeReport ? (
              <Suspense fallback={<div className="graph-loading">Initializing dependency visualization...</div>}>
                <DependencyGraph report={activeReport} preview />
              </Suspense>
            ) : (
              <EmptyGraph onScan={onScan} />
            )}
          </div>

          <div className="graph-footer">
            <span>
              <Workflow size={14} />
              {activeReport
                ? 'Interactive dependency network loaded from saved scan report'
                : 'Interactive graph activates after a successful scan'}
            </span>
            <span className="mono-label">CYTOSCAPE ENGINE</span>
          </div>
        </div>

        <aside className="side-panels">
          <div className="panel intel-panel">
            <div className="panel-header compact">
              <div>
                <div className="panel-kicker">THREAT INTELLIGENCE</div>
                <h2>Exposure signals</h2>
              </div>
              <Zap size={17} className="panel-accent-icon" />
            </div>
            <div className="intel-empty">
              <div className="intel-icon"><LockKeyhole size={19} /></div>
              <strong>
                {activeReport
                  ? `${summary.confirmed_findings ?? 0} confirmed findings`
                  : 'No report intelligence available'}
              </strong>
              <span>
                {activeReport
                  ? 'Latest saved report evidence and risk analysis.'
                  : 'EPSS, CISA KEV and NVD evidence will appear when a report is available.'}
              </span>
            </div>
            <div className="source-list">
              <div><span className="source-name">FIRST EPSS</span><span className="source-state">REPORT DATA</span></div>
              <div><span className="source-name">CISA KEV</span><span className="source-state">REPORT DATA</span></div>
              <div><span className="source-name">NVD / CVSS</span><span className="source-state">REPORT DATA</span></div>
            </div>
          </div>

          <div className="panel activity-panel">
            <div className="panel-header compact">
              <div>
                <div className="panel-kicker">SCAN ACTIVITY</div>
                <h2>Latest operations</h2>
              </div>
              <Clock3 size={16} className="muted-icon" />
            </div>

            {loading ? (
              <div className="activity-empty">Loading recent scan activity...</div>
            ) : dashboard.recentScans.length === 0 ? (
              <div className="activity-empty">
                <Activity size={19} />
                <span>No scan activity recorded.</span>
              </div>
            ) : (
              <div className="overview-activity-list">
                {dashboard.recentScans.map((scan) => (
                  <div className="overview-activity-item" key={scan.id}>
                    <div className="overview-activity-copy">
                      <strong>{scan.repository_name || 'Unknown repository'}</strong>
                      <span>{formatDate(scan.created_at)}</span>
                    </div>
                    <span className={`history-status ${scan.status}`}>
                      {scan.status}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </aside>
      </section>

      <section className="pipeline-panel panel">
        <div className="pipeline-heading">
          <div>
            <div className="panel-kicker">ANALYSIS PIPELINE</div>
            <h2>From lockfile to actionable intelligence</h2>
          </div>
          <span className="subtle-tag">{activeReport ? 'REPORT AVAILABLE' : 'READY WHEN YOU ARE'}</span>
        </div>
        <div className="pipeline-steps">
          {[
            { icon: Terminal, name: 'Lockfile parsing', desc: 'Package inventory' },
            { icon: Network, name: 'Graph construction', desc: 'Dependency topology' },
            { icon: Search, name: 'Advisory matching', desc: 'OSV intelligence' },
            { icon: Gauge, name: 'Risk analysis', desc: 'Evidence & reachability' },
            { icon: FileBarChart, name: 'Report generation', desc: 'Explainable output' },
          ].map(({ icon: Icon, name, desc }, index) => (
            <div className="pipeline-step" key={name}>
              <div className="pipeline-step-icon"><Icon size={17} /></div>
              <div><strong>{name}</strong><span>{desc}</span></div>
              {index < 4 && <div className="pipeline-connector" />}
            </div>
          ))}
        </div>
        <p className="pipeline-note">
          Pipeline stages are system capabilities, not live progress indicators.
        </p>
      </section>
    </>
  )
}
function GraphPage({ report, onScan }) {
  if (!report) {
    return (
      <section className="graph-page">
        <div className="eyebrow"><span className="eyebrow-line" /> GRAPH INTELLIGENCE / 03</div>
        <h1>Dependency graph<span className="heading-period">.</span></h1>
        <p className="page-subtitle">Explore package relationships and dependency paths.</p>
        <div className="panel graph-workspace-empty">
          <Network size={30} />
          <strong>No dependency network available</strong>
          <span>Run a repository scan to generate an interactive dependency graph.</span>
          <button className="primary-button" onClick={onScan}><Plus size={15} /> Run a scan</button>
        </div>
      </section>
    )
  }

  return (
    <section className="graph-page">
      <div className="page-intro">
        <div>
          <div className="eyebrow"><span className="eyebrow-line" /> GRAPH INTELLIGENCE / 03</div>
          <h1>Dependency graph<span className="heading-period">.</span></h1>
          <p className="page-subtitle">
            Explore package relationships, dependency paths and component metadata.
          </p>
        </div>
        <span className="subtle-tag">3D INTERACTIVE NETWORK</span>
      </div>

      <div className="graph-page-metrics">
        <div className="panel">
          <span>PACKAGES</span>
          <strong>{report.summary?.total_dependencies ?? report.dependencies?.length ?? 0}</strong>
        </div>
        <div className="panel">
          <span>RELATIONSHIPS</span>
          <strong>{report.summary?.total_edges ?? report.edges?.length ?? 0}</strong>
        </div>
        <div className="panel">
          <span>CONFIRMED FINDINGS</span>
          <strong>{report.summary?.confirmed_findings ?? 0}</strong>
        </div>
        <div className="panel">
          <span>UNREACHABLE</span>
          <strong>{report.summary?.unreachable_dependencies ?? 0}</strong>
        </div>
      </div>

      <div className="panel graph-page-panel">
        <div className="panel-header">
          <div>
            <div className="panel-kicker">DEPENDENCY TOPOLOGY</div>
            <h2>{report.repository_name || 'Repository network'}</h2>
            <p>Click a node to inspect its relationships and metadata.</p>
          </div>
          <span className="subtle-tag">3D ORBITAL ENGINE</span>
        </div>

        <Suspense fallback={<div className="graph-loading">Initializing graph engine...</div>}>
          <DependencyGraph report={report} full />
        </Suspense>
      </div>
    </section>
  )
}
function PlaceholderPage({ title, description, icon: Icon, onScan }) {
  return (
    <section className="placeholder-page">
      <div className="placeholder-icon"><Icon size={25} /></div>
      <div className="eyebrow"><span className="eyebrow-line" /> Deeprisk WORKSPACE</div>
      <h1>{title}<span className="heading-period">.</span></h1>
      <p>{description}</p>
      <div className="placeholder-card">
        <Sparkles size={18} />
        <div><strong>Waiting for scan evidence</strong><span>This workspace will populate with real repository data after your first successful scan.</span></div>
      </div>
      <button className="primary-button" onClick={onScan}><Plus size={16} /> Start a scan</button>
    </section>
  )
}

function ScanPage({ onReportReady }) {
  const [sourceType, setSourceType] = useState('github')
  const [source, setSource] = useState('')
  const [scanStatus, setScanStatus] = useState(null)
  const [scanId, setScanId] = useState('')
  const [error, setError] = useState('')
  const [isScanning, setIsScanning] = useState(false)

  const getErrorMessage = (err) =>
    err.response?.data?.detail || err.message || 'An unexpected error occurred.'

  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

  const handleScan = async () => {
    if (!source.trim() || isScanning) return

    setIsScanning(true)
    setError('')
    setScanStatus('Submitting scan...')
    setScanId('')

    try {
      const payload = sourceType === 'local'
        ? { source_type: 'local', repository_path: source.trim() }
        : { source_type: 'github', repository_url: source.trim() }

      const created = await submitScan(payload)
      setScanId(created.scan_id)
      setScanStatus('pending')

      for (let attempt = 0; attempt < 300; attempt += 1) {
        await wait(2000)

        const status = await getScanStatus(created.scan_id)
        setScanStatus(status.status)

        if (status.status === 'succeeded') {
          const result = await getScanReport(created.scan_id)
          onReportReady(result.report, status, created.scan_id)
          setScanStatus('succeeded')
          return
        }

        if (status.status === 'failed') {
          throw new Error(status.error_message || 'The scan failed.')
        }
      }

      throw new Error('The scan is taking longer than expected. You can check its status using the scan ID.')
    } catch (err) {
      setError(getErrorMessage(err))
      setScanStatus('failed')
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <section className="scan-page">
      <div className="eyebrow"><span className="eyebrow-line" /> REPOSITORY ANALYSIS / 02</div>
      <h1>Initialize a scan<span className="heading-period">.</span></h1>
      <p className="page-subtitle">
        Choose a repository source. Deeprisk will inspect its npm lockfile and build an explainable dependency report.
      </p>

      <div className="panel scan-form-panel">
        <div className="panel-kicker">SCAN CONFIGURATION</div>
        <h2>Repository source</h2>

        <div className="source-tabs">
          <button disabled={isScanning} className={sourceType === 'github' ? 'selected' : ''}
            onClick={() => { setSourceType('github'); setSource('') }}>
            <GitBranch size={17} /> GitHub repository
          </button>
          <button disabled={isScanning} className={sourceType === 'local' ? 'selected' : ''}
            onClick={() => { setSourceType('local'); setSource('') }}>
            <Terminal size={17} /> Local workspace
          </button>
        </div>

        <label className="field-label">
          {sourceType === 'github' ? 'PUBLIC REPOSITORY URL' : 'REPOSITORY PATH'}
        </label>

        <input
          className="scan-input"
          value={source}
          disabled={isScanning}
          onChange={(event) => setSource(event.target.value)}
          placeholder={sourceType === 'github'
            ? 'https://github.com/owner/repository'
            : 'Inventory-Management-System'}
        />

        <div className="scan-hint">
          {sourceType === 'github'
            ? 'Public GitHub repositories are supported.'
            : 'Enter a folder relative to the configured backend workspace root.'}
        </div>

        <button className="primary-button scan-submit"
          disabled={!source.trim() || isScanning}
          onClick={handleScan}>
          <Radar size={17} />
          {isScanning ? 'Scanning repository...' : 'Start repository scan'}
        </button>

        {scanStatus && (
          <div className={`scan-result-state ${scanStatus === 'failed' ? 'error' : scanStatus === 'succeeded' ? 'success' : ''}`}>
            <div className="scan-result-heading">
              <span className="scan-state-dot" />
              <strong>{scanStatus === 'succeeded' ? 'Scan completed' : scanStatus === 'failed' ? 'Scan failed' : scanStatus === 'Submitting scan...' ? scanStatus : `Scan ${scanStatus}`}</strong>
            </div>
            {scanId && <code>SCAN ID: {scanId}</code>}
            {scanStatus === 'succeeded' && <p>Report retrieved successfully. Your repository analysis is ready.</p>}
            {error && <p>{error}</p>}
          </div>
        )}

        <div className="scan-support">
          <ShieldCheck size={15} />
          Repository code is never installed or executed by the scanner.
        </div>
      </div>

      <div className="scan-capabilities">
        <div><Boxes size={17} /><span><strong>npm lockfiles</strong><small>Lockfile v2 and v3</small></span></div>
        <div><Network size={17} /><span><strong>Dependency graph</strong><small>Direct and transitive paths</small></span></div>
        <div><ShieldCheck size={17} /><span><strong>Evidence-backed</strong><small>OSV, EPSS, CISA KEV and NVD</small></span></div>
      </div>
    </section>
  )
}
function LandingPage({ onNavigate, onScan }) {
  const workflowRef = useRef(null)

  useEffect(() => {
    const section = workflowRef.current
    if (!section) return

    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        section.classList.add('workflow-visible')
        observer.unobserve(section)
      }
    }, { threshold: 0.2 })

    observer.observe(section)
    return () => observer.disconnect()
  }, [])
const intelligenceRef = useRef(null)
  const [intelligenceVisible, setIntelligenceVisible] = useState(false)

  useEffect(() => {
    const section = intelligenceRef.current
    if (!section) return

    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setIntelligenceVisible(true)
        observer.disconnect()
      }
    }, { threshold: 0.18 })

    observer.observe(section)
    return () => observer.disconnect()
  }, [])
  const links = [
    { label: 'Platform', page: 'Overview' },
    { label: 'Repositories', page: 'Repositories' },
    { label: 'Threat intelligence', page: 'Findings' },
    { label: 'Reports', page: 'Reports' },
  ]

  return (
    <div
      className="landing-shell"
      onMouseMove={(event) => {
        const rect = event.currentTarget.getBoundingClientRect()
        const x = event.clientX - rect.left
        const y = event.clientY - rect.top
        event.currentTarget.style.setProperty('--mouse-x', `${x}px`)
        event.currentTarget.style.setProperty('--mouse-y', `${y}px`)
      }}
    >
      <div className="landing-cursor-glow" />
      <div className="landing-grid" />
      <div className="landing-ambient landing-ambient-one" />
      <div className="landing-ambient landing-ambient-two" />

      <div className="landing-bg-universe" aria-hidden="true">
        <div className="bg-orbit bg-orbit-one" />
        <div className="bg-orbit bg-orbit-two" />
        <div className="bg-orbit bg-orbit-three" />

        <svg className="bg-shield bg-shield-one" viewBox="0 0 100 115">
          <path d="M50 5 L88 22 L84 69 Q78 94 50 108 Q22 94 16 69 L12 22 Z" />
          <path d="M50 19 L75 30 L72 67 Q67 84 50 94 Q33 84 28 67 L25 30 Z" />
        </svg>

        <svg className="bg-shield bg-shield-two" viewBox="0 0 100 115">
          <path d="M50 5 L88 22 L84 69 Q78 94 50 108 Q22 94 16 69 L12 22 Z" />
          <path d="M50 19 L75 30 L72 67 Q67 84 50 94 Q33 84 28 67 L25 30 Z" />
        </svg>

        <svg className="bg-shield bg-shield-three" viewBox="0 0 100 115">
          <path d="M50 5 L88 22 L84 69 Q78 94 50 108 Q22 94 16 69 L12 22 Z" />
        </svg>

        <span className="bg-particle bg-particle-one" />
        <span className="bg-particle bg-particle-two" />
        <span className="bg-particle bg-particle-three" />
        <span className="bg-particle bg-particle-four" />
        <span className="bg-particle bg-particle-five" />

        <span className="bg-attack-streak bg-streak-one" />
        <span className="bg-attack-streak bg-streak-two" />
      </div>

      <header className="landing-nav">
        <button className="landing-brand" onClick={() => onNavigate('Overview')}>
          <span className="landing-brand-mark">
  <img
    src="/deeprisk-crystal-emblem.png"
    alt="Deeprisk Crystal Logo"
  />
</span>
          <span>Deeprisk<span className="landing-brand-dot">.</span></span>
        </button>

        <nav className="landing-links">
          {links.map(link => (
            <button key={link.label} onClick={() => onNavigate(link.page)}>
              {link.label}
            </button>
          ))}
        </nav>

        <button className="landing-nav-cta" onClick={onScan}>
          Initialize scan <ArrowUpRight size={15} />
        </button>
      </header>

      <main className="landing-hero">
        <section className="landing-copy">
          <div className="landing-eyebrow">
            <span className="landing-live-dot" />
            SOFTWARE SUPPLY CHAIN INTELLIGENCE
          </div>

          <h1>
            SEE BEYOND
            <br />
            YOUR <span>CODE.</span>
            <br />
            <span className="landing-heading-muted">SECURE WHAT</span>
            <br />
            CONNECTS IT.
          </h1>

          <p className="landing-description">
            Understand your software dependencies. Discover vulnerabilities,
            trace hidden relationships and take control of your software
            supply-chain security.
          </p>

          <div className="landing-actions">
            <button className="landing-primary" onClick={onScan}>
              Initialize security scan <ArrowUpRight size={17} />
            </button>
            <button className="landing-secondary" onClick={() => onNavigate('Overview')}>
              Explore platform
            </button>
          </div>

          <div className="landing-proof">
            <span>01 / ANALYZE</span>
            <span>02 / DETECT</span>
            <span>03 / VISUALIZE</span>
          </div>
        </section>

        <section className="landing-visual" aria-label="Deeprisk security visual">
          <div className="landing-orbit landing-orbit-one" />
          <div className="landing-orbit landing-orbit-two" />
          <span className="landing-orbit-particle particle-one" />
          <span className="landing-orbit-particle particle-two" />
          <span className="landing-orbit-particle particle-three" />
          <span className="landing-orbit-particle particle-four" />
          <div className="landing-attack landing-attack-left">
            <span className="attack-label">INTRUSION DETECTED</span>
            <span className="attack-beam" />
          </div>

          <div className="landing-attack landing-attack-right">
            <span className="attack-label">MALWARE INJECTION</span>
            <span className="attack-beam" />
          </div>

          <div className="landing-attack landing-attack-top">
            <span className="attack-label">UNAUTHORIZED ACCESS</span>
            <span className="attack-beam" />
          </div>

          <div className="landing-attack landing-attack-bottom">
            <span className="attack-label">EXPLOIT ATTEMPT</span>
            <span className="attack-beam" />
          </div>

          <div className="landing-impact-ring" />
          <div className="landing-blocked-flash"><ShieldCheck className="protected-icon" size={21} strokeWidth={1.8} /><span className="protected-title">THREAT NEUTRALIZED</span><span className="protected-subtitle">Protected by Deeprisk</span></div>
          <div className="landing-crystal">
            <div className="landing-crystal-face landing-crystal-back" />
            <div className="landing-crystal-face landing-crystal-front">
              <ShieldCheck size={104} strokeWidth={0.8} />
            </div>
            <div className="landing-crystal-side" />
          </div>

          <div className="landing-float-card landing-card-top">
            <span className="landing-card-icon"><Network size={16} /></span>
            <span><small>DEPENDENCY NETWORK</small><strong>Relationship mapping</strong></span>
            <span className="landing-card-status">ACTIVE</span>
          </div>

          <div className="landing-float-card landing-card-bottom">
            <span className="landing-card-icon"><ShieldCheck size={16} /></span>
            <span><small>SECURITY INTELLIGENCE</small><strong>Risk analysis engine</strong></span>
            <span className="landing-card-status">READY</span>
          </div>

          <div className="landing-threat-panel landing-threat-left">
            <span className="landing-threat-pulse" />
            <span><small>THREAT INTELLIGENCE</small><strong>Risk signals monitored</strong></span>
            <b>LIVE</b>
          </div>

          <div className="landing-protection-panel">
            <ShieldCheck size={17} />
            <span><small>DEPENDENCY PROTECTION</small><strong>Security monitoring active</strong></span>
          </div>

          <div className="landing-visual-caption">
            <span>Deeprisk / INTELLIGENCE ENGINE</span>
            <span>LOCAL-FIRST SECURITY</span>
          </div>
        </section>
      </main>

      <section ref={intelligenceRef} className={`landing-intelligence landing-reveal ${intelligenceVisible ? "is-visible" : ""}`}>
        <div className="landing-section-heading">
          <span>01 / INTELLIGENCE LAYER</span>
          <h2>Know what lives <em>inside your code.</em></h2>
          <p>Go beyond package lists. Understand the connections, risks and exposure paths across your software supply chain.</p>
        </div>

        <div className="landing-feature-grid">
          <article className="landing-feature-card">
            <span className="landing-feature-number">01</span>
            <Network size={25} />
            <h3>Dependency intelligence</h3>
            <p>Map direct and transitive dependencies and explore how packages connect.</p>
            <span className="landing-feature-link">EXPLORE RELATIONSHIPS ?</span>
          </article>

          <article className="landing-feature-card">
            <span className="landing-feature-number">02</span>
            <ShieldAlert size={25} />
            <h3>Threat discovery</h3>
            <p>Surface known vulnerabilities and understand the security exposure in your dependencies.</p>
            <span className="landing-feature-link">IDENTIFY EXPOSURE ?</span>
          </article>

          <article className="landing-feature-card">
            <span className="landing-feature-number">03</span>
            <Activity size={25} />
            <h3>Evidence-led analysis</h3>
            <p>Explore security signals and supporting evidence to prioritize what needs attention.</p>
            <span className="landing-feature-link">INSPECT FINDINGS ?</span>
          </article>
        </div>
      </section>

      <section ref={workflowRef} className="landing-workflow landing-reveal">
        <div className="landing-section-heading">
          <span>02 / SECURITY WORKFLOW</span>
          <h2>From repository to <em>risk clarity.</em></h2>
          <p>A focused workflow to inspect, understand and act on dependency risks.</p>
        </div>

        <div className="landing-workflow-track">
          <div><b>01</b><strong>Analyze</strong><small>Inspect repositories and lockfiles.</small></div>
          <div><b>02</b><strong>Discover</strong><small>Identify vulnerable dependencies.</small></div>
          <div><b>03</b><strong>Visualize</strong><small>Explore package relationships.</small></div>
          <div><b>04</b><strong>Secure</strong><small>Review findings and remediation guidance.</small></div>
        </div>
      </section>

      <section className="landing-final-cta landing-reveal">
        <span>READY TO UNDERSTAND YOUR DEPENDENCIES?</span>
        <h2>Your code deserves <em>clarity.</em></h2>
        <button className="landing-primary" onClick={onScan}>
          Initialize your first scan <ArrowUpRight size={17} />
        </button>
      </section>
      <footer className="landing-footer">
        <span>DEPENDENCY INTELLIGENCE PLATFORM</span>
        <span>ANALYZE. DISCOVER. SECURE.</span>
      </footer>
    </div>
  )
}

function SplashScreen() {
  return (
    <div className="deprisk-splash">
      <div className="splash-grid" />
      <div className="splash-scanline" />
      <div className="splash-content">
        <div className="splash-emblem hybrid-emblem">
  <img
    className="splash-crystal-image"
    src="/deeprisk-crystal-emblem.png"
    alt="Deeprisk Hybrid Crystal Shield"
  />
  <span className="splash-beam" aria-hidden="true" />
  <span className="hybrid-particle particle-one" />
  <span className="hybrid-particle particle-two" />
  <span className="hybrid-particle particle-three" />
  <span className="hybrid-particle particle-four" />
  <span className="hybrid-particle particle-five" />
</div>
        <span className="splash-beam" aria-hidden="true" />
        <div className="splash-wordmark">Deeprisk<span>.</span></div>
        <div className="splash-tagline">DEPENDENCY INTELLIGENCE</div>
        <div className="splash-divider"><span /></div>
        <div className="splash-status">DISCOVER DEPENDENCY RISKS. TRACE THREATS. SECURE YOUR SOFTWARE.</div>
      </div>
      <div className="splash-corner splash-corner-left">LOCAL-FIRST / SECURITY</div>
      <div className="splash-corner splash-corner-right">SYSTEM BOOT / 001</div>
    </div>
  )
}


function WorkspaceIntro() {
  return (
    <div className="workspace-intro">
      <div className="workspace-intro-glow" />

      <div className="workspace-intro-content">
        <div className="workspace-intro-emblem">
          <img
            src="/deeprisk-crystal-emblem.png"
            alt="Deeprisk"
          />
          <span className="workspace-intro-beam" />
        </div>

        <div className="workspace-intro-wordmark">
          Deeprisk<span>.</span>
        </div>

        <div className="workspace-intro-loading">
          LOADING YOUR WORKSPACE
        </div>

        <div className="workspace-intro-progress">
          <span />
        </div>

        <div className="workspace-intro-tagline">
          YOUR SECURITY OPERATIONS START HERE.
        </div>
      </div>
    </div>
  )
}
function App() {
  const [showSplash, setShowSplash] = useState(true)
  const [showLanding, setShowLanding] = useState(true)

  const [showPlatformIntro, setShowPlatformIntro] = useState(false)
  useEffect(() => {
    const timer = window.setTimeout(() => setShowSplash(false), 4800)
    return () => window.clearTimeout(timer)
  }, [])
  
  useEffect(() => {
    if (!showPlatformIntro) return

    const timer = window.setTimeout(() => {
      setShowPlatformIntro(false)
    }, 2500)

    return () => window.clearTimeout(timer)
  }, [showPlatformIntro])
const [activePage, setActivePage] = useState('Overview')
  const [latestReport, setLatestReport] = useState(null)
  const [latestScan, setLatestScan] = useState(null)
  const [historySearch, setHistorySearch] = useState('')
  const [dashboardRefreshKey, setDashboardRefreshKey] = useState(0)

  // DEEPRISK_WORKSPACE_SCROLL_OBSERVER
  useEffect(() => {
    if (showSplash || showLanding || showPlatformIntro) return

    const content = document.querySelector('.app-shell .page-content')
    if (!content) return

    const targets = Array.from(content.children)

    if (!('IntersectionObserver' in window)) return

    targets.forEach((element) => {
      element.classList.add('dr-scroll-reveal')
    })

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('dr-scroll-visible')
          observer.unobserve(entry.target)
        }
      })
    }, {
      threshold: 0.08,
      rootMargin: '0px 0px -35px 0px'
    })

    targets.forEach((element) => observer.observe(element))

    return () => observer.disconnect()
  }, [showSplash, showLanding, showPlatformIntro, activePage])
  if (showSplash) return <SplashScreen />
  if (showPlatformIntro) return <WorkspaceIntro />

  const navigate = (page) => {
    if (page === '__LANDING__') {
      setShowLanding(true)
      setActivePage('Overview')
      return
    }
    setActivePage(page)
    setShowLanding(false)
  }
  const startScan = () => navigate('Scan')

  if (showLanding) {
    return (
      <LandingPage
        onNavigate={(page) => {
          setActivePage(page)
          setShowLanding(false)
          setShowPlatformIntro(true)
        }}
        onScan={() => {
          setActivePage('Scan')
          setShowLanding(false)
          setShowPlatformIntro(true)
        }}
      />
    )
  }
  const viewRepositoryScans = (repositoryName) => {
    setHistorySearch(repositoryName)
    setActivePage('Scan history')
  }

  const handleOpenHistoryReport = async (report, scan, scanId) => {
    setLatestReport(report)
    setLatestScan({ ...scan, scanId })
    setActivePage('Reports')
  }

  const handleReportReady = (report, status, scanId) => {
    setLatestReport(report)
    setLatestScan({ ...status, scanId })
    setDashboardRefreshKey(value => value + 1)
    setActivePage('Overview')
  }

  const pageDetails = {
    'Dependency graph': { icon: Network, description: 'Explore package relationships, dependency paths, and reachability.' },
  }

  return (
    <div className="app-shell">
      <Sidebar
        activePage={activePage}
        onNavigate={navigate}
        findingsCount={latestReport?.findings?.length ?? 0}
      />
      <main className="main-area">
                <Topbar
          activePage={activePage}
          onScan={startScan}
          onNavigate={navigate}
        />
        <div className="page-content">
          {activePage === 'Overview' && <Overview onScan={startScan} report={latestReport} refreshKey={dashboardRefreshKey} />}
          {activePage === 'Scan' && <ScanPage onReportReady={handleReportReady} />}
          {activePage === 'Repositories' && <RepositoriesPage onViewScans={viewRepositoryScans} />}
          {activePage === 'Scan history' && <ScanHistoryPage onOpenReport={handleOpenHistoryReport} initialSearch={historySearch} />}
          {activePage === 'Findings' && <FindingsPage report={latestReport} onScan={startScan} />}
          {activePage === 'Reports' && <ReportsPage report={latestReport} scan={latestScan} />}
          {activePage === 'Settings' && <SettingsPage />}
          {activePage === 'Remediation' && <RemediationPage report={latestReport} />}
          {activePage === 'Dependency graph' && (
            <GraphPage report={latestReport} onScan={startScan} />
          )}
          {pageDetails[activePage] && activePage !== 'Dependency graph' && (
            <PlaceholderPage
              title={activePage}
              description={pageDetails[activePage].description}
              icon={pageDetails[activePage].icon}
              onScan={startScan}
            />
          )}
        </div>
        <footer className="app-footer">
          <span>Deeprisk <span className="footer-separator">/</span> DEPENDENCY INTELLIGENCE</span>
          <span>LOCAL-FIRST SECURITY ANALYSIS <span className="footer-separator">Ã¢â‚¬Â¢</span> BUILD 0.1</span>
        </footer>
      </main>
    </div>
  )
}

export default App





















