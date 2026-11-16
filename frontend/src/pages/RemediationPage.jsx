import { useMemo, useState } from 'react'
import {
  Search, ShieldCheck, AlertTriangle, CheckCircle2,
  Clock3, ChevronDown, ChevronUp, Package, GitBranch
} from 'lucide-react'

function buildRemediationItems(findings) {
  return findings.flatMap((finding, index) => {
    const advisories = finding.advisories || []

    return advisories.flatMap(advisory => {
      const remediations = advisory.remediations || []

      return remediations.map((remediation, remediationIndex) => ({
        id: `${index}-${advisory.advisory_id}-${remediationIndex}`,
        package: remediation.package_name,
        ecosystem: remediation.ecosystem,
        fixedVersions: remediation.fixed_versions || [],
        status: remediation.status,
        advisoryId: advisory.advisory_id,
        severity: advisory.severity || 'unknown',
        summary: advisory.summary || 'No advisory summary available.',
        installPaths: finding.affected_install_paths || [],
      }))
    })
  })
}

function RemediationPage({ report }) {
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [expanded, setExpanded] = useState(null)

  const findings = report?.findings || []

  const items = useMemo(
    () => buildRemediationItems(findings),
    [findings]
  )

  const counts = useMemo(() => ({
    all: items.length,
    available: items.filter(item => item.status === 'available').length,
    unknown: items.filter(item => item.status === 'unknown').length,
  }), [items])

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()

    return items.filter(item => {
      const matchesSearch = !query || [
        item.package,
        item.advisoryId,
        item.ecosystem,
        ...item.fixedVersions,
      ].some(value => value?.toLowerCase().includes(query))

      const matchesStatus =
        statusFilter === 'all' || item.status === statusFilter

      return matchesSearch && matchesStatus
    })
  }, [items, search, statusFilter])

  if (!report) {
    return (
      <section className="remediation-page">
        <div className="page-intro">
          <div>
            <div className="eyebrow">SECURITY INTELLIGENCE / REMEDIATION</div>
            <h1>Remediation<span className="heading-period">.</span></h1>
            <p className="page-subtitle">
              Advisory-backed upgrade guidance for affected dependencies.
            </p>
          </div>
        </div>

        <div className="panel remediation-empty">
          <ShieldCheck size={30} />
          <h2>No scan report available</h2>
          <p>Run a repository scan to discover remediation evidence.</p>
        </div>
      </section>
    )
  }

  return (
    <section className="remediation-page">
      <div className="page-intro">
        <div>
          <div className="eyebrow">SECURITY INTELLIGENCE / REMEDIATION</div>
          <h1>Remediation<span className="heading-period">.</span></h1>
          <p className="page-subtitle">
            Evidence-backed remediation references for {report.repository_name}.
          </p>
        </div>
        <span className="subtle-tag">LATEST SCAN REPORT</span>
      </div>

      <div className="remediation-summary">
        <div className="panel">
          <span>TOTAL REFERENCES</span>
          <strong>{counts.all}</strong>
        </div>
        <div className="panel">
          <span>FIXED VERSIONS AVAILABLE</span>
          <strong>{counts.available}</strong>
        </div>
        <div className="panel">
          <span>STATUS UNKNOWN</span>
          <strong>{counts.unknown}</strong>
        </div>
      </div>

      <div className="panel remediation-workspace">
        <div className="remediation-toolbar">
          <div className="remediation-search">
            <Search size={16} />
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search package, advisory or fixed version..."
            />
          </div>

          <select
            value={statusFilter}
            onChange={event => setStatusFilter(event.target.value)}
          >
            <option value="all">All statuses</option>
            <option value="available">Fixed version available</option>
            <option value="unknown">Unknown status</option>
          </select>
        </div>

        <div className="remediation-result-count">
          Showing {filtered.length} of {items.length} remediation references
        </div>

        {filtered.length === 0 ? (
          <div className="remediation-empty">
            {items.length === 0 ? (
              <>
                <ShieldCheck size={30} />
                <h2>No remediation references</h2>
                <p>
                  {findings.length === 0
                    ? 'This report contains no confirmed findings requiring remediation.'
                    : 'No advisory-backed remediation references were supplied for the confirmed findings.'}
                </p>
              </>
            ) : (
              <>
                <Search size={25} />
                <h2>No matching remediation references</h2>
                <p>Try changing your search or status filter.</p>
                <button onClick={() => {
                  setSearch('')
                  setStatusFilter('all')
                }}>
                  Clear filters
                </button>
              </>
            )}
          </div>
        ) : (
          <div className="remediation-list">
            {filtered.map(item => {
              const isExpanded = expanded === item.id
              const available = item.status === 'available'

              return (
                <article className="remediation-row" key={item.id}>
                  <button
                    className="remediation-main"
                    onClick={() => setExpanded(isExpanded ? null : item.id)}
                    aria-expanded={isExpanded}
                  >
                    <div className={`remediation-status ${available ? 'available' : 'unknown'}`}>
                      {available
                        ? <CheckCircle2 size={13} />
                        : <AlertTriangle size={13} />}
                      {available ? 'AVAILABLE' : 'UNKNOWN'}
                    </div>

                    <div className="remediation-package">
                      <strong>{item.package}</strong>
                      <span>{item.ecosystem} · {item.severity}</span>
                    </div>

                    <div className="remediation-advisory">
                      <strong>{item.advisoryId}</strong>
                      <span>Advisory reference</span>
                    </div>

                    <div className="remediation-version">
                      <span>FIXED VERSIONS</span>
                      <strong>
                        {available ? item.fixedVersions.join(', ') : 'Not established'}
                      </strong>
                    </div>

                    {isExpanded
                      ? <ChevronUp size={17} />
                      : <ChevronDown size={17} />}
                  </button>

                  {isExpanded && (
                    <div className="remediation-details">
                      <p>{item.summary}</p>

                      <div className="remediation-detail-grid">
                        <div>
                          <span>PACKAGE</span>
                          <strong>{item.package}</strong>
                        </div>
                        <div>
                          <span>REMEDIATION STATUS</span>
                          <strong>{item.status}</strong>
                        </div>
                        <div>
                          <span>FIXED VERSIONS</span>
                          <strong>
                            {available
                              ? item.fixedVersions.join(', ')
                              : 'No fixed version reported'}
                          </strong>
                        </div>
                        <div>
                          <span>ADVISORY</span>
                          <strong>{item.advisoryId}</strong>
                        </div>
                      </div>

                      <div className="remediation-paths">
                        <strong>
                          <GitBranch size={14} /> Affected installation paths
                        </strong>
                        {item.installPaths.length ? (
                          item.installPaths.map(path => (
                            <code key={path}>{path}</code>
                          ))
                        ) : (
                          <span>No installation paths reported.</span>
                        )}
                      </div>
                    </div>
                  )}
                </article>
              )
            })}
          </div>
        )}
      </div>
    </section>
  )
}

export default RemediationPage
