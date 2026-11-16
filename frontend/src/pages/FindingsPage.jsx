import { useMemo, useState } from 'react'
import {
  Search, Bug, ChevronDown, ChevronUp, ShieldCheck,
  AlertTriangle, Filter, ExternalLink
} from 'lucide-react'

const severityOrder = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  unknown: 1,
}

const severityColors = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  unknown: 'unknown',
}

function getFindingDetails(finding) {
  const advisories = finding.advisories || []

  const sorted = [...advisories].sort((a, b) => {
    const severityDifference =
      (severityOrder[b.severity?.toLowerCase()] || 0) -
      (severityOrder[a.severity?.toLowerCase()] || 0)

    return severityDifference ||
      (b.cvss_score ?? -1) - (a.cvss_score ?? -1)
  })

  const primary = sorted[0] || {}

  const fixedVersions = [
    ...new Set(
      advisories.flatMap(advisory =>
        (advisory.remediations || []).flatMap(remediation =>
          remediation.fixed_versions || []
        )
      )
    ),
  ]

  return {
    severity: primary.severity?.toLowerCase() || 'unknown',
    cvss: primary.cvss_score,
    summary: primary.summary || 'No advisory summary available.',
    source: primary.source || 'Unknown',
    fixedVersions,
    advisories: sorted,
  }
}

function FindingsPage({ report }) {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('all')
  const [sortBy, setSortBy] = useState('severity')
  const [expanded, setExpanded] = useState(null)

  const findings = report?.findings || []

  const processed = useMemo(() => {
    const rows = findings.map((finding, index) => ({
      ...finding,
      id: `${finding.package?.name}-${finding.canonical_advisory_id}-${index}`,
      details: getFindingDetails(finding),
    }))

    const filtered = rows.filter(finding => {
      const query = search.trim().toLowerCase()

      const matchesSearch = !query || [
        finding.package?.name,
        finding.package?.version,
        finding.canonical_advisory_id,
        ...(finding.advisory_ids || []),
        ...(finding.aliases || []),
      ].some(value => value?.toLowerCase().includes(query))

      const matchesSeverity =
        severity === 'all' || finding.details.severity === severity

      return matchesSearch && matchesSeverity
    })

    return filtered.sort((a, b) => {
      if (sortBy === 'cvss') {
        return (b.details.cvss ?? -1) - (a.details.cvss ?? -1)
      }

      return (
        (severityOrder[b.details.severity] || 0) -
        (severityOrder[a.details.severity] || 0)
      )
    })
  }, [findings, search, severity, sortBy])

  const counts = useMemo(() => {
    const result = { all: findings.length }

    Object.keys(severityOrder).forEach(level => {
      result[level] = findings.filter(
        finding => getFindingDetails(finding).severity === level
      ).length
    })

    return result
  }, [findings])

  if (!report) {
    return (
      <section className="findings-page">
        <div className="page-intro">
          <div>
            <div className="eyebrow">SECURITY INTELLIGENCE / FINDINGS</div>
            <h1>Security findings<span className="heading-period">.</span></h1>
            <p className="page-subtitle">Run a repository scan to inspect verified vulnerability findings.</p>
          </div>
        </div>
        <div className="panel findings-empty">
          <Bug size={32} />
          <h2>No scan report available</h2>
          <p>Findings will appear here after a successful repository scan.</p>
        </div>
      </section>
    )
  }

  return (
    <section className="findings-page">
      <div className="page-intro">
        <div>
          <div className="eyebrow">SECURITY INTELLIGENCE / FINDINGS</div>
          <h1>Security findings<span className="heading-period">.</span></h1>
          <p className="page-subtitle">
            Verified advisory matches affecting packages in {report.repository_name}.
          </p>
        </div>
        <span className="subtle-tag">LATEST SCAN REPORT</span>
      </div>

      <div className="findings-summary">
        <div className="panel">
          <span>CONFIRMED FINDINGS</span>
          <strong>{findings.length}</strong>
        </div>
        {Object.entries(severityOrder).filter(([key]) => key !== 'unknown').map(([key]) => (
          <div className="panel" key={key}>
            <span>{key.toUpperCase()}</span>
            <strong>{counts[key]}</strong>
          </div>
        ))}
      </div>

      <div className="panel findings-workspace">
        <div className="findings-toolbar">
          <div className="findings-search">
            <Search size={16} />
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search package, CVE or advisory..."
            />
          </div>

          <div className="findings-toolbar-controls">
            <label>
              <Filter size={14} />
              <select value={severity} onChange={event => setSeverity(event.target.value)}>
                <option value="all">All severities</option>
                {Object.keys(severityOrder).map(level => (
                  <option key={level} value={level}>
                    {level.charAt(0).toUpperCase() + level.slice(1)}
                  </option>
                ))}
              </select>
            </label>

            <select value={sortBy} onChange={event => setSortBy(event.target.value)}>
              <option value="severity">Sort: Severity</option>
              <option value="cvss">Sort: CVSS</option>
            </select>
          </div>
        </div>

        <div className="findings-result-count">
          Showing {processed.length} of {findings.length} findings
        </div>

        {processed.length === 0 ? (
          <div className="findings-empty">
            {findings.length === 0 ? (
              <>
                <div className="findings-empty-icon">
                  <ShieldCheck size={27} />
                </div>
                <h2>No confirmed vulnerabilities</h2>
                <p>
                  This scan returned no confirmed affected-package matches.
                  This does not guarantee that the repository has no vulnerabilities.
                </p>
              </>
            ) : (
              <>
                <Search size={25} />
                <h2>No matching findings</h2>
                <p>Try changing your search or severity filter.</p>
                <button onClick={() => { setSearch(''); setSeverity('all') }}>
                  Clear filters
                </button>
              </>
            )}
          </div>
        ) : (
          <div className="findings-list">
            {processed.map(finding => {
              const details = finding.details
              const isExpanded = expanded === finding.id

              return (
                <article className="finding-row" key={finding.id}>
                  <button
                    className="finding-main"
                    onClick={() => setExpanded(isExpanded ? null : finding.id)}
                    aria-expanded={isExpanded}
                  >
                    <div className={`finding-severity ${severityColors[details.severity]}`}>
                      {details.severity.toUpperCase()}
                    </div>

                    <div className="finding-package">
                      <strong>{finding.package?.name}</strong>
                      <span>v{finding.package?.version} · {finding.package?.ecosystem}</span>
                    </div>

                    <div className="finding-advisory">
                      <strong>{finding.canonical_advisory_id}</strong>
                      <span>{finding.advisory_ids?.length || 0} advisory IDs</span>
                    </div>

                    <div className="finding-cvss">
                      <span>CVSS</span>
                      <strong>{details.cvss ?? 'N/A'}</strong>
                    </div>

                    {isExpanded ? <ChevronUp size={17} /> : <ChevronDown size={17} />}
                  </button>

                  {isExpanded && (
                    <div className="finding-details">
                      <p>{details.summary}</p>

                      <div className="finding-detail-grid">
                        <div>
                          <span>ADVISORY SOURCE</span>
                          <strong>{details.source}</strong>
                        </div>
                        <div>
                          <span>AFFECTED INSTALLATIONS</span>
                          <strong>{finding.affected_install_paths?.length || 0}</strong>
                        </div>
                        <div>
                          <span>FIXED VERSIONS</span>
                          <strong>{details.fixedVersions.length
                            ? details.fixedVersions.join(', ')
                            : 'No fixed version reported'}</strong>
                        </div>
                        <div>
                          <span>ADVISORY ALIASES</span>
                          <strong>{finding.aliases?.length
                            ? finding.aliases.join(', ')
                            : 'None reported'}</strong>
                        </div>
                      </div>

                      <div className="finding-installations">
                        <strong>Affected installation paths</strong>
                        {finding.affected_install_paths?.map(path => (
                          <code key={path}>{path}</code>
                        ))}
                      </div>

                      {details.advisories.map(advisory => (
                        <div className="finding-advisory-evidence" key={advisory.advisory_id}>
                          <strong>{advisory.advisory_id}</strong>
                          <span>{advisory.summary || 'No additional summary.'}</span>
                          <span>
                            {advisory.severity} · CVSS {advisory.cvss_score ?? 'N/A'}
                          </span>
                        </div>
                      ))}
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

export default FindingsPage
