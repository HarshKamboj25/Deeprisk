import { Fragment, useMemo, useState } from 'react'
import {
  FileBarChart, FolderGit2, Clock3, Package,
  ShieldCheck, Search, FileCode2, Download, FileJson, FileSpreadsheet
} from 'lucide-react'
import {
  ResponsiveContainer,
  PieChart, Pie, Cell,
  BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip
} from 'recharts'

function formatDate(value) {
  if (!value) return 'Not available'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return 'Not available'

  return date.toLocaleString()
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')

  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()

  URL.revokeObjectURL(url)
}

function escapeCsv(value) {
  const text = value == null ? '' : String(value)
  return `"${text.replace(/"/g, '""')}"`
}
function ReportsPage({ report, scan }) {
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [currentPage, setCurrentPage] = useState(1)
  const pageSize = 10

  const dependencies = report?.dependencies || []
  const findings = report?.findings || []
  const edges = report?.edges || []
  const summary = report?.summary || {}

  const analytics = useMemo(() => {
    const direct = dependencies.filter(item => item.is_direct === true).length
    const transitive = dependencies.filter(item => item.is_direct === false).length

    const unreachable = dependencies.filter(
      item => item.reachability?.is_unreachable === true
    ).length

    const scopeCounts = new Map()

    dependencies.forEach(item => {
      const scopes = Array.isArray(item.scopes) ? item.scopes : []

      if (scopes.length === 0) {
        scopeCounts.set('Unspecified', (scopeCounts.get('Unspecified') || 0) + 1)
        return
      }

      scopes.forEach(scope => {
        const label = String(scope || 'Unspecified')
        scopeCounts.set(label, (scopeCounts.get(label) || 0) + 1)
      })
    })

    const parentCounts = new Map()

    edges.forEach(edge => {
      const parent = edge.parent_path || 'Unknown parent'
      parentCounts.set(parent, (parentCounts.get(parent) || 0) + 1)
    })

    const relationshipHotspots = [...parentCounts.entries()]
      .map(([path, count]) => ({
        name: path.split('/').filter(Boolean).pop() || path,
        path,
        count,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8)

    return {
      composition: [
        { name: 'Direct', value: direct },
        { name: 'Transitive', value: transitive },
      ],
      scopes: [...scopeCounts.entries()].map(([name, value]) => ({
        name,
        value,
      })),
      reachability: [
        { name: 'Marked unreachable', value: unreachable },
        { name: 'Not marked unreachable', value: dependencies.length - unreachable },
      ],
      relationshipHotspots,
      direct,
      transitive,
      unreachable,
      unclassified: dependencies.length - direct - transitive,
    }
  }, [dependencies, edges])

  const filteredDependencies = useMemo(() => {
    const query = search.trim().toLowerCase()

    if (!query) return dependencies

    return dependencies.filter(dependency =>
      [
        dependency.name,
        dependency.version,
        dependency.ecosystem,
        dependency.install_path,
        dependency.source_type,
      ].some(value => value?.toLowerCase().includes(query))
    )
  }, [dependencies, search])

  const totalPages = Math.max(1, Math.ceil(filteredDependencies.length / pageSize))
  const pageStart = (currentPage - 1) * pageSize
  const visibleDependencies = filteredDependencies.slice(pageStart, pageStart + pageSize)
  const firstVisible = filteredDependencies.length === 0 ? 0 : pageStart + 1
  const lastVisible = Math.min(pageStart + pageSize, filteredDependencies.length)

  if (!report) {
    return (
      <section className="reports-page">
        <div className="page-intro">
          <div>
            <div className="eyebrow">SECURITY INTELLIGENCE / REPORTS</div>
            <h1>Scan reports<span className="heading-period">.</span></h1>
            <p className="page-subtitle">
              Inspect immutable repository analysis snapshots.
            </p>
          </div>
        </div>

        <div className="panel reports-empty">
          <FileBarChart size={32} />
          <h2>No report available</h2>
          <p>Complete a repository scan to inspect its report snapshot.</p>
        </div>
      </section>
    )
  }

  const status = scan?.status || 'succeeded'

  const safeRepositoryName = (report.repository_name || 'repository')
    .replace(/[^a-zA-Z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'repository'

  const exportJson = () => {
    const json = JSON.stringify(report, null, 2)
    downloadFile(
      json,
      `${safeRepositoryName}-scan-report.json`,
      'application/json;charset=utf-8'
    )
  }

  const exportCsv = () => {
    const headers = [
      'Package',
      'Version',
      'Ecosystem',
      'Type',
      'Scopes',
      'Reachability',
      'Source Type',
      'Installation Path',
      'Resolved URL',
      'Has Install Script',
    ]

    const rows = dependencies.map(dependency => [
      dependency.name,
      dependency.version,
      dependency.ecosystem,
      dependency.is_direct === true
        ? 'Direct'
        : dependency.is_direct === false
          ? 'Transitive'
          : 'Unclassified',
      Array.isArray(dependency.scopes)
        ? dependency.scopes.join('; ')
        : '',
      dependency.reachability?.is_unreachable === true
        ? 'Unreachable'
        : 'Not marked unreachable',
      dependency.source_type,
      dependency.install_path,
      dependency.resolved,
      dependency.has_install_script,
    ])

    const csv = [
      headers.map(escapeCsv).join(','),
      ...rows.map(row => row.map(escapeCsv).join(',')),
    ].join('\r\n')

    downloadFile(
      '\uFEFF' + csv,
      `${safeRepositoryName}-dependencies.csv`,
      'text/csv;charset=utf-8'
    )
  }

  return (
    <section className="reports-page">
      <div className="page-intro">
        <div>
          <div className="eyebrow">SECURITY INTELLIGENCE / REPORTS</div>
          <h1>Scan reports<span className="heading-period">.</span></h1>
          <p className="page-subtitle">
            Latest available analysis snapshot for {report.repository_name}.
          </p>
        </div>
        <div className="reports-export-actions">
          <span className="subtle-tag">LATEST REPORT SNAPSHOT</span>

          <button
            type="button"
            className="reports-export-button"
            onClick={exportJson}
            title="Download complete JSON report"
          >
            <FileJson size={15} />
            Export JSON
            <Download size={14} />
          </button>

          <button
            type="button"
            className="reports-export-button secondary"
            onClick={exportCsv}
            title="Download complete dependency inventory"
          >
            <FileSpreadsheet size={15} />
            Export CSV
            <Download size={14} />
          </button>
        </div>
      </div>

      <div className="reports-identity panel">
        <div className="reports-identity-icon">
          <FolderGit2 size={21} />
        </div>

        <div className="reports-identity-copy">
          <span>ANALYZED REPOSITORY</span>
          <h2>{report.repository_name || 'Unknown repository'}</h2>
          <p>{report.repository_path || 'Repository path not available'}</p>
        </div>

        <div className={`reports-status ${status}`}>
          <span />
          {status.toUpperCase()}
        </div>
      </div>

      <div className="reports-summary">
        <div className="panel">
          <span>DEPENDENCIES</span>
          <strong>{summary.total_dependencies ?? dependencies.length}</strong>
        </div>
        <div className="panel">
          <span>RELATIONSHIPS</span>
          <strong>{summary.total_edges ?? edges.length}</strong>
        </div>
        <div className="panel">
          <span>CONFIRMED FINDINGS</span>
          <strong>{summary.confirmed_findings ?? findings.length}</strong>
        </div>
        <div className="panel">
          <span>UNREACHABLE</span>
          <strong>{summary.unreachable_dependencies ?? 'N/A'}</strong>
        </div>
      </div>

<section className="reports-analytics">
        <div className="reports-analytics-heading">
          <div>
            <div className="eyebrow">REPORT BREAKDOWN</div>
            <h2>Dependency analytics<span className="heading-period">.</span></h2>
            <p>Structural insights calculated from this scan snapshot.</p>
          </div>
          <span className="subtle-tag">LIVE REPORT DATA</span>
        </div>

        <div className="reports-chart-grid">
          <article className="panel reports-chart-card">
            <div className="reports-chart-heading">
              <div>
                <h3>Dependency composition</h3>
                <p>Direct and transitive packages</p>
              </div>
              <Package size={17} />
            </div>

            <div className="reports-chart">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={analytics.composition}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={57}
                    outerRadius={83}
                    paddingAngle={4}
                    stroke="none"
                  >
                    <Cell fill="#58c8c0" />
                    <Cell fill="#647b9d" />
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: '#111a21',
                      border: '1px solid #30424c',
                      borderRadius: '9px',
                      color: '#e5edf1',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="reports-chart-legend">
              <span><i className="legend-teal" />Direct <strong>{analytics.direct}</strong></span>
              <span><i className="legend-blue" />Transitive <strong>{analytics.transitive}</strong></span>
              {analytics.unclassified > 0 && (
                <span className="reports-chart-note">
                  {analytics.unclassified} dependencies have an unclassified type.
                </span>
              )}
            </div>
          </article>

          <article className="panel reports-chart-card">
            <div className="reports-chart-heading">
              <div>
                <h3>Scope distribution</h3>
                <p>Package scope labels from the lockfile analysis</p>
              </div>
              <FileBarChart size={17} />
            </div>

            {analytics.scopes.length > 0 ? (
              <>
                <div className="reports-chart">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={analytics.scopes}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={57}
                        outerRadius={83}
                        paddingAngle={3}
                        stroke="none"
                      >
                        {analytics.scopes.map((entry, index) => (
                          <Cell
                            key={entry.name}
                            fill={['#58c8c0', '#647b9d', '#a28acb', '#c69d65', '#728d9b', '#819b83'][index % 6]}
                          />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: '#111a21',
                          border: '1px solid #30424c',
                          borderRadius: '9px',
                          color: '#e5edf1',
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                <div className="reports-scope-legend">
                  {analytics.scopes.map((scope, index) => (
                    <span key={scope.name}>
                      <i style={{
                        background: ['#58c8c0', '#647b9d', '#a28acb', '#c69d65', '#728d9b', '#819b83'][index % 6]
                      }} />
                      {scope.name} <strong>{scope.value}</strong>
                    </span>
                  ))}
                </div>
                <p className="reports-chart-note">
                  Scope labels may overlap when a package has multiple scopes.
                </p>
              </>
            ) : (
              <div className="reports-chart-empty">No scope data available.</div>
            )}
          </article>

          <article className="panel reports-chart-card">
            <div className="reports-chart-heading">
              <div>
                <h3>Reachability analysis</h3>
                <p>Explicit reachability classification</p>
              </div>
              <ShieldCheck size={17} />
            </div>

            <div className="reports-chart">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={analytics.reachability} margin={{ top: 15, right: 12, left: 0, bottom: 5 }}>
                  <CartesianGrid stroke="#26343d" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="name"
                    tick={{ fill: '#91a2ad', fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: '#91a2ad', fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#111a21',
                      border: '1px solid #30424c',
                      borderRadius: '9px',
                      color: '#e5edf1',
                    }}
                  />
                  <Bar dataKey="value" name="Packages" radius={[5, 5, 0, 0]}>
                    <Cell fill="#d18b79" />
                    <Cell fill="#58aeb1" />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <p className="reports-chart-note">
              Not marked unreachable does not necessarily mean confirmed reachable.
            </p>
          </article>

          <article className="panel reports-chart-card reports-hotspot-card">
            <div className="reports-chart-heading">
              <div>
                <h3>Relationship hotspots</h3>
                <p>Packages with the most outgoing dependency edges</p>
              </div>
              <FileBarChart size={17} />
            </div>

            {analytics.relationshipHotspots.length > 0 ? (
              <div className="reports-chart reports-hotspot-chart">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={analytics.relationshipHotspots}
                    layout="vertical"
                    margin={{ top: 4, right: 18, left: 8, bottom: 4 }}
                  >
                    <CartesianGrid stroke="#26343d" strokeDasharray="3 3" horizontal={false} />
                    <XAxis
                      type="number"
                      allowDecimals={false}
                      tick={{ fill: '#91a2ad', fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={105}
                      tick={{ fill: '#b7c6ce', fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      formatter={(value) => [value, 'Outgoing edges']}
                      labelFormatter={(label, payload) => payload?.[0]?.payload?.path || label}
                      contentStyle={{
                        background: '#111a21',
                        border: '1px solid #30424c',
                        borderRadius: '9px',
                        color: '#e5edf1',
                      }}
                    />
                    <Bar dataKey="count" name="Outgoing edges" fill="#647b9d" radius={[0, 5, 5, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="reports-chart-empty">No relationship data available.</div>
            )}
          </article>
        </div>
      </section>

      <div className="reports-information">
        <div className="panel reports-metadata">
          <div className="reports-section-heading">
            <FileCode2 size={17} />
            <h2>Report metadata</h2>
          </div>

          <div className="reports-metadata-grid">
            <div>
              <span>REPORT SCHEMA</span>
              <strong>{report.schema_version || 'Not available'}</strong>
            </div>
            <div>
              <span>SCAN ID</span>
              <strong className="reports-mono">{scan?.scanId || 'Not retained in this session'}</strong>
            </div>
            <div>
              <span>SCAN CREATED</span>
              <strong>{formatDate(scan?.created_at)}</strong>
            </div>
            <div>
              <span>SCAN STARTED</span>
              <strong>{formatDate(scan?.started_at)}</strong>
            </div>
            <div>
              <span>SCAN FINISHED</span>
              <strong>{formatDate(scan?.finished_at)}</strong>
            </div>
            <div>
              <span>LOCKFILE</span>
              <strong>{report.lockfile_path || 'Not available'}</strong>
            </div>
          </div>
        </div>

        <div className="panel reports-scan-context">
          <div className="reports-section-heading">
            <Clock3 size={17} />
            <h2>Scan context</h2>
          </div>

          <div className="reports-context-row">
            <span>Source type</span>
            <strong>{scan?.source_type || 'Not retained'}</strong>
          </div>
          <div className="reports-context-row">
            <span>Analysis status</span>
            <strong>{status}</strong>
          </div>
          <div className="reports-context-row">
            <span>Dependencies analyzed</span>
            <strong>{dependencies.length}</strong>
          </div>
          <div className="reports-context-row">
            <span>Advisory findings</span>
            <strong>{findings.length}</strong>
          </div>
        </div>
      </div>

      <div className="panel reports-dependencies">
        <div className="reports-section-heading">
          <Package size={17} />
          <h2>Dependency inventory</h2>
          <span className="reports-section-count">{dependencies.length} packages</span>
        </div>

        <div className="reports-search">
          <Search size={15} />
          <input
            value={search}
            onChange={event => { setSearch(event.target.value); setCurrentPage(1); setExpanded(null) }}
            placeholder="Search package, version or installation path..."
          />
        </div>

        <div className="reports-table-wrap">
          <table className="reports-table">
            <thead>
              <tr>
                <th>PACKAGE</th>
                <th>VERSION</th>
                <th>TYPE</th>
                <th>SCOPE</th>
                <th>REACHABILITY</th>
              </tr>
            </thead>
            <tbody>
              {visibleDependencies.map((dependency, index) => {
                const dependencyKey = dependency.install_path || `${dependency.name}-${dependency.version}`
                const isExpanded = expanded === dependencyKey

                return (
                  <Fragment key={dependencyKey}>
                    <tr
                      className="reports-dependency-row"
                      onClick={() => setExpanded(isExpanded ? null : dependencyKey)}
                    >
                      <td>
                        <strong>{dependency.name}</strong>
                      </td>
                      <td>{dependency.version}</td>
                      <td>{dependency.is_direct ? 'Direct' : 'Transitive'}</td>
                      <td>{(dependency.scopes || []).join(', ') || 'Unknown'}</td>
                      <td>{dependency.reachability?.is_unreachable ? 'Unreachable' : 'Reachable / unclassified'}</td>
                    </tr>
                    {isExpanded && (
                      <tr className="reports-expanded-row">
                        <td colSpan={5}>
                          <div>
                            <span>INSTALLATION PATH</span>
                            <code>{dependency.install_path || 'Not available'}</code>
                          </div>
                          <div>
                            <span>SOURCE TYPE</span>
                            <strong>{dependency.source_type || 'Unknown'}</strong>
                          </div>
                          <div>
                            <span>RESOLVED</span>
                            <strong>{dependency.resolved ? 'Yes' : 'No'}</strong>
                          </div>
                          <div>
                            <span>INSTALL SCRIPT</span>
                            <strong>{dependency.has_install_script ? 'Present' : 'Not reported'}</strong>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>

        {filteredDependencies.length === 0 && (
          <div className="reports-table-empty">
            No matching dependencies found.
          </div>
)}

        {filteredDependencies.length > 0 && (
          <div className="reports-pagination">
            <span>
              Showing <strong>{firstVisible}–{lastVisible}</strong> of{' '}
              <strong>{filteredDependencies.length}</strong> packages
            </span>

            <div className="reports-pagination-controls">
              <button
                type="button"
                className="reports-page-button"
                disabled={currentPage === 1}
                onClick={() => {
                  setCurrentPage(page => Math.max(1, page - 1))
                  setExpanded(null)
                }}
              >
                Previous
              </button>

              <span className="reports-page-indicator">
                Page {currentPage} of {totalPages}
              </span>

              <button
                type="button"
                className="reports-page-button"
                disabled={currentPage >= totalPages}
                onClick={() => {
                  setCurrentPage(page => Math.min(totalPages, page + 1))
                  setExpanded(null)
                }}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="panel reports-findings">
        <div className="reports-section-heading">
          <ShieldCheck size={17} />
          <h2>Confirmed findings</h2>
          <span className="reports-section-count">{findings.length} findings</span>
        </div>

        {findings.length ? findings.map((finding, index) => (
          <div className="reports-finding-row" key={`${finding.package?.name}-${index}`}>
            <div>
              <strong>{finding.package?.name}</strong>
              <span>
                {finding.package?.version} · {finding.canonical_advisory_id}
              </span>
            </div>
            <span>{finding.advisory_ids?.length || 0} advisory IDs</span>
          </div>
        )) : (
          <div className="reports-findings-empty">
            <ShieldCheck size={23} />
            <strong>No confirmed findings in this report</strong>
            <span>This does not establish that the repository is vulnerability-free.</span>
          </div>
        )}
      </div>
    </section>
  )
}

export default ReportsPage
