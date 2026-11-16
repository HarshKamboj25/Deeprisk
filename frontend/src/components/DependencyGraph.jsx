import { useCallback, useEffect, useRef, useState } from 'react'
import { Search, ZoomIn, ZoomOut, Maximize, X, Network, GitBranch } from 'lucide-react'
import ForceGraph3D from '3d-force-graph'

function DependencyGraph({ report, full = false, preview = false }) {
  const containerRef = useRef(null)
  const graphRef = useRef(null)
  const allNodesRef = useRef([])
  const allLinksRef = useRef([])
  const [selected, setSelected] = useState(null)
  const [search, setSearch] = useState('')
  const [showDirect, setShowDirect] = useState(true)
  const [showTransitive, setShowTransitive] = useState(true)

  useEffect(() => {
    if (!containerRef.current || !report) return

    const dependencies = report.dependencies || []
    const edges = report.edges || []
    const paths = new Set(dependencies.map(item => item.install_path))
    const children = new Map()

    edges.forEach(edge => {
      const parent = edge.parent_path || '__root__'
      if (!children.has(parent)) children.set(parent, [])
      children.get(parent).push(edge.child_path)
    })

    const depths = new Map([['__root__', 0]])
    const queue = ['__root__']

    for (let i = 0; i < queue.length; i++) {
      const parent = queue[i]
      ;(children.get(parent) || []).forEach(child => {
        if (depths.has(child)) return
        depths.set(child, (depths.get(parent) || 0) + 1)
        queue.push(child)
      })
    }

    const nodes = [
      {
        id: '__root__',
        name: report.repository_name || 'Repository',
        kind: 'root',
        val: 13,
        color: '#8df5df'
      },
      ...dependencies.map(dependency => ({
        id: dependency.install_path,
        name: dependency.name,
        label: dependency.name,
        version: dependency.version,
        kind: dependency.is_direct ? 'direct' : 'transitive',
        depth: depths.get(dependency.install_path) ?? 1,
        ecosystem: dependency.ecosystem,
        reachability: dependency.reachability,
        sourceType: dependency.source_type,
        resolved: dependency.resolved,
        installPath: dependency.install_path,
        hasInstallScript: dependency.has_install_script,
        sourceEligibility: dependency.source_eligibility,
        val: dependency.is_direct ? 4 : 2,
        color: dependency.is_direct ? '#70d8c2' : '#8b83d6'
      }))
    ]

    const links = edges
      .filter(edge =>
        paths.has(edge.child_path) &&
        (!edge.parent_path || paths.has(edge.parent_path))
      )
      .map(edge => ({
        source: edge.parent_path || '__root__',
        target: edge.child_path,
        requestedRange: edge.requested_range || '',
        scope: edge.scope || ''
      }))

    allNodesRef.current = nodes
    allLinksRef.current = links

    const graph = ForceGraph3D({
      controlType: 'orbit',
      rendererConfig: { antialias: true, alpha: true }
    })(containerRef.current)

    graphRef.current = graph

    const largeGraph = nodes.length > 2500

    graph
      .backgroundColor('#071014')
      .showNavInfo(false)
      .nodeId('id')
      .nodeLabel(node =>
        node.kind === 'root'
          ? node.name
          : `${node.name} · ${node.version || 'Unknown'}`
      )
      .nodeVal('val')
      .nodeColor(node => node.color)
      .nodeOpacity(0.94)
      .nodeResolution(largeGraph ? 5 : 9)
      .linkColor(link =>
        selected && (
          link.source.id === selected.id ||
          link.target.id === selected.id
        ) ? '#9af5df' : '#397c83'
      )
      .linkOpacity(largeGraph ? 0.22 : 0.48)
      .linkWidth(0.65)
      .linkDirectionalParticles(links.length > 2500 ? 0 : 1)
      .linkDirectionalParticleWidth(1.4)
      .linkDirectionalParticleSpeed(0.0025)
      .graphData({ nodes, links })
      .cooldownTicks(largeGraph ? 45 : 90)
      .warmupTicks(largeGraph ? 12 : 25)
      .d3AlphaDecay(0.045)
      .d3VelocityDecay(0.35)
      .onNodeClick(node => {
        setSelected({ ...node })
        graph.cameraPosition(
          { x: node.x * 1.4 + 1, y: node.y * 1.4 + 1, z: node.z * 1.4 + 140 },
          node,
          700
        )
      })

    graph.controls().autoRotate = true
    graph.controls().autoRotateSpeed = 0.32
    graph.controls().enableDamping = true

    const resizeObserver = new ResizeObserver(entries => {
      const rect = entries[0]?.contentRect
      if (rect?.width && rect?.height) {
        graph.width(rect.width)
        graph.height(rect.height)
      }
    })

    resizeObserver.observe(containerRef.current)

    const visibilityHandler = () => {
      if (document.hidden) graph.pauseAnimation()
      else graph.resumeAnimation()
    }

    document.addEventListener('visibilitychange', visibilityHandler)

    return () => {
      resizeObserver.disconnect()
      document.removeEventListener('visibilitychange', visibilityHandler)
      graph.pauseAnimation()
      graph.graphData({ nodes: [], links: [] })
      graphRef.current = null
      if (containerRef.current) containerRef.current.innerHTML = ''
    }
  }, [report])

  useEffect(() => {
    const graph = graphRef.current
    if (!graph) return

    graph.nodeVisibility(node =>
      node.kind === 'root' ||
      (node.kind === 'direct' && showDirect) ||
      (node.kind === 'transitive' && showTransitive)
    )

    graph.linkVisibility(link => {
      const source = typeof link.source === 'object' ? link.source : null
      const target = typeof link.target === 'object' ? link.target : null
      if (!source || !target) return true

      const sourceVisible = source.kind === 'root' ||
        (source.kind === 'direct' && showDirect) ||
        (source.kind === 'transitive' && showTransitive)

      const targetVisible = target.kind === 'root' ||
        (target.kind === 'direct' && showDirect) ||
        (target.kind === 'transitive' && showTransitive)

      return sourceVisible && targetVisible
    })
  }, [showDirect, showTransitive])

  useEffect(() => {
    const graph = graphRef.current
    if (!graph) return

    const term = search.trim().toLowerCase()
    const nodes = allNodesRef.current
    const match = term
      ? nodes.find(node =>
          node.kind !== 'root' &&
          `${node.name} ${node.version || ''} ${node.installPath || ''}`
            .toLowerCase().includes(term)
        )
      : null

    graph.nodeColor(node => {
      if (selected && node.id === selected.id) return '#ffffff'
      if (term && node.kind !== 'root') {
        return node.id === match?.id ? '#b9fff0' : '#263b43'
      }
      return node.color
    })

    if (match) {
      graph.cameraPosition(
        { x: match.x * 1.5 + 1, y: match.y * 1.5 + 1, z: match.z * 1.5 + 150 },
        match,
        800
      )
    }
  }, [search, selected])

  const fitGraph = useCallback(() => {
    graphRef.current?.zoomToFit(650, 65)
  }, [])

  const zoom = factor => {
    const graph = graphRef.current
    if (!graph) return
    const camera = graph.cameraPosition()
    graph.cameraPosition({
      x: camera.x * factor,
      y: camera.y * factor,
      z: camera.z * factor
    }, undefined, 350)
  }

  const clearSelection = () => setSelected(null)
  const inspect = selected?.kind !== 'root'

  if (!report) {
    return <div className="graph-empty">Run a scan to generate the dependency network.</div>
  }

  return (
    <div className={`dependency-graph-wrap graph-3d ${full ? 'graph-full' : ''} ${preview ? 'graph-preview' : ''}`}>
      <div className="graph-toolbar">
        <div className="graph-search">
          <Search size={15} />
          <input
            value={search}
            onChange={event => setSearch(event.target.value)}
            placeholder="Search packages..."
            aria-label="Search packages"
          />
          {search && (
            <button onClick={() => setSearch('')} aria-label="Clear search">
              <X size={14} />
            </button>
          )}
        </div>

        <div className="graph-filters">
          <label>
            <input type="checkbox" checked={showDirect}
              onChange={event => setShowDirect(event.target.checked)} />
            Direct
          </label>
          <label>
            <input type="checkbox" checked={showTransitive}
              onChange={event => setShowTransitive(event.target.checked)} />
            Transitive
          </label>
        </div>

        <div className="graph-controls">
          <button onClick={() => zoom(0.8)} aria-label="Zoom in"><ZoomIn size={16} /></button>
          <button onClick={() => zoom(1.25)} aria-label="Zoom out"><ZoomOut size={16} /></button>
          <button onClick={fitGraph} aria-label="Fit graph"><Maximize size={16} /></button>
        </div>
      </div>

      <div className="dependency-graph-canvas" ref={containerRef} />

      {selected && (
        <div className="graph-selection">
          <div className="graph-inspector-heading">
            <div>
              <div className="panel-kicker">SELECTED COMPONENT</div>
              <strong>{selected.name || selected.label}</strong>
            </div>
            <button onClick={clearSelection} aria-label="Close inspector">
              <X size={15} />
            </button>
          </div>

          {inspect ? (
            <div className="graph-inspector-grid">
              <div><span>VERSION</span><strong>{selected.version || 'Unknown'}</strong></div>
              <div><span>DEPENDENCY TYPE</span><strong>{selected.kind}</strong></div>
              <div><span>ECOSYSTEM</span><strong>{selected.ecosystem || 'Unknown'}</strong></div>
              <div><span>SOURCE</span><strong>{selected.sourceType || 'Unknown'}</strong></div>
              <div><span>REACHABILITY</span><strong>{selected.reachability?.effective_scope || 'Not available'}</strong></div>
              <div><span>INSTALL SCRIPT</span><strong>{selected.hasInstallScript ? 'Present' : 'Not present'}</strong></div>
              <div className="inspector-wide"><span>INSTALL PATH</span><strong>{selected.installPath}</strong></div>
              <div className="inspector-wide"><span>SOURCE ELIGIBILITY</span><strong>{selected.sourceEligibility?.status || 'Not available'}</strong></div>
            </div>
          ) : <span>Repository root</span>}
        </div>
      )}

      <div className="graph-interaction-hint">
        <span><Network size={13} /> {report.dependencies?.length || 0} packages</span>
        <span><GitBranch size={13} /> {report.edges?.length || 0} relationships</span>
        <span>Drag to orbit · Scroll to zoom · Click a node to inspect</span>
      </div>
    </div>
  )
}

export default DependencyGraph
