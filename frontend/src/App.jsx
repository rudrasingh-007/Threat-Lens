import React, { useEffect, useState, useCallback, useMemo } from 'react'
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  useNodesState,
  useEdgesState,
  MarkerType,
} from 'reactflow'
import 'reactflow/dist/style.css'
import axios from 'axios'
import './App.css'

const API_BASE_URL = 'http://localhost:5000'
const NODE_TYPES = ['Host', 'User', 'Hash', 'IP']
const RELATIONSHIP_TYPES = ['ALL', 'LATERAL_MOVEMENT', 'RAN', 'CONNECTED_TO', 'LOGGED_INTO']

function getNodeColor(node) {
  if (node?.status === 'malicious') return '#ef4444'
  if (node?.status === 'suspicious') return '#f97316'

  switch (node?.type) {
    case 'Host':
      return '#10b981'
    case 'User':
      return '#3b82f6'
    case 'Hash':
      return '#eab308'
    case 'IP':
      return '#8b5cf6'
    default:
      return '#94a3b8'
  }
}

function nodeColorFn(node) {
  switch (node?.type) {
    case 'Host':
      return '#10b981'
    case 'User':
      return '#3b82f6'
    case 'Hash':
      return '#eab308'
    case 'IP':
      return '#8b5cf6'
    default:
      return '#94a3b8'
  }
}

function nodeTypeIcon(type) {
  switch (type) {
    case 'Host':
      return '[HOST]'
    case 'User':
      return '[USER]'
    case 'Hash':
      return '[HASH]'
    case 'IP':
      return '[IP]'
    default:
      return '[NODE]'
  }
}

const nodeTypIcon = nodeTypeIcon

function getNodeSize(node) {
  const severity = Number(node?.severity_score ?? 0)
  return 28 + (severity / 100) * 16
}

function getEdgeColor(type) {
  switch (type) {
    case 'LATERAL_MOVEMENT':
      return '#ef4444'
    case 'RAN':
      return '#eab308'
    case 'CONNECTED_TO':
      return '#8b5cf6'
    case 'LOGGED_INTO':
      return '#94a3b8'
    default:
      return '#1e2d45'
  }
}

function buildLayout(apiNodes, apiLinks) {
  if (!apiNodes.length) return { nodes: [], edges: [] }

  const timestamps = apiNodes.map((n) => (n.timestamp ? new Date(n.timestamp).getTime() : 0))
  const minT = Math.min(...timestamps)
  const maxT = Math.max(...timestamps)
  const range = maxT - minT || 1

  const TYPE_Y = { IP: 0, Hash: 180, Host: 360, User: 540 }
  const xCounters = {}

  const nodes = apiNodes.map((n) => {
    const t = n.timestamp ? new Date(n.timestamp).getTime() : minT
    const baseX = ((t - minT) / range) * 2400
    const typeKey = `${n.type}_${Math.round(baseX / 60)}`
    xCounters[typeKey] = (xCounters[typeKey] || 0) + 1
    const xOffset = (xCounters[typeKey] - 1) * 110
    const x = baseX + xOffset
    const y = TYPE_Y[n.type] ?? 360
    const size = 28 + ((n.severity_score || 0) / 100) * 16
    const color = n.status === 'malicious' ? '#ef4444' :
                  n.status === 'suspicious' ? '#f97316' :
                  n.type === 'Host' ? '#10b981' :
                  n.type === 'User' ? '#3b82f6' :
                  n.type === 'Hash' ? '#eab308' :
                  n.type === 'IP' ? '#8b5cf6' : '#94a3b8'

    return {
      id: n.id,
      type: 'threatNode',
      position: { x, y },
      data: { ...n, size, color, label: n.name || n.id },
    }
  })

  const nodeIds = new Set(nodes.map((n) => n.id))
  const edges = apiLinks
    .filter((l) => nodeIds.has(l.source) && nodeIds.has(l.target))
    .map((l, i) => ({
      id: `e${i}-${l.source}-${l.target}`,
      source: l.source,
      target: l.target,
      animated: l.type === 'LATERAL_MOVEMENT',
      style: {
        stroke: l.type === 'LATERAL_MOVEMENT' ? '#ef4444' :
                l.type === 'RAN' ? '#eab308' :
                l.type === 'CONNECTED_TO' ? '#8b5cf6' : '#4a5568',
        strokeWidth: l.type === 'LATERAL_MOVEMENT' ? 2 : 1,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color: l.type === 'LATERAL_MOVEMENT' ? '#ef4444' : '#4a5568' },
    }))

  return { nodes, edges }
}

function severityColor(score) {
  if (score < 40) return '#10b981'
  if (score < 70) return '#f97316'
  return '#ef4444'
}

function blastDepthColor(depth) {
  switch (depth) {
    case 1:
      return 'rgba(249, 115, 22, 1)'
    case 2:
      return 'rgba(249, 115, 22, 0.7)'
    case 3:
      return 'rgba(249, 115, 22, 0.4)'
    case 4:
      return 'rgba(249, 115, 22, 0.2)'
    default:
      return 'rgba(249, 115, 22, 0.2)'
  }
}

function ThreatNode({ data }) {
  const size = data.size || 36
  return (
    <div style={{ textAlign: 'center', cursor: 'pointer' }}>
      <Handle type="target" position={Position.Left} style={{background: 'transparent', border: 'none'}} />
      <div style={{
        width: size,
        height: size,
        borderRadius: '50%',
        background: data.color || '#94a3b8',
        border: data.status === 'malicious' ? '2px solid #ef4444' : data.status === 'suspicious' ? '2px solid #f97316' : '1px solid rgba(255,255,255,0.15)',
        boxShadow: data.status === 'malicious' ? '0 0 12px rgba(239,68,68,0.6)' : 'none',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '7px',
        fontWeight: '700',
        color: '#000',
        margin: '0 auto'
      }} />
      <div style={{
        marginTop: 6,
        fontSize: 10,
        color: data.status === 'malicious' ? '#ef4444' : data.status === 'suspicious' ? '#f97316' : '#94a3b8',
        fontFamily: 'Courier New',
        whiteSpace: 'nowrap',
        maxWidth: 90,
        overflow: 'hidden',
        textOverflow: 'ellipsis'
      }}>
        {data.name || data.id}
      </div>
      <Handle type="source" position={Position.Right} style={{background: 'transparent', border: 'none'}} />
    </div>
  )
}


function formatFieldLabel(key) {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase())
}

function formatFieldValue(value) {
  if (value === null || value === undefined || value === '') {
    return 'N/A'
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false'
  }

  return String(value)
}

function resolveEndpointId(endpoint) {
  if (endpoint && typeof endpoint === 'object') {
    return endpoint.id
  }

  return endpoint
}


function App() {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] })
  const [selectedNode, setSelectedNode] = useState(null)
  const [hypothesis, setHypothesis] = useState('')
  const [showHypothesis, setShowHypothesis] = useState(false)
  const [blastRadius, setBlastRadius] = useState(null)
  const [attackPath, setAttackPath] = useState(null)
  const [attackPathMode, setAttackPathMode] = useState(false)
  const [pathSource, setPathSource] = useState(null)
  const [filters, setFilters] = useState({
    Host: true,
    User: true,
    Hash: true,
    IP: true,
  })
  const [showThreatsOnly, setShowThreatsOnly] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [relationshipFilter, setRelationshipFilter] = useState('ALL')
  const [loading, setLoading] = useState(false)
  const [highlightNodes, setHighlightNodes] = useState(new Set())
  const [currentTime, setCurrentTime] = useState(() => new Date())

  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const nodeTypes = useMemo(() => ({ threatNode: ThreatNode }), [])

  useEffect(() => {
    let active = true

    async function fetchGraph() {
      setLoading(true)

      try {
        const response = await axios.get(`${API_BASE_URL}/api/graph`)
        if (!active) return

        const apiNodes = Array.isArray(response.data?.nodes)
          ? response.data.nodes
          : []
        const apiLinks = Array.isArray(response.data?.links)
          ? response.data.links
          : []

        setGraphData({
          nodes: apiNodes,
          links: apiLinks,
        })

        const { nodes: layoutNodes, edges: layoutEdges } = buildLayout(
          apiNodes,
          apiLinks,
        )
        setNodes(layoutNodes)
        setEdges(layoutEdges)
      } catch (error) {
        if (!active) return
        setGraphData({ nodes: [], links: [] })
        setNodes([])
        setEdges([])
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    fetchGraph()

    return () => {
      active = false
    }
  }, [setNodes, setEdges])

  useEffect(() => {
    const timerId = setInterval(() => {
      setCurrentTime(new Date())
    }, 1000)

    return () => clearInterval(timerId)
  }, [])

  const blastDepthMap = useMemo(() => {
    const depthMap = new Map()

    blastRadius?.reachable?.forEach((item) => {
      if (item?.id) {
        depthMap.set(item.id, item.depth)
      }
    })

    return depthMap
  }, [blastRadius])

  const filteredGraphData = useMemo(() => {
    const trimmedSearch = searchTerm.trim().toLowerCase()

    const visibleNodes = graphData.nodes.filter((node) => {
      if (!filters[node.type]) {
        return false
      }

      if (showThreatsOnly && node.status === 'clean') {
        return false
      }

      return true
    })

    const visibleNodeMap = new Map(visibleNodes.map((node) => [node.id, node]))

    if (!trimmedSearch) {
      const links = graphData.links.filter((link) => {
        if (relationshipFilter !== 'ALL' && link.type !== relationshipFilter) {
          return false
        }

        const sourceId = resolveEndpointId(link.source)
        const targetId = resolveEndpointId(link.target)

        return visibleNodeMap.has(sourceId) && visibleNodeMap.has(targetId)
      })

      return { nodes: visibleNodes, links }
    }

    const matchingIds = new Set()

    visibleNodes.forEach((node) => {
      const haystack = Object.values(node)
        .filter((value) => value !== null && value !== undefined)
        .map((value) => String(value).toLowerCase())
        .join(' ')

      if (haystack.includes(trimmedSearch)) {
        matchingIds.add(node.id)
      }
    })

    const searchNodeIds = new Set(matchingIds)

    graphData.links.forEach((link) => {
      const sourceId = resolveEndpointId(link.source)
      const targetId = resolveEndpointId(link.target)

      if (matchingIds.has(sourceId) && visibleNodeMap.has(targetId)) {
        searchNodeIds.add(targetId)
      }

      if (matchingIds.has(targetId) && visibleNodeMap.has(sourceId)) {
        searchNodeIds.add(sourceId)
      }
    })

    matchingIds.forEach((id) => searchNodeIds.add(id))

    const nodes = visibleNodes.filter((node) => searchNodeIds.has(node.id))
    const nodeSet = new Set(nodes.map((node) => node.id))

    const links = graphData.links.filter((link) => {
      if (relationshipFilter !== 'ALL' && link.type !== relationshipFilter) {
        return false
      }

      const sourceId = resolveEndpointId(link.source)
      const targetId = resolveEndpointId(link.target)

      return nodeSet.has(sourceId) && nodeSet.has(targetId)
    })

    return { nodes, links }
  }, [filters, graphData.links, graphData.nodes, relationshipFilter, searchTerm, showThreatsOnly])

  useEffect(() => {
    const { nodes: layoutNodes, edges: layoutEdges } = buildLayout(
      filteredGraphData.nodes,
      filteredGraphData.links,
    )

    setNodes(layoutNodes)
    setEdges(layoutEdges)
  }, [filteredGraphData, setNodes, setEdges])

  useEffect(() => {
    if (highlightNodes.size === 0) {
      setNodes((prevNodes) =>
        prevNodes.map((node) => ({
          ...node,
          style: {
            ...node.style,
            opacity: 1,
            boxShadow:
              node.data?.status === 'malicious'
                ? '0 0 12px rgba(239,68,68,0.6)'
                : 'none',
            border:
              node.data?.status === 'malicious'
                ? '2px solid #ef4444'
                : '1px solid #1e2d45',
          },
        })),
      )
    } else {
      setNodes((prevNodes) =>
        prevNodes.map((node) => {
          const isHighlighted = highlightNodes.has(node.id)
          const isSelected = selectedNode?.id === node.id
          const depth = blastDepthMap.get(node.id) ?? 1

          if (isHighlighted) {
            return {
              ...node,
              style: {
                ...node.style,
                opacity: 1,
                border: `2px solid ${blastDepthColor(depth)}`,
                boxShadow: `0 0 12px ${blastDepthColor(depth)}`,
              },
            }
          } else if (isSelected) {
            return {
              ...node,
              style: {
                ...node.style,
                opacity: 1,
                border: '2px solid #06b6d4',
                boxShadow: '0 0 12px rgba(6,182,212,0.6)',
              },
            }
          } else {
            return {
              ...node,
              style: {
                ...node.style,
                opacity: 0.2,
                boxShadow: 'none',
              },
            }
          }
        }),
      )
    }
  }, [highlightNodes, selectedNode?.id, blastDepthMap, setNodes])

  const nodeDetails = useMemo(() => {
    if (!selectedNode) {
      return []
    }

    return Object.entries(selectedNode).filter(
      ([, value]) =>
        value !== null && value !== undefined && value !== '',
    )
  }, [selectedNode])

  const fetchBlastRadius = async (nodeId) => {
    if (!nodeId) {
      return
    }

    setLoading(true)

    try {
      const response = await axios.get(
        `${API_BASE_URL}/api/blast-radius/${nodeId}`,
      )
      const data = response.data ?? null
      setBlastRadius(data)

      const nextHighlights = new Set([nodeId])
      data?.reachable?.forEach((item) => {
        if (item?.id) {
          nextHighlights.add(item.id)
        }
      })
      setHighlightNodes(nextHighlights)
    } catch (error) {
      setBlastRadius(null)
      setHighlightNodes(new Set([nodeId]))
    } finally {
      setLoading(false)
    }
  }

  const handleHypothesis = async () => {
    setLoading(true)

    try {
      const response = await axios.get(`${API_BASE_URL}/api/hypothesis`)
      setHypothesis(response.data?.hypothesis ?? '')
      setShowHypothesis(true)
    } catch (error) {
      setHypothesis('Unable to load hypothesis at this time.')
      setShowHypothesis(true)
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setSelectedNode(null)
    setBlastRadius(null)
    setAttackPath(null)
    setPathSource(null)
    setHighlightNodes(new Set())
    setAttackPathMode(false)
    setShowHypothesis(false)
    setSearchTerm('')
    setHypothesis('')
  }

  const onNodeClick = useCallback(
    async (event, node) => {
      console.log('Node clicked:', node.id, node.data?.id)
      console.log('PathSource:', pathSource?.id, pathSource?.data?.id)

      if (attackPathMode) {
        if (!pathSource) {
          setPathSource(node.data)
          setHighlightNodes(new Set([node.id]))
          return
        }

        setLoading(true)

        try {
          const sourceId = pathSource.id || pathSource.data?.id
          const targetId = node.id || node.data?.id
          console.log('Fetching attack path:', sourceId, targetId)
          const response = await axios.get(`${API_BASE_URL}/api/attack-path/${sourceId}/${targetId}`)
          console.log('Attack path response:', response.data)
          setAttackPath(response.data ?? null)
          setHighlightNodes(new Set(response.data?.path_nodes ?? []))
        } catch (error) {
          setAttackPath({
            found: false,
            source: pathSource.id,
            target: node.id,
            path_nodes: [],
          })
          setHighlightNodes(new Set([pathSource.id, node.id]))
        } finally {
          setLoading(false)
          setAttackPathMode(false)
          setPathSource(null)
        }

        return
      }

      setSelectedNode(node.data)
      setAttackPath(null)
      setPathSource(null)
      await fetchBlastRadius(node.id)
    },
    [attackPathMode, pathSource],
  )

  const selectedSeverity = Number(selectedNode?.severity_score ?? 0)
  const blastSummary = blastRadius?.summary ?? {
    total: 0,
    hosts: 0,
    ips: 0,
    hashes: 0,
    users: 0,
  }
  const blastBars = [
    { label: 'Hosts', key: 'hosts', color: '#10b981' },
    { label: 'IPs', key: 'ips', color: '#8b5cf6' },
    { label: 'Hashes', key: 'hashes', color: '#eab308' },
    { label: 'Users', key: 'users', color: '#3b82f6' },
  ]

  return (
    <div className="app">
      <div className={`loading-bar ${loading ? 'active' : ''}`} />

      <header className="header">
        <div className="header-left">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="live-dot" />
            <span className="header-title">THREATLENS</span>
          </div>
          <span className="header-subtitle">THREAT VISUALIZATION PLATFORM</span>
        </div>

        <div className="header-center">
          <div className="stat-item">
            <span className="stat-value" style={{ color: '#06b6d4' }}>
              {graphData.nodes.length}
            </span>
            <span className="stat-label">NODES</span>
          </div>
          <div className="stat-item">
            <span className="stat-value" style={{ color: '#eab308' }}>
              {graphData.links.length}
            </span>
            <span className="stat-label">LINKS</span>
          </div>
          <div className="stat-item">
            <span
              className="stat-value"
              style={{ color: '#94a3b8', fontSize: '13px' }}
            >
              {currentTime.toLocaleTimeString()}
            </span>
            <span className="stat-label">LOCAL TIME</span>
          </div>
        </div>

        <div className="header-actions">
          <button
            className={`btn ${showHypothesis ? 'btn-active' : ''}`}
            onClick={handleHypothesis}
          >
            AI Hypothesis
          </button>
          <button
            className={`btn ${attackPathMode ? 'btn-active' : ''}`}
            onClick={() => {
              setAttackPathMode((mode) => !mode)
              setPathSource(null)
              setAttackPath(null)
              setHighlightNodes(new Set())
            }}
          >
            Attack Path{' '}
            {attackPathMode
              ? pathSource
                ? '— pick target'
                : '— pick source'
              : ''}
          </button>
          <button className="btn btn-danger" onClick={handleReset}>
            Reset
          </button>
        </div>
      </header>

      <div className="main-content">
        <aside className="sidebar">
          <div className="sidebar-section">
            <div className="sidebar-title">Search</div>
            <input
              className="search-input"
              placeholder="Search nodes..."
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
            />
          </div>

          <div className="sidebar-section">
            <div className="sidebar-title">Node Types</div>
            {NODE_TYPES.map((type) => (
              <div
                className="filter-row"
                key={type}
                onClick={() =>
                  setFilters((current) => ({
                    ...current,
                    [type]: !current[type],
                  }))
                }
              >
                <label className="filter-label">
                  <input
                    type="checkbox"
                    checked={filters[type]}
                    readOnly
                  />
                  <span
                    className="filter-dot"
                    style={{ background: nodeColorFn({ type }) }}
                  />
                  {type}
                </label>
                <span className="filter-count">
                  {
                    graphData.nodes.filter((node) => node.type === type)
                      .length
                  }
                </span>
              </div>
            ))}
          </div>

          <div className="sidebar-section">
            <div className="sidebar-title">Filters</div>
            <div className="toggle-row">
              <span>Threats Only</span>
              <div
                className={`toggle ${showThreatsOnly ? 'on' : ''}`}
                onClick={() =>
                  setShowThreatsOnly((value) => !value)
                }
              >
                <div className="toggle-thumb" />
              </div>
            </div>
          </div>

          <div className="sidebar-section">
            <div className="sidebar-title">Relationship</div>
            <select
              className="select-input"
              value={relationshipFilter}
              onChange={(event) =>
                setRelationshipFilter(event.target.value)
              }
            >
              {RELATIONSHIP_TYPES.map((type) => (
                <option value={type} key={type}>
                  {type === 'ALL'
                    ? 'All Types'
                    : type === 'LATERAL_MOVEMENT'
                      ? 'Lateral Movement'
                      : type === 'CONNECTED_TO'
                        ? 'Connected To'
                        : type === 'LOGGED_INTO'
                          ? 'Logged Into'
                          : 'Ran'}
                </option>
              ))}
            </select>
          </div>
        </aside>

        <div
          className={`graph-container ${
            attackPathMode ? 'attack-path-active' : ''
          }`}
        >
          <ReactFlow
            nodeTypes={nodeTypes}
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.1}
            maxZoom={3}
            attributionPosition="bottom-right"
          >
            <Background color="#1e2d45" gap={24} size={1} />
            <Controls
              style={{
                background: '#111827',
                border: '1px solid #1e2d45',
              }}
            />
            <MiniMap
              nodeColor={(node) => node.style?.background || '#94a3b8'}
              style={{
                background: '#0d1117',
                border: '1px solid #1e2d45',
              }}
            />
          </ReactFlow>

          <div className="graph-legend">
            {[
              ['Host', '#10b981'],
              ['User', '#3b82f6'],
              ['Hash', '#eab308'],
              ['IP', '#8b5cf6'],
            ].map(([label, color]) => (
              <div className="legend-item" key={label}>
                <span
                  className="legend-dot"
                  style={{ background: color }}
                />
                {label}
              </div>
            ))}
          </div>
        </div>

        <aside className="right-panel">
          {!selectedNode && !showHypothesis && !attackPath && (
            <div className="empty-state">
              Click any node to begin investigation
            </div>
          )}

          {selectedNode && (
            <div className="panel-section">
              <div className="panel-title">Node Details</div>
              <div className="node-card">
                <div
                  className="node-card-header"
                  style={{
                    background: nodeColorFn(selectedNode),
                    color: '#0a0e1a',
                  }}
                >
                  {nodeTypIcon(selectedNode.type)} {selectedNode.name}
                </div>
                <div className="node-card-body">
                  {nodeDetails.map(([key, value]) => {
                    if (key === 'severity_score') {
                      return (
                        <div
                          className="node-row"
                          key={key}
                          style={{
                            flexDirection: 'column',
                            alignItems: 'stretch',
                            gap: '6px',
                          }}
                        >
                          <div
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'center',
                            }}
                          >
                            <span className="node-label">
                              Severity Score
                            </span>
                            <span
                              className="node-value"
                              style={{
                                color: severityColor(selectedSeverity),
                              }}
                            >
                              {formatFieldValue(value)}
                            </span>
                          </div>
                          <div className="severity-bar-container">
                            <div
                              className="severity-bar"
                              style={{
                                width: `${Math.max(
                                  0,
                                  Math.min(100, selectedSeverity),
                                )}%`,
                                background: severityColor(
                                  selectedSeverity,
                                ),
                              }}
                            />
                          </div>
                        </div>
                      )
                    }

                    if (key === 'status') {
                      return (
                        <div className="node-row" key={key}>
                          <span className="node-label">Status</span>
                          <span
                            className={`status-badge status-${String(
                              value,
                            ).toLowerCase()}`}
                          >
                            {formatFieldValue(value)}
                          </span>
                        </div>
                      )
                    }

                    return (
                      <div className="node-row" key={key}>
                        <span className="node-label">
                          {formatFieldLabel(key)}
                        </span>
                        <span className="node-value">
                          {formatFieldValue(value)}
                        </span>
                      </div>
                    )
                  })}

                  <button
                    className="btn-node-action"
                    onClick={() =>
                      fetchBlastRadius(selectedNode.id)
                    }
                  >
                    Show Blast Radius
                  </button>
                </div>
              </div>
            </div>
          )}

          {blastRadius && (
            <div className="panel-section">
              <div className="panel-title">Blast Radius</div>
              <div className="node-card" style={{ padding: '14px' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '28px',
                    fontWeight: 700,
                    color: '#06b6d4',
                    marginBottom: '12px',
                  }}
                >
                  {blastSummary.total}
                </div>
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                  }}
                >
                  {blastBars.map((bar) => {
                    const value = blastSummary[bar.key] ?? 0
                    const width =
                      blastSummary.total > 0
                        ? (value / blastSummary.total) * 100
                        : 0

                    return (
                      <div className="blast-bar-row" key={bar.key}>
                        <span className="blast-bar-label">
                          {bar.label}
                        </span>
                        <div className="blast-bar-track">
                          <div
                            className="blast-bar-fill"
                            style={{
                              width: `${width}%`,
                              background: bar.color,
                            }}
                          />
                        </div>
                        <span className="blast-count">{value}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          {attackPath && (
            <div className="panel-section">
              <div className="panel-title">Attack Path</div>
              {attackPath.found ? (
                <div className="node-card" style={{ padding: '14px' }}>
                  <div className="path-chain">
                    {attackPath.path_nodes.map(
                      (nodeId, index) => {
                        const pathNode = graphData.nodes.find(
                          (entry) => entry.id === nodeId,
                        )

                        return (
                          <span
                            key={nodeId}
                            style={{ display: 'contents' }}
                          >
                            <span
                              className="path-node"
                              style={{
                                borderColor: pathNode
                                  ? nodeColorFn(pathNode)
                                  : '#1e2d45',
                                color: pathNode
                                  ? nodeColorFn(pathNode)
                                  : '#e2e8f0',
                              }}
                            >
                              {nodeId}
                            </span>
                            {index <
                              attackPath.path_nodes.length -
                                1 && (
                              <span className="path-arrow">
                                →
                              </span>
                            )}
                          </span>
                        )
                      },
                    )}
                  </div>
                  <div className="node-row" style={{ marginTop: '8px' }}>
                    <span className="node-label">Hops</span>
                    <span
                      className="node-value"
                      style={{ color: '#eab308' }}
                    >
                      {attackPath.hops}
                    </span>
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  No path found between nodes
                </div>
              )}
            </div>
          )}

          {showHypothesis && hypothesis && (
            <div className="panel-section">
              <div className="panel-title">AI Hypothesis</div>
              <div className="hypothesis-box">{hypothesis}</div>
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}

export default App

