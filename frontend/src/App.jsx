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
const EXCLUDED_KEYS = ['size', 'color', 'label', 'isSelected', 'isConnected', 'isSimulated', 'hasSelection', 'simulationColor', 'simulationDepth', 'shortLabel', 'x', 'y', 'vx', 'vy', 'fx', 'fy', 'index']

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

function getNodeSize(node) {
  const severity = Number(node?.severity_score ?? 0)
  return 28 + (severity / 100) * 16
}

function getConnectedNodeIds(nodeId, edges) {
  const connected = new Set([nodeId])
  edges.forEach((edge) => {
    if (edge.source === nodeId) connected.add(edge.target)
    if (edge.target === nodeId) connected.add(edge.source)
  })
  return connected
}

function buildLayout(apiNodes, apiLinks) {
  if (!apiNodes.length) return { nodes: [], edges: [] }

  const timestamps = apiNodes.map((n) => (n.timestamp ? new Date(n.timestamp).getTime() : 0))
  const minT = Math.min(...timestamps)
  const maxT = Math.max(...timestamps)
  const range = maxT - minT || 1

  const GRAPH_WIDTH = Math.max(window.innerWidth - 600, 800)
  const TYPE_Y = { IP: 0, Hash: 250, Host: 500, User: 750 }
  const xCounters = {}

  const nodes = apiNodes.map((n) => {
    const t = n.timestamp ? new Date(n.timestamp).getTime() : minT
    const baseX = ((t - minT) / range) * GRAPH_WIDTH
    const typeKey = `${n.type}_${Math.round(baseX / 60)}`
    xCounters[typeKey] = (xCounters[typeKey] || 0) + 1
    const xOffset = (xCounters[typeKey] - 1) * 140
    const x = baseX + xOffset + 50
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
      data: {
        ...n,
        size,
        color,
        label: n.name || n.id,
        isSelected: false,
        isConnected: false,
        isSimulated: false,
        simulationDepth: null,
        simulationColor: null,
      },
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

function getSimulationColor(depth) {
  switch(depth) {
    case 0: return '#ef4444'  // source — red
    case 1: return '#ef4444'  // depth 1 — red
    case 2: return '#f97316'  // depth 2 — orange
    case 3: return '#eab308'  // depth 3 — yellow
    default: return '#854d0e' // depth 4+ — dark yellow
  }
}

function ThreatNode({ data }) {
  const size = data.size || 36
  const activeColor = data.simulationColor || data.color
  const isSimulated = data.isSimulated
  const simulationDepth = data.simulationDepth
  const isSelected = Boolean(data.isSelected)
  const isConnected = Boolean(data.isConnected)
  const [hovered, setHovered] = useState(false)
  const [visible, setVisible] = useState(false)
  const scale = hovered ? 1.1 : isSelected ? 1.15 : isConnected ? 1.05 : 1
  const hasSelection = data.hasSelection === true
  const simulationGlow =
    simulationDepth === 0
      ? '0 0 20px rgba(239,68,68,0.9), 0 0 40px rgba(239,68,68,0.6)'
      : simulationDepth === 1
        ? '0 0 18px rgba(249,115,22,0.8), 0 0 35px rgba(249,115,22,0.5)'
        : '0 0 15px rgba(234,179,8,0.7), 0 0 25px rgba(234,179,8,0.4)'

  useEffect(() => {
    const timeoutId = setTimeout(() => setVisible(true), 50)
    return () => clearTimeout(timeoutId)
  }, [])

  return (
    <div
      className="threat-node"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        textAlign: 'center',
        cursor: 'pointer',
        transition: 'opacity 0.4s ease, transform 0.3s ease',
        transform: `scale(${scale})`,
        opacity: visible ? (isSelected ? 1 : isConnected ? 0.85 : hasSelection ? 0.1 : 0.9) : 0,
        zIndex: isSelected ? 10 : 'auto'
      }}
    >
      <Handle type="target" position={Position.Left} style={{background: 'transparent', border: 'none'}} />
      <div style={{
        width: size,
        height: size,
        borderRadius: '50%',
        background: activeColor || '#94a3b8',
        border: isSelected
          ? '2px solid #06b6d4'
          : data.status === 'malicious'
            ? '2px solid #ef4444'
            : data.status === 'suspicious'
              ? '2px solid #f97316'
              : '1px solid rgba(255,255,255,0.15)',
        boxShadow: isSelected
          ? '0 0 20px rgba(6,182,212,0.9)'
          : isSimulated
            ? simulationGlow
            : !hasSelection && data.status === 'malicious'
              ? '0 0 10px rgba(239,68,68,0.6)'
              : !hasSelection && data.status === 'suspicious'
                ? '0 0 8px rgba(249,115,22,0.5)'
                : data.status === 'malicious'
                  ? '0 0 12px rgba(239,68,68,0.6)'
                  : isConnected
                    ? '0 0 10px rgba(255,255,255,0.15)'
                    : 'none',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '7px',
        fontWeight: '700',
        color: '#000',
        margin: '0 auto',
        transition: 'all 0.25s ease',
        animation: isSimulated ? 'pulseGlow 1.2s ease-in-out infinite' : 'none',
        animationDelay: isSimulated && simulationDepth !== null ? `${simulationDepth * 0.2}s` : '0s'
      }} />
      <div style={{
        marginTop: 6,
        fontSize: 11,
        fontWeight: 500,
        fontFamily: "'JetBrains Mono', monospace",
        color: '#e2e8f0',
        whiteSpace: 'nowrap',
        maxWidth: 90,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        background: 'rgba(0,0,0,0.6)',
        padding: '2px 6px',
        borderRadius: '4px',
        display: 'inline-block'
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
  const [isBlastLoading, setIsBlastLoading] = useState(false)
  const [isSimulating, setIsSimulating] = useState(false)
  const [highlightNodes, setHighlightNodes] = useState(new Set())
  const [currentTime, setCurrentTime] = useState(() => new Date())
  const [simulationActive, setSimulationActive] = useState(false)
  const [simulationNodes, setSimulationNodes] = useState(new Map()) // nodeId → depth
  const [activeTab, setActiveTab] = useState('graph') // 'graph' or 'replay'
  const [replayNodes, setReplayNodes] = useState([]) // nodes revealed so far
  const [replayIndex, setReplayIndex] = useState(0) // current position
  const [replayPlaying, setReplayPlaying] = useState(false) // is playing
  const [replaySpeed, setReplaySpeed] = useState(1000) // ms between nodes

  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const nodeTypes = useMemo(() => ({ threatNode: ThreatNode }), [])

  const displayNodes = useMemo(
    () =>
      nodes.map((node) => {
        const isSelected = selectedNode?.id === node.id
        const isConnected = highlightNodes.has(node.id)
        const simulationDepth = simulationNodes.get(node.id) ?? null

        return {
          ...node,
          position: node.position,
          data: {
            ...node.data,
            isSelected,
            isConnected,
            simulationDepth,
            isSimulated: simulationDepth !== null,
            simulationColor:
              simulationDepth !== null ? getSimulationColor(simulationDepth) : null,
            hasSelection: Boolean(selectedNode),
          },
        }
      }),
    [highlightNodes, nodes, selectedNode?.id, simulationNodes, selectedNode],
  )

  const sortedByTime = useMemo(() => {
    return [...graphData.nodes]
      .filter(n => n.timestamp)
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
  }, [graphData.nodes])

  const timelineSummary = useMemo(() => {
    const total = graphData.nodes.length
    const malicious = graphData.nodes.filter(n => n.status === 'malicious').length
    const suspicious = graphData.nodes.filter(n => n.status === 'suspicious').length
    const clean = graphData.nodes.filter(n => n.status === 'clean').length
    return { total, malicious, suspicious, clean }
  }, [graphData.nodes])

  const timelineEvents = useMemo(() => {
    console.log('Timeline events computed:', graphData.nodes.length, 'nodes')
    return [...graphData.nodes]
      .sort((a, b) => {
        if (!a.timestamp) return -1
        if (!b.timestamp) return 1
        return new Date(a.timestamp) - new Date(b.timestamp)
      })
      .map(n => ({
        ...n,
        formattedTime: n.timestamp
          ? new Date(n.timestamp).toLocaleString('en-GB', {
              day: '2-digit', month: 'short', year: 'numeric',
              hour: '2-digit', minute: '2-digit'
            })
          : 'No timestamp',
        description: n.status === 'malicious'
          ? `⚠️ ${n.description || n.role || n.filename || 'Malicious activity detected'}`
          : n.status === 'suspicious'
          ? `⚡ ${n.description || n.role || n.filename || 'Suspicious activity flagged'}`
          : `✓ ${n.description || n.role || n.filename || 'Benign / expected activity'}`
      }))
  }, [graphData.nodes])

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

  useEffect(() => {
    if (!replayPlaying) return
    if (replayIndex >= sortedByTime.length) {
      setReplayPlaying(false)
      return
    }
    const timer = setTimeout(() => {
      setReplayNodes(sortedByTime.slice(0, replayIndex + 1))
      setReplayIndex(prev => prev + 1)
    }, replaySpeed)
    return () => clearTimeout(timer)
  }, [replayPlaying, replayIndex, sortedByTime, replaySpeed])

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

  const renderedEdges = useMemo(
    () =>
      (() => {
        const attackPathEdgeSet = new Set()

        if (attackPath?.path_nodes?.length > 1) {
          for (let index = 0; index < attackPath.path_nodes.length - 1; index += 1) {
            attackPathEdgeSet.add(
              `${attackPath.path_nodes[index]}->${attackPath.path_nodes[index + 1]}`,
            )
          }
        }

        return edges.map((edge) => {
        const sourceHighlighted = highlightNodes.has(edge.source)
        const targetHighlighted = highlightNodes.has(edge.target)
        const isHighlighted = sourceHighlighted && targetHighlighted
        const isAttackPathEdge = attackPathEdgeSet.has(`${edge.source}->${edge.target}`)
        const isSimulationEdge =
          simulationNodes.has(edge.source) && simulationNodes.has(edge.target)
        const isFlowEdge = isAttackPathEdge || isSimulationEdge

        return {
          ...edge,
          style: {
            ...edge.style,
            opacity: highlightNodes.size === 0 ? 1 : isHighlighted ? 1 : 0.08,
            strokeWidth:
              highlightNodes.size === 0
                ? edge.style?.strokeWidth ?? 1
                : isHighlighted
                  ? 2.5
                  : 1,
            strokeDasharray: isFlowEdge ? '6 6' : edge.style?.strokeDasharray,
            animation: isFlowEdge ? 'flow 1s linear infinite' : edge.style?.animation,
          },
        }
        })
      })(),
    [attackPath, edges, highlightNodes, simulationNodes],
  )

  const nodeDetails = useMemo(() => {
    if (!selectedNode) {
      return []
    }

    return Object.entries(selectedNode).filter(
      ([key, value]) =>
        !EXCLUDED_KEYS.includes(key) && value !== null && value !== undefined && value !== '',
    )
  }, [selectedNode])

  const fetchBlastRadius = async (nodeId) => {
    if (!nodeId) {
      return
    }

    setIsBlastLoading(true)
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
      setIsBlastLoading(false)
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
    setSimulationActive(false)
    setSimulationNodes(new Map())

    const { nodes: layoutNodes, edges: layoutEdges } = buildLayout(
      graphData.nodes,
      graphData.links,
    )

    setNodes(layoutNodes)
    setEdges(layoutEdges)
  }

  const handleReplayPlay = () => {
    if (replayIndex >= sortedByTime.length) {
      setReplayIndex(0)
      setReplayNodes([])
    }
    setReplayPlaying(true)
  }
  const handleReplayPause = () => setReplayPlaying(false)
  const handleReplayReset = () => {
    setReplayPlaying(false)
    setReplayIndex(0)
    setReplayNodes([])
  }
  const handleScrubber = (e) => {
    const idx = Number(e.target.value)
    setReplayPlaying(false)
    setReplayIndex(idx)
    setReplayNodes(sortedByTime.slice(0, idx))
  }

  const onNodeClick = useCallback(
    async (event, node) => {
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
          const response = await axios.get(`${API_BASE_URL}/api/attack-path/${sourceId}/${targetId}`)
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
      setHighlightNodes(getConnectedNodeIds(node.id, edges))
      setAttackPath(null)
      setPathSource(null)
      setBlastRadius(null)
    },
    [attackPathMode, edges, pathSource],
  )

  const handleSimulateCompromise = async () => {
    if (!selectedNode) return
    setIsSimulating(true)
    setSimulationActive(true)
    setSimulationNodes(new Map())

    try {
      const response = await axios.get(`${API_BASE_URL}/api/blast-radius/${selectedNode.id}`)
      const reachable = response.data?.reachable || []

      // Group nodes by depth
      const byDepth = {}
      reachable.forEach(item => {
        if (!byDepth[item.depth]) byDepth[item.depth] = []
        byDepth[item.depth].push(item.id)
      })

      // Start with source node
      setSimulationNodes(new Map([[selectedNode.id, 0]]))

      // Spread by depth with delays
      const maxDepth = Math.max(...Object.keys(byDepth).map(Number))
      for (let depth = 1; depth <= maxDepth; depth++) {
        await new Promise(resolve => setTimeout(resolve, 800))
        setSimulationNodes(prev => {
          const next = new Map(prev)
          byDepth[depth]?.forEach(id => next.set(id, depth))
          return next
        })
      }
    } catch (error) {
      setSimulationActive(false)
    } finally {
      setIsSimulating(false)
    }
  }

  const handleResetSimulation = () => {
    setSimulationActive(false)
    setSimulationNodes(new Map())
  }

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
            <span className="header-title">ThreatLens</span>
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

      <div className="tab-bar">
        <button
          className={`tab-btn ${activeTab === 'graph' ? 'tab-active' : ''}`}
          onClick={() => setActiveTab('graph')}>
          🕸️ Threat Graph
        </button>
        <button
          className={`tab-btn ${activeTab === 'replay' ? 'tab-active' : ''}`}
          onClick={() => setActiveTab('replay')}>
          ▶ Attack Replay
        </button>
        <button
          className={`tab-btn ${activeTab === 'timeline' ? 'tab-active' : ''}`}
          onClick={() => setActiveTab('timeline')}>
          📋 Timeline View
        </button>
      </div>

      <div className="main-content" style={{display: activeTab === 'graph' ? 'flex' : 'none'}}>
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
            nodes={displayNodes}
            edges={renderedEdges}
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
              nodeColor={(node) => node.data?.simulationColor || node.data?.color || '#94a3b8'}
              style={{
                background: 'rgba(15,23,42,0.8)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 8,
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
              <div>👋 Welcome to ThreatLens</div>
              <div style={{marginTop:'6px'}}>
                • Click a red node (malicious)<br/>
                • Run Blast Radius<br/>
                • Try Simulate Compromise
              </div>
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
                  {nodeTypeIcon(selectedNode.type)} {selectedNode.name}
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
                    className={`btn-node-action ${isBlastLoading ? 'btn-loading' : ''}`}
                    onClick={() => fetchBlastRadius(selectedNode.id)}
                    disabled={isBlastLoading}
                  >
                    {isBlastLoading ? 'Running...' : 'Show Blast Radius'}
                  </button>

                  {!simulationActive ? (
                    <button className={`btn-node-action ${isSimulating ? 'btn-loading' : ''}`} onClick={handleSimulateCompromise}
                      disabled={isSimulating}
                      style={{borderColor:'#f97316', color:'#f97316'}}>
                      {isSimulating ? 'Simulating...' : '⚡ Simulate Compromise'}
                    </button>
                  ) : (
                    <button className="btn-node-action" onClick={handleResetSimulation}
                      style={{borderColor:'#ef4444', color:'#ef4444'}}>
                      ↺ Reset Simulation
                    </button>
                  )}
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

      {activeTab === 'timeline' && (
        <div style={{flex:1, display:'flex', flexDirection:'column', overflow:'hidden', background:'var(--bg-primary)'}}>
          <div style={{display:'flex', borderBottom:'1px solid var(--border)', flexShrink:0}}>
            {[
              {label:'TOTAL EVENTS', value: timelineSummary.total, color:'var(--accent-cyan)'},
              {label:'MALICIOUS', value: timelineSummary.malicious, color:'#ef4444'},
              {label:'SUSPICIOUS', value: timelineSummary.suspicious, color:'#f97316'},
              {label:'CLEAN', value: timelineSummary.clean, color:'#10b981'},
            ].map(item => (
              <div key={item.label} style={{flex:1, padding:'20px 24px', borderRight:'1px solid var(--border)'}}>
                <div style={{fontSize:'10px', color:'var(--text-muted)', letterSpacing:'2px', marginBottom:'6px'}}>{item.label}</div>
                <div style={{fontSize:'28px', fontWeight:'700', color:item.color, fontFamily:'Courier New'}}>{item.value}</div>
              </div>
            ))}
          </div>

          <div style={{display:'flex', alignItems:'center', padding:'10px 20px', background:'var(--bg-secondary)', borderBottom:'1px solid var(--border)', fontSize:'10px', color:'var(--text-muted)', letterSpacing:'1.5px', flexShrink:0, gap:'12px'}}>
            <span style={{width:'8px'}}></span>
            <span style={{flex:2}}>TIMESTAMP</span>
            <span style={{flex:2}}>NODE</span>
            <span style={{flex:1}}>TYPE</span>
            <span style={{flex:3}}>DESCRIPTION</span>
            <span style={{flex:1}}>STATUS</span>
          </div>

          <div style={{flex:1, overflowY:'auto'}}>
            {timelineEvents.map((event, i) => (
              <div key={event.id || i} style={{
                display:'flex', alignItems:'center', gap:'12px',
                padding:'12px 20px',
                borderBottom:'1px solid var(--border)',
                borderLeft: event.status === 'malicious' ? '3px solid #ef4444' :
                            event.status === 'suspicious' ? '3px solid #f97316' : '3px solid transparent',
                fontSize:'12px',
                cursor:'default',
                transition:'background 0.15s',
              }}
              onMouseEnter={e => e.currentTarget.style.background='var(--bg-card)'}
              onMouseLeave={e => e.currentTarget.style.background='transparent'}
              >
                <div style={{
                  width:'8px', height:'8px', borderRadius:'50%', flexShrink:0,
                  background: event.status === 'malicious' ? '#ef4444' :
                              event.status === 'suspicious' ? '#f97316' :
                              event.type === 'Host' ? '#10b981' :
                              event.type === 'User' ? '#3b82f6' :
                              event.type === 'Hash' ? '#eab308' :
                              event.type === 'IP' ? '#8b5cf6' : '#94a3b8'
                }} />
                <span style={{flex:2, color:'var(--text-muted)', fontFamily:'Courier New', fontSize:'11px'}}>{event.formattedTime}</span>
                <span style={{
                  flex:2, fontFamily:'Courier New',
                  color: event.status === 'malicious' ? '#ef4444' :
                         event.status === 'suspicious' ? '#f97316' : '#e2e8f0',
                  fontWeight: event.status === 'malicious' ? '700' : '400'
                }}>{event.name}</span>
                <span style={{flex:1}}>
                  <span style={{
                    padding:'2px 8px', borderRadius:'3px', fontSize:'9px',
                    fontWeight:'700', textTransform:'uppercase', letterSpacing:'1px',
                    background: event.type === 'Host' ? 'rgba(16,185,129,0.15)' :
                                event.type === 'User' ? 'rgba(59,130,246,0.15)' :
                                event.type === 'Hash' ? 'rgba(234,179,8,0.15)' : 'rgba(139,92,246,0.15)',
                    color: event.type === 'Host' ? '#10b981' :
                           event.type === 'User' ? '#3b82f6' :
                           event.type === 'Hash' ? '#eab308' : '#8b5cf6',
                  }}>{event.type}</span>
                </span>
                <span style={{flex:3, fontSize:'11px', color:'var(--text-secondary)'}}>{event.description}</span>
                <span style={{flex:1}}>
                  <span className={`status-badge status-${event.status}`}>{event.status}</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'replay' && (
        <div className="replay-container">
          <div className="replay-header">
            <div className="replay-controls">
              <button className="btn btn-primary" onClick={handleReplayPlay} disabled={replayPlaying}>
                ▶ Play
              </button>
              <button className="btn" onClick={handleReplayPause} disabled={!replayPlaying}>
                ⏸ Pause
              </button>
              <button className="btn btn-danger" onClick={handleReplayReset}>
                ↺ Reset
              </button>
              <select className="select-input" style={{width:'140px'}}
                value={replaySpeed} onChange={e => setReplaySpeed(Number(e.target.value))}>
                <option value={2000}>0.5x Speed</option>
                <option value={1000}>1x Speed</option>
                <option value={500}>2x Speed</option>
                <option value={250}>4x Speed</option>
              </select>
            </div>
            <div className="replay-progress">
              <span className="replay-stat">
                {replayNodes.length} / {sortedByTime.length} nodes revealed
              </span>
              <input
                type="range"
                min={0}
                max={sortedByTime.length}
                value={replayIndex}
                onChange={handleScrubber}
                className="replay-scrubber"
              />
            </div>
          </div>

          <div className="replay-timeline">
            {replayNodes.map((node, i) => (
              <div key={node.id} className="replay-event" style={{
                animationDelay: `${i * 0.05}s`
              }}>
                <div className="replay-dot" style={{
                  background: node.status === 'malicious' ? '#ef4444' :
                              node.status === 'suspicious' ? '#f97316' :
                              node.type === 'Host' ? '#10b981' :
                              node.type === 'User' ? '#3b82f6' :
                              node.type === 'Hash' ? '#eab308' :
                              node.type === 'IP' ? '#8b5cf6' : '#94a3b8'
                }} />
                <div className="replay-event-content">
                  <span className="replay-time">{node.timestamp?.replace('T', ' ').replace('Z', '')}</span>
                  <span className="replay-name" style={{
                    color: node.status === 'malicious' ? '#ef4444' :
                           node.status === 'suspicious' ? '#f97316' : '#e2e8f0'
                  }}>{node.name}</span>
                  <span className="replay-type" style={{color:'#4a5568'}}>[{node.type}]</span>
                  <span className={`status-badge status-${node.status}`}>{node.status}</span>
                </div>
              </div>
            ))}
            {replayNodes.length === 0 && (
              <div className="empty-state">Press Play to begin attack replay</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default App

