import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, Database, Search, Filter, RefreshCw } from 'lucide-react'

const API_BASE = '/api'

function KnowledgeGraph() {
    const [nodes, setNodes] = useState([])
    const [_edges, setEdges] = useState([])
    const [selectedNode, setSelectedNode] = useState(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [offline, setOffline] = useState(false)
    const [filter, setFilter] = useState({ type: 'all', search: '' })

    useEffect(() => {
        fetchGraph()
    }, [])

    async function fetchGraph() {
        setLoading(true)
        setError(null)
        setOffline(false)
        try {
            const resp = await fetch(`${API_BASE}/knowledge/graph`)
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
            const data = await resp.json()
            setNodes(data.nodes || [])
            setEdges(data.edges || [])
        } catch (err) {
            const message = err.message || 'Failed to load knowledge graph'
            const backendOffline = message.includes('Failed to fetch') ||
                message.includes('NetworkError') ||
                message.includes('HTTP 500') ||
                message.includes('HTTP 502')
            setNodes([])
            setEdges([])
            setOffline(backendOffline)
            setError(backendOffline ? null : message)
        }
        setLoading(false)
    }

    const nodeTypes = ['all', ...new Set(nodes.map(n => n.type))]
    const filteredNodes = nodes.filter(n => {
        if (filter.type !== 'all' && n.type !== filter.type) return false
        if (filter.search && !n.label?.toLowerCase().includes(filter.search.toLowerCase())) return false
        return true
    })

    // Hardcoded class maps — dynamic `bg-${var}` strings are stripped by Tailwind's purger
    const typeTextClass = {
        Host: 'text-accent-cyan',
        Service: 'text-accent-purple',
        Vulnerability: 'text-accent-red',
        Technique: 'text-accent-orange',
        Payload: 'text-accent-yellow',
        TechStack: 'text-accent-green',
    }
    const typeDotClass = {
        Host: 'bg-accent-cyan',
        Service: 'bg-accent-purple',
        Vulnerability: 'bg-accent-red',
        Technique: 'bg-accent-orange',
        Payload: 'bg-accent-yellow',
        TechStack: 'bg-accent-green',
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="lg-surface relative z-10 p-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-4">
                    <Link to="/" className="p-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 transition-colors">
                        <ArrowLeft className="w-4 h-4 text-text-muted" />
                    </Link>
                    <div>
                        <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
                            <Database className="w-6 h-6 text-accent-purple" />
                            Knowledge Graph
                        </h1>
                        <p className="text-xs text-text-muted mt-1">Cross-session attack intelligence and relationships</p>
                    </div>
                </div>
                <button onClick={fetchGraph} className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-xs text-text-muted transition-colors">
                    <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
                    Refresh
                </button>
            </div>

            {/* Filters */}
            <div className="relative z-10 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex items-center gap-2 bg-white/5 border border-white/10 rounded-xl px-3 py-1.5">
                    <Search className="w-3 h-3 text-text-muted" />
                    <input
                        type="text"
                        placeholder="Search nodes..."
                        value={filter.search}
                        onChange={e => setFilter(f => ({ ...f, search: e.target.value }))}
                        className="bg-transparent text-xs text-text-primary placeholder:text-text-muted/50 outline-none w-full sm:w-56"
                    />
                </div>
                <div className="flex items-center gap-1 overflow-x-auto pb-1">
                    <Filter className="w-3 h-3 text-text-muted mr-1" />
                    {nodeTypes.map(t => (
                        <button
                            key={t}
                            onClick={() => setFilter(f => ({ ...f, type: t }))}
                            className={`px-2 py-0.5 rounded-full text-[10px] font-mono uppercase transition-colors border ${
                                filter.type === t
                                    ? 'bg-accent-cyan/20 border-accent-cyan/40 text-accent-cyan'
                                    : 'bg-white/5 border-white/10 text-text-muted hover:text-text-primary'
                            }`}
                        >
                            {t}
                        </button>
                    ))}
                </div>
            </div>

            {/* Stats */}
            <div className="relative z-10 grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
                {Object.entries(typeTextClass).map(([type, textCls]) => {
                    const count = nodes.filter(n => n.type === type).length
                    return (
                        <div key={type} className="card-surface p-3">
                            <div className={`text-[10px] font-mono uppercase tracking-wider ${textCls}`}>{type}</div>
                            <div className="text-xl font-bold text-text-primary mt-1">{count}</div>
                        </div>
                    )
                })}
            </div>

            {/* Node List */}
            <div className="relative z-10 grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2 space-y-2 max-h-[600px] overflow-y-auto pr-2">
                    {loading ? (
                        <div className="card-surface text-center py-12 text-text-muted text-sm">Loading knowledge graph...</div>
                    ) : error ? (
                        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400 font-mono">
                            {error}
                        </div>
                    ) : offline ? (
                        <div className="card-surface text-center px-6 py-12">
                            <Database className="mx-auto h-10 w-10 text-accent-purple/80" />
                            <h2 className="mt-4 text-lg font-semibold text-text-primary">Knowledge backend offline</h2>
                            <p className="mx-auto mt-2 max-w-md text-sm text-text-muted">
                                Start the Mirage API server to load graph nodes and relationships. The graph view is ready and will populate as soon as `/api/knowledge/graph` responds.
                            </p>
                        </div>
                    ) : filteredNodes.length === 0 ? (
                        <div className="card-surface text-center py-12 text-text-muted text-sm">
                            No nodes found. Run scans to build the knowledge graph.
                        </div>
                    ) : (
                        filteredNodes.map(node => (
                            <button
                                key={node.id}
                                onClick={() => setSelectedNode(node)}
                                className={`w-full text-left rounded-xl border px-3 py-2 text-xs transition-all ${
                                    selectedNode?.id === node.id
                                        ? 'bg-white/10 border-white/25 shadow-lg'
                                        : 'bg-white/[0.04] border-white/10 hover:bg-white/[0.08]'
                                }`}
                            >
                                <div className="flex items-center gap-2">
                                    <span className={`inline-block w-2 h-2 rounded-full ${typeDotClass[node.type] || 'bg-white/30'}`} />
                                    <span className="font-mono text-[10px] text-text-muted uppercase">{node.type}</span>
                                    <span className="text-text-primary truncate">{node.label}</span>
                                </div>
                            </button>
                        ))
                    )}
                </div>

                {/* Detail Panel */}
                <div className="card-surface p-4">
                    {selectedNode ? (
                        <div className="space-y-3">
                            <h3 className="text-sm font-bold text-text-primary">{selectedNode.label}</h3>
                            <div className="text-[10px] font-mono text-text-muted uppercase">{selectedNode.type}</div>
                            <div className="space-y-1">
                                {Object.entries(selectedNode.properties || {}).map(([key, val]) => (
                                    <div key={key} className="flex justify-between text-[11px]">
                                        <span className="text-text-muted">{key}</span>
                                        <span className="text-text-primary truncate ml-2">{String(val)}</span>
                                    </div>
                                ))}
                            </div>
                            {selectedNode.flow_id && (
                                <Link to={`/flow/${selectedNode.flow_id}`} className="block text-[10px] text-accent-cyan hover:underline mt-2">
                                    View source flow
                                </Link>
                            )}
                        </div>
                    ) : (
                        <div className="text-center text-text-muted text-xs py-8">Select a node to view details</div>
                    )}
                </div>
            </div>
        </div>
    )
}

export default KnowledgeGraph
