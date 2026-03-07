import React, { useState, useEffect, useRef, useMemo } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { ArrowLeft, Target, Clock, Activity, Cpu, Wrench, MessageSquare, CheckCircle, XCircle, ChevronRight, Terminal, Trash2, AlertTriangle, Shield, Zap, Bug, Eye, FileText, Search, Crosshair, Wifi } from 'lucide-react'
import { FlowLedgerPanel, FlowEvidencePanel } from '../components/FlowLedgerPanel'

const API_BASE = '/api'

const CHIP_BASE = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

function FindingList({ findings, formatTime }) {
    const [expandedIndex, setExpandedIndex] = useState(null)

    return (
        <div className="space-y-1">
            {findings.map((event, idx) => {
                const content = event.content || ''
                const severityMatch = content.match(/\*\*Severity\*\*:\s*(\w+)/i)
                const severity = (severityMatch ? severityMatch[1] : 'info').toLowerCase()
                const titleLine = content.split('\n').find((line) => line.trim().startsWith('## ')) || ''
                const title = titleLine.replace(/^##\s*/, '') || 'Finding'

                const badgeClasses =
                    severity === 'critical'
                        ? 'bg-accent-red/15 text-accent-red border-accent-red/40'
                        : severity === 'high'
                            ? 'bg-accent-orange/15 text-accent-orange border-accent-orange/40'
                            : severity === 'medium'
                                ? 'bg-accent-yellow/15 text-accent-yellow border-accent-yellow/40'
                                : severity === 'low'
                                    ? 'bg-accent-green/15 text-accent-green border-accent-green/40'
                                    : 'bg-accent-cyan/15 text-accent-cyan border-accent-cyan/40'

                const isExpanded = expandedIndex === idx

                return (
                    <button
                        key={idx}
                        type="button"
                        onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                        className={`w-full text-left rounded-xl border px-3 py-2 text-xs text-text-primary flex flex-col transition-all ${isExpanded
                            ? 'bg-white/10 border-white/20 shadow-[0_12px_40px_rgba(15,23,42,0.9)] scale-[1.01]'
                            : 'bg-white/4 hover:bg-white/8 border-white/10'
                            }`}
                    >
                        <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2 min-w-0">
                                <span
                                    className={`${CHIP_BASE} text-[9px] ${badgeClasses}`}
                                >
                                    {severity}
                                </span>
                                <span className="text-[11px] truncate font-medium">{title}</span>
                            </div>
                            <span className="text-[10px] font-mono text-text-muted/70 flex-shrink-0">
                                {formatTime(event.timestamp)}
                            </span>
                        </div>
                        {isExpanded && (
                            <div className="mt-2 pt-2 border-t border-border/40 text-[11px] text-text-muted">
                                <div className="whitespace-pre-wrap mb-3">
                                    {content.replace(/\*\*Severity\*\*:[^\n]+/i, '').trim()}
                                </div>
                                {event.metadata?.screenshot && (
                                    <div className="mt-4 rounded-lg overflow-hidden border border-white/10 shadow-lg">
                                        <div className="bg-white/5 px-2 py-1 text-[9px] uppercase tracking-wider font-bold border-b border-white/10 flex items-center justify-between">
                                            <span>Visual Confirmation (Browser Screenshot)</span>
                                            <span className="text-accent-green">PHOENIX EDITION</span>
                                        </div>
                                        <img
                                            src={`/screenshots/${event.metadata.screenshot}`}
                                            alt="Finding Screenshot"
                                            className="w-full h-auto cursor-zoom-in hover:scale-[1.02] transition-transform"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                window.open(`/screenshots/${event.metadata.screenshot}`, '_blank');
                                            }}
                                        />
                                    </div>
                                )}
                            </div>
                        )}
                    </button>
                )
            })}
        </div>
    )
}

// ============================================================================
// PIPELINE TRACKER — Animated phase stepper
// ============================================================================

const PIPELINE_PHASES = [
    { key: 'reconnaissance', label: 'Recon', icon: Search, color: 'accent-cyan' },
    { key: 'discovery', label: 'Discovery', icon: Eye, color: 'accent-purple' },
    { key: 'strategy', label: 'Strategy', icon: Crosshair, color: 'accent-yellow' },
    { key: 'exploitation', label: 'Exploit', icon: Zap, color: 'accent-orange' },
    { key: 'validation', label: 'Validate', icon: Shield, color: 'accent-green' },
    { key: 'reporting', label: 'Report', icon: FileText, color: 'accent-pink' },
    { key: 'complete', label: 'Complete', icon: CheckCircle, color: 'accent-green' },
]

function PipelineTracker({ currentPhase }) {
    const currentIndex = PIPELINE_PHASES.findIndex(p => p.key === currentPhase)

    return (
        <div className="relative mb-8">
            {/* Glass container */}
            <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-2xl p-5 shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                {/* Ambient glow behind active phase */}
                {currentIndex >= 0 && (
                    <motion.div
                        className="absolute top-0 h-full w-32 rounded-full blur-[60px] opacity-30"
                        animate={{
                            left: `${(currentIndex / (PIPELINE_PHASES.length - 1)) * 100}%`,
                            background: [
                                'radial-gradient(circle, rgba(0,212,255,0.4), transparent)',
                                'radial-gradient(circle, rgba(168,85,247,0.4), transparent)',
                                'radial-gradient(circle, rgba(0,212,255,0.4), transparent)'
                            ],
                        }}
                        style={{ transform: 'translateX(-50%)' }}
                        transition={{ left: { duration: 0.8, ease: 'easeOut' }, background: { duration: 3, repeat: Infinity } }}
                    />
                )}

                {/* Header */}
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                        <div className="p-1.5 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20">
                            <Activity className="w-3.5 h-3.5 text-accent-cyan" />
                        </div>
                        <span className="text-[10px] font-mono font-bold uppercase tracking-[0.2em] text-text-muted">Pipeline Phase</span>
                    </div>
                    {currentIndex >= 0 && (
                        <motion.span
                            key={currentPhase}
                            initial={{ opacity: 0, y: -8 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="text-[10px] font-mono font-bold uppercase tracking-[0.16em] text-accent-cyan bg-accent-cyan/10 border border-accent-cyan/20 rounded-full px-2.5 py-0.5"
                        >
                            {PIPELINE_PHASES[currentIndex]?.label || currentPhase}
                        </motion.span>
                    )}
                </div>

                {/* Phase Steps */}
                <div className="relative flex items-center justify-between">
                    {/* Background connector line */}
                    <div className="absolute top-4 left-4 right-4 h-[2px] bg-white/8 rounded-full" />

                    {/* Animated progress line */}
                    <motion.div
                        className="absolute top-4 left-4 h-[2px] rounded-full bg-gradient-to-r from-accent-cyan via-accent-purple to-accent-green"
                        initial={{ width: '0%' }}
                        animate={{
                            width: currentIndex >= 0
                                ? `${Math.min((currentIndex / (PIPELINE_PHASES.length - 1)) * 100, 100)}%`
                                : '0%'
                        }}
                        transition={{ duration: 1, ease: 'easeOut' }}
                        style={{ boxShadow: '0 0 12px rgba(0,212,255,0.5), 0 0 30px rgba(0,212,255,0.2)' }}
                    />

                    {PIPELINE_PHASES.map((phase, idx) => {
                        const isComplete = idx < currentIndex
                        const isCurrent = idx === currentIndex
                        const isFuture = idx > currentIndex || currentIndex < 0
                        const Icon = phase.icon

                        return (
                            <div key={phase.key} className="relative flex flex-col items-center z-10 flex-1">
                                {/* Phase dot / icon */}
                                <motion.div
                                    className={`relative w-8 h-8 rounded-full flex items-center justify-center border-2 transition-all duration-500 ${isComplete
                                        ? 'bg-accent-green/20 border-accent-green/60'
                                        : isCurrent
                                            ? 'bg-accent-cyan/20 border-accent-cyan/60'
                                            : 'bg-white/5 border-white/15'
                                        }`}
                                    animate={isCurrent ? {
                                        boxShadow: [
                                            '0 0 0px rgba(0,212,255,0)',
                                            '0 0 20px rgba(0,212,255,0.4)',
                                            '0 0 0px rgba(0,212,255,0)',
                                        ]
                                    } : {}}
                                    transition={isCurrent ? { duration: 2, repeat: Infinity, ease: 'easeInOut' } : {}}
                                >
                                    {isComplete ? (
                                        <motion.div
                                            initial={{ scale: 0 }}
                                            animate={{ scale: 1 }}
                                            transition={{ type: 'spring', stiffness: 400, damping: 15 }}
                                        >
                                            <CheckCircle className="w-4 h-4 text-accent-green" />
                                        </motion.div>
                                    ) : (
                                        <Icon className={`w-3.5 h-3.5 ${isCurrent ? 'text-accent-cyan' : 'text-text-muted/40'
                                            }`} />
                                    )}

                                    {/* Active phase ping ring */}
                                    {isCurrent && (
                                        <motion.div
                                            className="absolute inset-0 rounded-full border border-accent-cyan/40"
                                            animate={{ scale: [1, 1.6], opacity: [0.6, 0] }}
                                            transition={{ duration: 1.5, repeat: Infinity, ease: 'easeOut' }}
                                        />
                                    )}
                                </motion.div>

                                {/* Phase label */}
                                <span className={`mt-2 text-[9px] font-mono font-bold uppercase tracking-[0.14em] transition-colors duration-500 ${isComplete ? 'text-accent-green/80'
                                    : isCurrent ? 'text-text-primary'
                                        : 'text-text-muted/40'
                                    }`}>
                                    {phase.label}
                                </span>
                            </div>
                        )
                    })}
                </div>
            </div>
        </div>
    )
}

// ============================================================================
// SPECIALIST DISPATCH — Animated badge grid
// ============================================================================

const SPECIALIST_COLORS = {
    'XSS': { bg: 'bg-accent-red/15', text: 'text-accent-red', border: 'border-accent-red/30', icon: Bug },
    'SQLi': { bg: 'bg-accent-purple/15', text: 'text-accent-purple', border: 'border-accent-purple/30', icon: Bug },
    'SSRF': { bg: 'bg-accent-cyan/15', text: 'text-accent-cyan', border: 'border-accent-cyan/30', icon: Wifi },
    'RCE': { bg: 'bg-accent-orange/15', text: 'text-accent-orange', border: 'border-accent-orange/30', icon: Zap },
    'LFI': { bg: 'bg-accent-yellow/15', text: 'text-accent-yellow', border: 'border-accent-yellow/30', icon: FileText },
    'IDOR': { bg: 'bg-accent-pink/15', text: 'text-accent-pink', border: 'border-accent-pink/30', icon: Eye },
    'CSTI': { bg: 'bg-accent-amber/15', text: 'text-accent-amber', border: 'border-accent-amber/30', icon: Zap },
    'XXE': { bg: 'bg-accent-red/15', text: 'text-accent-red', border: 'border-accent-red/30', icon: FileText },
}

function getSpecialistStyle(type) {
    const upper = (type || '').toUpperCase()
    return SPECIALIST_COLORS[upper] || {
        bg: 'bg-white/10', text: 'text-text-primary', border: 'border-white/20', icon: Shield
    }
}

function SpecialistDispatchCard({ event }) {
    const agents = event.metadata?.agents || []
    const count = agents.length || parseInt((event.content.match(/(\d+)\s*specialized/) || [])[1]) || 0

    return (
        <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="relative overflow-hidden rounded-xl border border-accent-cyan/20 bg-gradient-to-br from-accent-cyan/[0.06] to-accent-purple/[0.04] p-4 my-3 shadow-[0_8px_30px_rgba(0,212,255,0.08)]"
        >
            {/* Header */}
            <div className="flex items-center gap-2 mb-3">
                <div className="p-1.5 rounded-lg bg-accent-cyan/15 border border-accent-cyan/25">
                    <Crosshair className="w-4 h-4 text-accent-cyan" />
                </div>
                <span className="text-xs font-bold text-text-primary">Specialist Swarm Deployed</span>
                <span className="ml-auto text-[10px] font-mono font-bold text-accent-cyan bg-accent-cyan/10 border border-accent-cyan/20 rounded-full px-2 py-0.5">
                    {count} agents
                </span>
            </div>

            {/* Agent badges */}
            <div className="flex flex-wrap gap-2">
                {agents.length > 0 ? agents.map((agent, idx) => {
                    const style = getSpecialistStyle(agent.type || agent)
                    const Icon = style.icon
                    const label = typeof agent === 'string' ? agent : agent.type
                    const priority = typeof agent === 'object' ? agent.priority : null

                    return (
                        <motion.div
                            key={idx}
                            initial={{ scale: 0, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            transition={{ delay: idx * 0.08, type: 'spring', stiffness: 500, damping: 20 }}
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border ${style.bg} ${style.border} ${style.text} text-[10px] font-mono font-bold uppercase tracking-wider backdrop-blur-sm`}
                            title={priority ? `Priority: ${priority}` : undefined}
                        >
                            <Icon className="w-3 h-3" />
                            {label}
                            {priority && (
                                <span className={`ml-1 w-1.5 h-1.5 rounded-full ${priority === 'critical' ? 'bg-accent-red' :
                                    priority === 'high' ? 'bg-accent-orange' :
                                        priority === 'medium' ? 'bg-accent-yellow' : 'bg-text-muted'
                                    }`} />
                            )}
                        </motion.div>
                    )
                }) : (
                    <span className="text-[10px] text-text-muted italic">Dispatching...</span>
                )}
            </div>
        </motion.div>
    )
}

// ============================================================================
// SCHEMA WARNING — Orange validation alert
// ============================================================================

function SchemaWarningCard({ event }) {
    return (
        <motion.div
            initial={{ opacity: 0, x: -12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ type: 'spring', stiffness: 300, damping: 25 }}
            className="relative overflow-hidden rounded-xl border border-accent-orange/25 bg-gradient-to-r from-accent-orange/[0.08] to-accent-amber/[0.04] px-4 py-3 my-3 shadow-[0_8px_30px_rgba(255,145,0,0.06)]"
        >
            {/* Animated warning stripe */}
            <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-accent-orange via-accent-amber to-accent-orange" />

            <div className="flex gap-3 pl-2">
                <div className="flex-shrink-0 mt-0.5">
                    <motion.div
                        animate={{ rotate: [0, -8, 8, -4, 0] }}
                        transition={{ duration: 0.5, delay: 0.2 }}
                    >
                        <AlertTriangle className="w-4 h-4 text-accent-orange" />
                    </motion.div>
                </div>
                <div className="flex-1">
                    <div className="text-[10px] font-mono font-bold uppercase tracking-[0.18em] text-accent-orange mb-1">
                        Schema Validation Recovery
                    </div>
                    <div className="text-xs text-accent-orange/80 whitespace-pre-wrap leading-relaxed">
                        {event.content.replace(/^⚠️\s*/, '')}
                    </div>
                </div>
            </div>
        </motion.div>
    )
}

// ============================================================================
// EVENT CLASSIFIERS
// ============================================================================

function isSchemaWarning(event) {
    return event.type === 'message' &&
        (event.content?.includes('schema validation') || event.content?.startsWith('⚠️'))
}

function isSpecialistDispatch(event) {
    return event.type === 'message' &&
        event.content?.includes('Planner dispatching')
}

function isPipelinePhaseEvent(event) {
    return event.type === 'message' &&
        event.content?.includes('Pipeline Phase:')
}

function extractPipelinePhase(content) {
    const match = content.match(/Pipeline Phase:\s*(\w+)/i)
    return match ? match[1].toLowerCase() : null
}

// ============================================================================
// CAUSAL GRAPH — Evidence relationships
// ============================================================================

function CausalGraph({ nodes, edges }) {
    const nodeArray = Object.values(nodes)

    if (nodeArray.length === 0) {
        return (
            <div className="flex-1 flex flex-col items-center justify-center text-text-muted/50 p-12 text-center">
                <Shield className="w-12 h-12 mb-4 opacity-10" />
                <p className="text-sm font-mono uppercase tracking-widest">No causal data points localized</p>
                <p className="text-[10px] mt-2 max-w-xs opacity-60">
                    The agent generates reasoning nodes as it validates hypotheses.
                </p>
            </div>
        )
    }

    const typeColors = {
        'Evidence': 'text-accent-cyan border-accent-cyan/40 bg-accent-cyan/10',
        'Hypothesis': 'text-accent-purple border-accent-purple/40 bg-accent-purple/10',
        'Vulnerability': 'text-accent-red border-accent-red/40 bg-accent-red/10',
        'Fact': 'text-accent-green border-accent-green/40 bg-accent-green/10',
    }

    const statusColors = {
        'PENDING': 'border-white/20 text-white/60',
        'CONFIRMED': 'border-accent-green/60 text-accent-green shadow-[0_0_10px_rgba(0,230,118,0.2)]',
        'FALSIFIED': 'border-accent-red/60 text-accent-red line-through opacity-50',
        'DEPRECATED': 'border-white/10 text-white/30 italic grayscale',
    }

    return (
        <div className="flex-1 min-h-0 flex flex-col p-4 relative overflow-hidden">
            {/* Legend */}
            <div className="flex gap-4 mb-6 relative z-10">
                {Object.entries(typeColors).map(([type, color]) => (
                    <div key={type} className="flex items-center gap-1.5">
                        <div className={`w-2 h-2 rounded-full ${color.split(' ')[0]}`} />
                        <span className="text-[9px] font-mono uppercase tracking-wider text-text-muted">{type}</span>
                    </div>
                ))}
            </div>

            <div className="flex-1 overflow-auto relative grid grid-cols-1 md:grid-cols-3 gap-8 p-4">
                {/* Levels: Left (Evidence/Fact), Middle (Hypothesis), Right (Vulnerability) */}
                <div className="space-y-4">
                    <h4 className="text-[10px] uppercase tracking-widest text-text-muted mb-4 border-b border-white/5 pb-1">Foundations</h4>
                    {nodeArray.filter(n => n.node_type === 'Evidence' || n.node_type === 'Fact').map(node => (
                        <CausalNode key={node.id} node={node} typeColor={typeColors[node.node_type]} statusColor={statusColors[node.status]} />
                    ))}
                </div>
                <div className="space-y-4">
                    <h4 className="text-[10px] uppercase tracking-widest text-text-muted mb-4 border-b border-white/5 pb-1">Hypotheses</h4>
                    {nodeArray.filter(n => n.node_type === 'Hypothesis').map(node => (
                        <CausalNode key={node.id} node={node} typeColor={typeColors[node.node_type]} statusColor={statusColors[node.status]} />
                    ))}
                </div>
                <div className="space-y-4">
                    <h4 className="text-[10px] uppercase tracking-widest text-text-muted mb-4 border-b border-white/5 pb-1">Impact</h4>
                    {nodeArray.filter(n => n.node_type === 'Vulnerability').map(node => (
                        <CausalNode key={node.id} node={node} typeColor={typeColors[node.node_type]} statusColor={statusColors[node.status]} />
                    ))}
                </div>
            </div>

            {/* Relationship Count Overlay */}
            {edges.length > 0 && (
                <div className="absolute bottom-4 right-4 px-3 py-1 bg-white/5 border border-white/10 rounded-full text-[9px] font-mono text-text-muted uppercase tracking-widest backdrop-blur-md">
                    {edges.length} Active Causal Edges
                </div>
            )}
        </div>
    )
}

function CausalNode({ node, typeColor, statusColor }) {
    return (
        <motion.div
            layout
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className={`p-3 rounded-xl border backdrop-blur-md transition-all ${typeColor} ${statusColor} shadow-lg`}
        >
            <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold tracking-tighter truncate max-w-[120px]">{node.id}</span>
                <span className="text-[9px] font-mono px-1.5 rounded-full bg-black/20 border border-white/5">
                    {Math.round((node.confidence || 0) * 100)}%
                </span>
            </div>
            <p className="text-[11px] leading-tight text-text-primary/90">{node.description}</p>
            {node.status !== 'PENDING' && (
                <div className="mt-2 text-[9px] font-mono font-bold uppercase tracking-wider text-right opacity-80">
                    {node.status}
                </div>
            )}
        </motion.div>
    )
}

function FlowDetail() {
    const { id } = useParams()
    const navigate = useNavigate()
    const [flow, setFlow] = useState(null)
    const [events, setEvents] = useState([])
    const [connected, setConnected] = useState(false)
    const [loading, setLoading] = useState(true)
    const [stopping, setStopping] = useState(false)
    const [deleting, setDeleting] = useState(false)
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
    const [eventsError, setEventsError] = useState(null)
    const [ledger, setLedger] = useState(null)
    const [ledgerError, setLedgerError] = useState(null)
    const [activeTab, setActiveTab] = useState('timeline') // 'timeline' | 'ledger' | 'findings' | 'graph' | 'raw'
    const [causalNodes, setCausalNodes] = useState({})
    const [causalEdges, setCausalEdges] = useState([])
    const eventsEndRef = useRef(null)
    const wsRef = useRef(null)

    // Pipeline phase tracking — derive from events
    const currentPhase = useMemo(() => {
        for (let i = events.length - 1; i >= 0; i--) {
            if (isPipelinePhaseEvent(events[i])) {
                return extractPipelinePhase(events[i].content)
            }
        }
        // If flow is complete/failed, show that
        if (flow?.status === 'completed') return 'complete'
        if (flow?.status === 'failed') return null
        return null
    }, [events, flow?.status])

    useEffect(() => {
        fetchFlow()
        fetchEvents()
        fetchLedger()
        connectWebSocket()

        return () => {
            if (wsRef.current) {
                // Ensure we clean up the websocket fully on unmount or re-render
                wsRef.current.onclose = null; // Prevent reconnect loop on unmount
                wsRef.current.close()
                wsRef.current = null
            }
        }
    }, [id])

    useEffect(() => {
        if (!flow || (flow.status !== 'active' && flow.status !== 'running' && flow.status !== 'pending')) {
            return undefined
        }

        const timer = setInterval(() => {
            fetchLedger()
        }, 5000)

        return () => clearInterval(timer)
    }, [flow?.status, id])

    useEffect(() => {
        eventsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [events])

    async function fetchFlow() {
        try {
            const res = await fetch(`${API_BASE}/flows/${id}`)
            if (res.ok) {
                const data = await res.json()
                setFlow(data)
            }
        } catch (err) {
            console.error('Failed to fetch flow:', err)
        } finally {
            setLoading(false)
        }
    }

    async function fetchEvents() {
        try {
            const res = await fetch(`${API_BASE}/flows/${id}/events`)
            if (res.ok) {
                const data = await res.json()
                if (data && Array.isArray(data)) {
                    setEvents(data)

                    // Reconstruct causal graph from history
                    const nodes = {}
                    const edges = []
                    data.forEach(event => {
                        if (event.type === 'causal_node_added') {
                            nodes[event.metadata.id] = event.metadata
                        } else if (event.type === 'causal_node_updated') {
                            const update = event.metadata
                            if (nodes[update.id]) {
                                nodes[update.id] = {
                                    ...nodes[update.id],
                                    status: update.status || nodes[update.id].status,
                                    confidence: update.confidence
                                }
                            }
                        } else if (event.type === 'causal_edge_added') {
                            edges.push(event.metadata)
                        }
                    })
                    setCausalNodes(nodes)
                    setCausalEdges(edges)
                }
                setEventsError(null)
            } else {
                setEventsError('Failed to load historical events')
            }
        } catch (err) {
            console.error('Failed to fetch historical events:', err)
            setEventsError('Failed to load historical events')
        }
    }

    async function fetchLedger() {
        try {
            const res = await fetch(`${API_BASE}/flows/${id}/ledger`)
            if (!res.ok) {
                setLedgerError('Failed to load execution ledger')
                return
            }
            const data = await res.json()
            setLedger(data)
            setLedgerError(null)
        } catch (err) {
            console.error('Failed to fetch ledger:', err)
            setLedgerError('Failed to load execution ledger')
        }
    }

    function connectWebSocket() {
        if (wsRef.current) return;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl = `${protocol}//${window.location.host}/ws`

        const ws = new WebSocket(wsUrl)
        wsRef.current = ws

        ws.onopen = () => {
            setConnected(true)
            console.log('WebSocket connected')
        }

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data)
                if (data.flow_id === id) {
                    let isNewEvent = false
                    setEvents((prev) => {
                        const alreadyExists = prev.some(e => e.id === data.id || (e.timestamp === data.timestamp && e.content === data.content));
                        if (alreadyExists) return prev;
                        isNewEvent = true
                        return [...prev, data];
                    });

                    if (isNewEvent) {
                        if (data.type === 'causal_node_added') {
                            const node = data.metadata
                            setCausalNodes(prev => ({ ...prev, [node.id]: node }))
                        } else if (data.type === 'causal_node_updated') {
                            const update = data.metadata
                            setCausalNodes(prev => {
                                const node = prev[update.id]
                                if (!node) return prev
                                return { ...prev, [update.id]: { ...node, ...update } }
                            })
                        } else if (data.type === 'causal_edge_added') {
                            const edge = data.metadata
                            setCausalEdges(prev => {
                                const exists = prev.some(e => e.source_id === edge.source_id && e.target_id === edge.target_id && e.label === edge.label)
                                if (exists) return prev
                                return [...prev, edge]
                            })
                        }
                    }

                    if (data.type === 'complete' || data.type === 'error') {
                        setTimeout(() => {
                            fetchFlow()
                            fetchLedger()
                        }, 1000)
                    }
                }
            } catch (err) {
                console.error('Failed to parse WS message:', err)
            }
        }

        ws.onclose = () => {
            setConnected(false)
            console.log('WebSocket disconnected')
            setTimeout(connectWebSocket, 3000)
        }

        ws.onerror = () => {
            setConnected(false)
        }
    }

    function formatTime(timestamp) {
        if (!timestamp) return ''
        return new Date(timestamp).toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', second: '2-digit',
        })
    }

    function getEventIcon(type) {
        switch (type) {
            case 'thinking': return <Cpu className="w-4 h-4" />
            case 'tool_call': return <Wrench className="w-4 h-4" />
            case 'tool_result': return <CheckCircle className="w-4 h-4" />
            case 'message': return <MessageSquare className="w-4 h-4" />
            case 'complete': return <CheckCircle className="w-4 h-4" />
            case 'error': return <XCircle className="w-4 h-4" />
            default: return <ChevronRight className="w-4 h-4" />
        }
    }

    function getEventColorClass(type) {
        switch (type) {
            case 'thinking': return 'text-accent-purple'
            case 'tool_call': return 'text-accent-cyan'
            case 'tool_result': return 'text-accent-green'
            case 'message': return 'text-accent-yellow'
            case 'complete': return 'text-accent-green'
            case 'error': return 'text-accent-red'
            default: return 'text-text-secondary'
        }
    }

    if (loading) {
        return (
            <div className="relative pb-12 max-w-[1600px] mx-auto">
                <div className="pointer-events-none absolute inset-x-0 -top-28 h-60 bg-[radial-gradient(circle_at_top,_rgba(0,212,255,0.18),transparent_60%)] opacity-80" />
                <div className="mt-10 grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-8 px-4 sm:px-6 lg:px-8">
                    <div className="lg:col-span-2 h-[600px] relative overflow-hidden rounded-3xl border border-white/12 bg-white/6 backdrop-blur-2xl shadow-[0_20px_80px_rgba(15,23,42,0.95)]">
                        <div className="absolute inset-0 bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.25),transparent)] bg-[length:220%_100%] animate-[shimmer_2.5s_linear_infinite] opacity-40" />
                        <div className="relative p-6 space-y-4">
                            <div className="h-4 w-1/3 bg-white/12 rounded-full" />
                            <div className="space-y-2">
                                {Array.from({ length: 6 }).map((_, idx) => (
                                    <div key={idx} className="h-3 w-full bg-white/6 rounded-full" />
                                ))}
                            </div>
                        </div>
                    </div>
                    <div className="h-[600px] relative overflow-hidden rounded-3xl border border-white/12 bg-white/6 backdrop-blur-2xl shadow-[0_20px_80px_rgba(15,23,42,0.95)]">
                        <div className="absolute inset-0 bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.25),transparent)] bg-[length:220%_100%] animate-[shimmer_2.5s_linear_infinite] opacity-40" />
                        <div className="relative p-6 space-y-4">
                            <div className="h-4 w-1/2 bg-white/12 rounded-full" />
                            {Array.from({ length: 5 }).map((_, idx) => (
                                <div key={idx} className="h-3 w-full bg-white/6 rounded-full" />
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        )
    }

    if (!flow) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[40vh] p-12 text-center border border-border/50 rounded-2xl bg-card-bg/30 backdrop-blur-sm">
                <div className="w-20 h-20 bg-accent-red/10 border border-accent-red/30 rounded-full flex items-center justify-center mb-6">
                    <XCircle className="w-8 h-8 text-accent-red" />
                </div>
                <h2 className="text-2xl font-bold text-text-primary mb-3">Trace Cannot Be Located</h2>
                <Link to="/" className="btn btn-primary mt-4">Return to HQ</Link>
            </div>
        )
    }

    const isActive = flow.status === 'active' || flow.status === 'running' || flow.status === 'pending'

    const headerGradientClass =
        flow.status === 'failed'
            ? 'bg-gradient-to-r from-text-primary to-accent-red'
            : flow.status === 'completed'
                ? 'bg-gradient-to-r from-text-primary to-accent-green'
                : 'bg-gradient-to-r from-text-primary to-text-muted'

    const glowClass =
        flow.status === 'failed'
            ? 'bg-[radial-gradient(circle_at_top,_rgba(255,71,87,0.22),transparent_60%)]'
            : flow.status === 'completed'
                ? 'bg-[radial-gradient(circle_at_top,_rgba(0,230,118,0.22),transparent_60%)]'
                : 'bg-[radial-gradient(circle_at_top,_rgba(0,212,255,0.16),transparent_60%)]'

    const findings = events.filter(
        (event) => event.type === 'tool_result' && event.metadata && event.metadata.tool === 'report_findings'
    )

    async function handleStopScan() {
        if (!confirm('Are you sure you want to stop this scan?')) return;
        setStopping(true);
        try {
            const res = await fetch(`${API_BASE}/flows/${id}/cancel`, { method: 'POST' });
            if (res.ok) {
                // Optimistically update
                setFlow(prev => ({ ...prev, status: 'failed' }));
            }
        } catch (err) {
            console.error('Failed to stop scan:', err);
        } finally {
            setStopping(false);
        }
    }

    function openDeleteConfirm() {
        if (flow) setShowDeleteConfirm(true)
    }

    async function confirmDeleteFlow(flowId) {
        if (!flowId) return
        setShowDeleteConfirm(false)
        setDeleting(true)
        try {
            const res = await fetch(`${API_BASE}/flows/${flowId}`, { method: 'DELETE' })
            if (res.ok) {
                navigate('/', { replace: true })
            } else {
                const text = await res.text()
                window.alert(text || 'Failed to delete flow.')
            }
        } catch (err) {
            console.error('Failed to delete flow:', err)
            window.alert('Failed to delete flow: ' + (err.message || 'network error'))
        } finally {
            setDeleting(false)
        }
    }

    return (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="relative pb-12 max-w-[1600px] mx-auto">
            {/* Delete confirmation modal — in-app so it can't be closed by navigation */}
            {showDeleteConfirm && (
                <div
                    className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
                    onClick={() => setShowDeleteConfirm(false)}
                    role="dialog"
                    aria-modal="true"
                >
                    <div
                        className="relative rounded-2xl border border-white/20 bg-[#0f172a] p-6 shadow-2xl max-w-sm w-full"
                        onClick={(e) => e.stopPropagation()}
                        onMouseDown={(e) => e.stopPropagation()}
                    >
                        <h3 className="text-lg font-bold text-text-primary mb-2">Delete this flow?</h3>
                        <p className="text-sm text-text-muted mb-4">
                            {flow && (flow.status === 'active' || flow.status === 'running')
                                ? 'This flow is still running. It will be stopped, then deleted.'
                                : 'This cannot be undone.'}
                        </p>
                        {flow && (
                            <p className="text-xs font-mono text-text-muted truncate mb-6" title={flow.name}>
                                {flow.name}
                            </p>
                        )}
                        <div className="flex gap-3 justify-end">
                            <button
                                type="button"
                                onClick={() => setShowDeleteConfirm(false)}
                                className="px-4 py-2 rounded-lg text-sm font-medium text-text-primary bg-white/10 border border-white/20 hover:bg-white/15"
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={(e) => {
                                    e.preventDefault()
                                    e.stopPropagation()
                                    confirmDeleteFlow(id)
                                }}
                                className="px-4 py-2 rounded-lg text-sm font-medium text-white bg-accent-red border border-accent-red hover:opacity-90"
                            >
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Ambient background glow & vertical streaks (tinted by status) */}
            <div className="pointer-events-none absolute inset-0 -z-10">
                <div className={`absolute inset-x-0 -top-28 h-60 opacity-80 ${glowClass}`} />
                <div className="absolute left-1/4 inset-y-10 w-px bg-gradient-to-b from-accent-cyan/0 via-accent-cyan/35 to-accent-cyan/0 opacity-60" />
                <div className="absolute left-1/2 inset-y-0 w-px bg-gradient-to-b from-accent-purple/0 via-accent-purple/30 to-accent-purple/0 opacity-50" />
                <div className="absolute right-1/5 inset-y-10 w-px bg-gradient-to-b from-accent-green/0 via-accent-green/35 to-accent-green/0 opacity-55" />
            </div>
            {/* Header */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-6 border-b border-border/50 pb-6 relative z-10">
                <div>
                    <Link to="/" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-cyan transition-colors mb-4 text-sm font-semibold uppercase tracking-wider relative group">
                        <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" /> Dashboard
                    </Link>
                    <h1 className={`text-3xl md:text-4xl font-display font-black text-transparent bg-clip-text ${headerGradientClass} mb-2 tracking-tight`}>
                        {flow.name}
                    </h1>
                    <p className="text-text-muted/80 max-w-2xl text-sm leading-relaxed mb-2">{flow.description}</p>
                    <div className="flex flex-wrap gap-2 text-[10px] font-mono uppercase tracking-[0.16em] text-text-muted/80">
                        <span className={`${CHIP_BASE} bg-white/5 border-white/10`}>
                            <Target className="w-3 h-3 text-accent-cyan" />
                            <span className="truncate max-w-[160px]">{flow.target}</span>
                        </span>
                        <span className={`${CHIP_BASE} bg-white/5 border-white/10`}>
                            <Clock className="w-3 h-3 text-accent-yellow" />
                            <span>Started {new Date(flow.created_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
                        </span>
                        <span className={`${CHIP_BASE} bg-white/5 border-white/10`}>
                            <Clock className="w-3 h-3 text-accent-purple" />
                            <span>Updated {new Date(flow.updated_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
                        </span>
                        <span className={`${CHIP_BASE} bg-white/5 border-white/10`}>
                            <span className="w-2 h-2 rounded-full bg-text-muted" />
                            <span>{flow.id.slice(0, 8)}</span>
                        </span>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <span className={`${CHIP_BASE} px-3 py-1 font-bold backdrop-blur-md shadow-sm ${isActive ? 'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30 animate-pulse' :
                        flow.status === 'completed' ? 'bg-accent-green/10 text-accent-green border-accent-green/30' :
                            'bg-accent-red/10 text-accent-red border-accent-red/30'
                        }`}>
                        {flow.status}
                    </span>
                    <span className={`${CHIP_BASE} px-3 py-1 font-bold backdrop-blur-md shadow-sm ${connected ? 'bg-accent-green/10 text-accent-green border-accent-green/30' : 'bg-text-muted/10 text-text-muted border-text-muted/30'
                        }`}>
                        <span className={`w-2 h-2 rounded-full ${connected ? 'bg-accent-green animate-ping' : 'bg-text-muted'}`}></span>
                        {connected ? 'Uplink Live' : 'Offline'}
                    </span>

                    {isActive && (
                        <button
                            onClick={handleStopScan}
                            disabled={stopping}
                            className={`flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-mono font-bold tracking-widest uppercase border backdrop-blur-md shadow-sm transition-all
                                ${stopping ? 'bg-text-muted/10 text-text-muted border-text-muted/30 cursor-not-allowed' : 'bg-accent-red/10 text-accent-red border-accent-red/30 hover:bg-accent-red/20 hover:scale-105'}`}
                        >
                            {stopping ? 'Stopping...' : <><XCircle className="w-3 h-3" /> Stop Scan</>}
                        </button>
                    )}

                    <button
                        type="button"
                        onMouseDown={(e) => {
                            e.preventDefault()
                            e.stopPropagation()
                        }}
                        onClick={(e) => {
                            e.preventDefault()
                            e.stopPropagation()
                            openDeleteConfirm()
                        }}
                        disabled={deleting}
                        className={`flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-mono font-bold tracking-widest uppercase border backdrop-blur-md shadow-sm transition-all
                            ${deleting
                                ? 'bg-text-muted/10 text-text-muted border-text-muted/30 cursor-not-allowed'
                                : 'bg-text-muted/10 text-text-muted border-text-muted/30 hover:bg-accent-red/15 hover:text-accent-red hover:border-accent-red/40 hover:scale-105'}`}
                    >
                        {deleting ? 'Deleting...' : <><Trash2 className="w-3 h-3" /> Delete Flow</>}
                    </button>

                </div>
            </div>

            {/* Pipeline Tracker */}
            <div className="relative z-10">
                <PipelineTracker currentPhase={currentPhase} />
            </div>

            {/* Info Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8 relative z-10">
                <div className="relative overflow-hidden rounded-2xl border border-white/14 bg-white/5 backdrop-blur-xl p-5 hover:border-accent-cyan/50 transition-colors group shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                    <div className="flex items-center gap-2 text-text-muted mb-2"><Target className="w-4 h-4 text-accent-cyan group-hover:scale-110 transition-transform" /> <span className="text-xs font-bold uppercase tracking-wider">Target Node</span></div>
                    <div className="font-mono text-accent-cyan text-sm sm:text-base font-medium truncate" title={flow.target}>{flow.target}</div>
                </div>
                <div className="relative overflow-hidden rounded-2xl border border-white/14 bg-white/5 backdrop-blur-xl p-5 hover:border-accent-cyan/50 transition-colors group shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                    <div className="flex items-center gap-2 text-text-muted mb-2"><Activity className="w-4 h-4 text-accent-purple group-hover:scale-110 transition-transform" /> <span className="text-xs font-bold uppercase tracking-wider">Current State</span></div>
                    <div className="text-text-primary text-sm sm:text-base font-medium capitalize">{flow.status}</div>
                </div>
                <div className="relative overflow-hidden rounded-2xl border border-white/14 bg-white/5 backdrop-blur-xl p-5 hover:border-accent-cyan/50 transition-colors group shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                    <div className="flex items-center gap-2 text-text-muted mb-2"><Clock className="w-4 h-4 text-accent-yellow group-hover:scale-110 transition-transform" /> <span className="text-xs font-bold uppercase tracking-wider">Time Initiated</span></div>
                    <div className="text-text-primary text-sm font-medium">{new Date(flow.created_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</div>
                </div>
                <div className="relative overflow-hidden rounded-2xl border border-white/14 bg-white/5 backdrop-blur-xl p-5 hover:border-accent-cyan/50 transition-colors group shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                    <div className="absolute top-0 right-0 w-16 h-16 bg-accent-green/10 rounded-full blur-[20px]"></div>
                    <div className="flex items-center gap-2 text-text-muted mb-2 relative z-10"><Terminal className="w-4 h-4 text-accent-green group-hover:scale-110 transition-transform" /> <span className="text-xs font-bold uppercase tracking-wider">Telemetry Events</span></div>
                    <div className="text-text-primary text-2xl font-black relative z-10">{events.length}</div>
                </div>
            </div>

            {/* Main Terminal & Timeline Split */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-8 pb-8 relative z-10">

                {/* 1. Terminal Window */}
                <div className="lg:col-span-2 flex flex-col h-[600px] bg-[#0a0f18] rounded-2xl border border-border/80 shadow-2xl overflow-hidden relative group">
                    {/* Mac-style Terminal Header */}
                    <div className="px-4 py-3 bg-[#111827] border-b border-border/80 flex items-center justify-between sticky top-0 z-10 backdrop-blur-md">
                        <div className="flex items-center gap-2">
                            <div className="w-3 h-3 rounded-full bg-accent-red/80"></div>
                            <div className="w-3 h-3 rounded-full bg-accent-yellow/80"></div>
                            <div className="w-3 h-3 rounded-full bg-accent-green/80"></div>
                        </div>
                        <div className="text-xs font-mono tracking-widest text-text-muted flex items-center gap-2">
                            <Terminal className="w-3 h-3" /> mirage_agent@{flow.target}
                        </div>
                        <div className="w-12 flex justify-end">
                            {isActive && <div className="w-4 h-4 border-2 border-accent-cyan/40 border-t-accent-cyan rounded-full animate-spin"></div>}
                        </div>
                    </div>

                    {/* Terminal Body */}
                    <div className="flex-1 min-h-0 p-5 lg:p-6 overflow-y-auto font-mono text-[13px] leading-relaxed relative scroll-smooth terminal-scrollbar">
                        {/* Glow overlay */}
                        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-accent-cyan/5 blur-[120px] pointer-events-none"></div>

                        {events.length === 0 ? (
                            <div className="h-full flex flex-col items-center justify-center text-text-muted/60">
                                {isActive ? (
                                    <>
                                        <div className="w-8 h-8 border-2 border-accent-cyan/20 border-t-accent-cyan rounded-full animate-spin mb-4 shadow-[0_0_15px_rgba(0,212,255,0.3)]"></div>
                                        <p className="tracking-widest text-xs uppercase text-text-muted/80">Awaiting secure shell initialization...</p>
                                    </>
                                ) : (
                                    <p>No telemetry recorded for this operation.</p>
                                )}
                            </div>
                        ) : (
                            events.map((event, i) => {
                                const meta = event.metadata || {}
                                return (
                                    <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} key={i} className="mb-4 break-words">
                                        {/* Command Execution */}
                                        {event.type === 'tool_call' && meta.tool === 'execute_command' && (
                                            <div className="text-accent-cyan/90 font-bold flex gap-3">
                                                <span className="text-accent-purple select-none mt-0.5">λ</span>
                                                <span className="whitespace-pre-wrap flex-1">
                                                    {meta.subtask_id && <span className="mr-2 inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-mono text-white/70 bg-white/10" title="Agent Thread ID">{meta.subtask_id}</span>}
                                                    {(() => {
                                                        try {
                                                            const args = JSON.parse(meta.args || '{}')
                                                            return args.command || meta.args
                                                        } catch {
                                                            return meta.args
                                                        }
                                                    })()}
                                                </span>
                                            </div>
                                        )}
                                        {/* Agent Thinking */}
                                        {(event.type === 'thinking' || (event.type === 'tool_call' && meta.tool === 'think')) && (
                                            <div className="text-text-muted/70 italic flex gap-3 pl-5 border-l-2 border-text-muted/20 my-2.5">
                                                <Cpu className="w-4 h-4 mt-1 flex-shrink-0 opacity-40 text-accent-purple" />
                                                <span className="whitespace-pre-wrap flex-1">
                                                    {meta.subtask_id && <span className="mr-2 inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-mono text-white/50 bg-white/5" title="Agent Thread ID">{meta.subtask_id}</span>}
                                                    {(() => {
                                                        if (event.type === 'tool_call') {
                                                            try {
                                                                const args = JSON.parse(meta.args || '{}')
                                                                return args.thought || meta.args
                                                            } catch {
                                                                return meta.args
                                                            }
                                                        }
                                                        return event.content
                                                    })()}
                                                </span>
                                            </div>
                                        )}
                                        {/* Command Result Output */}
                                        {event.type === 'tool_result' && meta.tool === 'execute_command' && (
                                            <div className="text-[#a8b2c2] mt-2 pl-7 whitespace-pre-wrap relative text-xs bg-[#111827]/40 p-3 rounded border border-border/20 shadow-inner">
                                                {event.content}
                                            </div>
                                        )}
                                        {/* Schema Validation Warning */}
                                        {isSchemaWarning(event) && (
                                            <SchemaWarningCard event={event} />
                                        )}
                                        {/* Specialist Dispatch */}
                                        {isSpecialistDispatch(event) && (
                                            <SpecialistDispatchCard event={event} />
                                        )}
                                        {/* Agent Message / System Info (exclude schema warnings & dispatch which have their own rendering) */}
                                        {(event.type === 'message' || (event.type === 'tool_result' && meta.tool !== 'execute_command')) && !isSchemaWarning(event) && !isSpecialistDispatch(event) && (
                                            <div className="text-accent-yellow/90 bg-accent-yellow/5 px-4 py-3 rounded-lg border border-accent-yellow/10 my-3 whitespace-pre-wrap flex gap-3">
                                                <MessageSquare className="w-4 h-4 flex-shrink-0 mt-0.5" />
                                                <span className="flex-1">{event.content}</span>
                                            </div>
                                        )}
                                        {/* Errors */}
                                        {event.type === 'error' && (
                                            <div className="text-accent-red bg-accent-red/5 px-4 py-3 rounded-lg border border-accent-red/20 my-3 flex gap-3">
                                                <XCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                                                <span className="font-bold flex-1">{event.content}</span>
                                            </div>
                                        )}
                                        {/* Completion */}
                                        {event.type === 'complete' && (
                                            <div className="text-accent-green bg-accent-green/5 px-4 py-3 rounded-lg border border-accent-green/20 mt-6 flex gap-3 shadow-[0_0_15px_rgba(0,230,118,0.1)]">
                                                <CheckCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                                                <span className="font-bold flex-1 text-sm tracking-wide">Execution Finalized: {event.content}</span>
                                            </div>
                                        )}
                                    </motion.div>
                                )
                            })
                        )}
                        {/* Blinking Cursor */}
                        {isActive && (
                            <div className="flex items-center gap-3 text-accent-cyan h-6 mt-3 pl-1">
                                <span className="text-accent-purple select-none mt-0.5 font-bold">λ</span>
                                <div className="w-2.5 h-4 bg-accent-cyan animate-[blink_1s_step-end_infinite] shadow-[0_0_8px_rgba(0,212,255,0.8)]"></div>
                            </div>
                        )}
                        <div ref={eventsEndRef} className="h-8" />
                    </div>
                </div>

                {/* 2. Timeline Sidebar */}
                <div className="flex flex-col h-[600px]">
                    <div className="flex items-center justify-between mb-3">
                        <h3 className="text-sm font-bold text-text-muted tracking-widest uppercase flex items-center gap-2">
                            <Activity className="w-4 h-4 text-accent-cyan" /> Scan Story
                        </h3>
                        <div className="relative inline-flex items-center rounded-full bg-white/5 border border-white/10 p-1 text-xs font-mono overflow-hidden min-w-[220px]">
                            <div
                                className="absolute inset-y-0 left-0 rounded-full bg-accent-cyan shadow-[0_0_10px_rgba(0,212,255,0.4)] transition-transform duration-500 ease-out"
                                style={{
                                    width: `${100 / 5}%`,
                                    transform:
                                        activeTab === 'timeline'
                                            ? 'translateX(0%)'
                                            : activeTab === 'ledger'
                                                ? 'translateX(100%)'
                                                : activeTab === 'findings'
                                                    ? 'translateX(200%)'
                                                    : activeTab === 'graph'
                                                        ? 'translateX(300%)'
                                                        : 'translateX(400%)',
                                }}
                            />
                            {['timeline', 'ledger', 'findings', 'graph', 'raw'].map((tab) => (
                                <button
                                    key={tab}
                                    type="button"
                                    onClick={() => setActiveTab(tab)}
                                    className={`relative z-10 flex-1 px-2.5 py-1 rounded-full text-center transition-colors duration-200 ${activeTab === tab ? 'text-primary-bg' : 'text-text-muted hover:text-text-primary'
                                        }`}
                                >
                                    {tab === 'timeline' && 'Timeline'}
                                    {tab === 'ledger' && 'Ledger'}
                                    {tab === 'findings' && 'Findings'}
                                    {tab === 'graph' && 'Evidence Graph'}
                                    {tab === 'raw' && 'Raw Logs'}
                                </button>
                            ))}
                        </div>
                    </div>
                    <div className="flex-1 min-h-0 relative overflow-hidden rounded-2xl border border-white/14 bg-white/5 backdrop-blur-xl p-5 overflow-y-auto timeline-scrollbar shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                        {eventsError && (
                            <div className="mb-3 rounded-xl border border-accent-red/30 bg-accent-red/10 px-3 py-2 text-xs text-accent-red">
                                {eventsError}
                            </div>
                        )}
                        {ledgerError && activeTab === 'ledger' && (
                            <div className="mb-3 rounded-xl border border-accent-red/30 bg-accent-red/10 px-3 py-2 text-xs text-accent-red">
                                {ledgerError}
                            </div>
                        )}
                        <AnimatePresence mode="wait">
                            <motion.div
                                key={activeTab}
                                initial={{ opacity: 0, y: 4 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -4 }}
                                transition={{ duration: 0.18, ease: 'easeOut' }}
                                className="h-full"
                            >
                                {activeTab === 'timeline' && (
                                    <>
                                        {events.length === 0 ? (
                                            <div className="h-full flex items-center justify-center text-text-muted text-sm italic py-10">
                                                Waiting for signals...
                                            </div>
                                        ) : (
                                            <div className="relative border-l-2 border-border/60 ml-3 space-y-6 pb-4 pt-2">
                                                {events.map((event, i) => (
                                                    <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} key={i} className="relative pl-6 group">
                                                        {/* Timeline Dot */}
                                                        <div className={`absolute -left-[7px] top-1.5 w-3 h-3 rounded-full border-2 border-card-bg transition-transform group-hover:scale-125 ${event.type === 'error' ? 'bg-accent-red shadow-[0_0_10px_rgba(255,49,49,0.5)]' : event.type === 'complete' ? 'bg-accent-green shadow-[0_0_10px_rgba(0,230,118,0.5)]' : 'bg-text-muted'}`}></div>

                                                        <div className="flex justify-between items-start mb-1.5">
                                                            <div className={`flex items-center gap-2 text-xs font-bold uppercase tracking-wider ${getEventColorClass(event.type)}`}>
                                                                {getEventIcon(event.type)}
                                                                {event.type.replace('_', ' ')}
                                                            </div>
                                                        </div>

                                                        <div className="text-sm text-text-primary/80 leading-relaxed bg-[#111827]/50 rounded border border-border/30 p-2.5 shadow-sm group-hover:border-accent-cyan/20 transition-colors">
                                                            {event.content.length > 100 ? event.content.substring(0, 100) + '...' : event.content}

                                                            <div className="flex items-center justify-between mt-2 pt-2 border-t border-border/30">
                                                                <span className="text-[10px] font-mono text-text-muted/60 tracking-wider">
                                                                    {formatTime(event.timestamp)}
                                                                </span>
                                                                {event.metadata?.tool && (
                                                                    <span className="inline-block px-1.5 py-0.5 bg-accent-cyan/10 border border-accent-cyan/20 rounded text-[9px] font-mono text-accent-cyan uppercase tracking-wider">
                                                                        {event.metadata.tool}
                                                                    </span>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </motion.div>
                                                ))}
                                            </div>
                                        )}
                                    </>
                                )}
                                {activeTab === 'ledger' && (
                                    <FlowLedgerPanel ledger={ledger} formatTime={formatTime} />
                                )}
                                {activeTab === 'findings' && (
                                    <>
                                        {findings.length === 0 ? (
                                            <FlowEvidencePanel evidence={ledger?.evidence || []} formatTime={formatTime} />
                                        ) : (
                                            <div className="space-y-4">
                                                <FlowEvidencePanel evidence={ledger?.evidence || []} formatTime={formatTime} />
                                                <div className="pt-2 border-t border-border/40">
                                                    <FindingList findings={findings} formatTime={formatTime} />
                                                </div>
                                            </div>
                                        )}
                                    </>
                                )}
                                {activeTab === 'graph' && (
                                    <div className="h-full flex flex-col">
                                        <CausalGraph nodes={causalNodes} edges={causalEdges} />
                                    </div>
                                )}
                                {activeTab === 'raw' && (
                                    <pre className="text-[11px] font-mono text-text-muted whitespace-pre-wrap">
                                        {events.map((event) => {
                                            const time = formatTime(event.timestamp)
                                            const tool = event.metadata?.tool ? ` [${event.metadata.tool}]` : ''
                                            return `[${time}] (${event.type})${tool} ${event.content}\n\n`
                                        })}
                                    </pre>
                                )}
                            </motion.div>
                        </AnimatePresence>
                    </div>
                </div>

            </div>
        </motion.div>
    )
}

export default FlowDetail
