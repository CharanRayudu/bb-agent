import React, { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Search, Zap, Clock, Activity, Target, ArrowRight } from 'lucide-react'

const API_BASE = '/api'

function Dashboard() {
    const [flows, setFlows] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [findings, setFindings] = useState([])
    const [findingsLoading, setFindingsLoading] = useState(false)
    const findingsLoadedRef = useRef(false)

    useEffect(() => {
        fetchFlows()
        const interval = setInterval(fetchFlows, 5000)
        return () => clearInterval(interval)
    }, [])

    async function fetchFlows() {
        try {
            const res = await fetch(`${API_BASE}/flows`)
            if (res.ok) {
                const data = await res.json()
                setFlows(data || [])
                setError(null)
            } else {
                setError('Failed to load scans')
            }
        } catch (err) {
            console.error('Failed to fetch flows:', err)
            setError('Failed to load scans')
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        if (!loading && flows.length > 0 && !findingsLoadedRef.current) {
            findingsLoadedRef.current = true
            fetchFindingsForFlows(flows.slice(0, 6))
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [loading, flows])

    async function fetchFindingsForFlows(selectedFlows) {
        try {
            setFindingsLoading(true)
            const allFindings = []
            await Promise.all(
                selectedFlows.map(async (flow) => {
                    try {
                        const res = await fetch(`${API_BASE}/flows/${flow.id}/events`)
                        if (!res.ok) return
                        const events = await res.json()
                        if (!Array.isArray(events)) return
                        events
                            .filter((event) => event.type === 'tool_result' && event.metadata && event.metadata.tool === 'report_findings')
                            .forEach((event) => {
                                const content = event.content || ''
                                const severityMatch = content.match(/\*\*Severity\*\*:\s*(\w+)/i)
                                const severity = (severityMatch ? severityMatch[1] : 'info').toLowerCase()
                                const titleLine = content.split('\n').find((line) => line.trim().startsWith('## ')) || ''
                                const title = titleLine.replace(/^##\s*/, '') || 'Finding'
                                allFindings.push({
                                    id: `${flow.id}-${event.timestamp}`,
                                    flowId: flow.id,
                                    flowName: flow.name,
                                    severity,
                                    title,
                                    content,
                                })
                            })
                    } catch {
                        // ignore per-flow errors
                    }
                })
            )
            setFindings(allFindings)
        } finally {
            setFindingsLoading(false)
        }
    }

    function getStatusBadge(status) {
        const baseClasses = 'inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-mono uppercase tracking-[0.16em] border backdrop-blur-sm shadow-sm'
        switch (status) {
            case 'completed':
                return `${baseClasses} bg-accent-green/10 text-accent-green border-accent-green/30`
            case 'active':
                // Active but not yet completed — blue/cyan without pulse
                return `${baseClasses} bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30`
            case 'running':
                return `${baseClasses} bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30 animate-pulse`
            case 'failed':
                // Make FAILED much more prominent on the dark glass background
                return `${baseClasses} bg-[#ff4757] text-white border-transparent shadow-[0_0_18px_rgba(255,71,87,0.6)]`
            default:
                return `${baseClasses} bg-text-muted/10 text-text-muted border-text-muted/30`
        }
    }

    function formatDate(dateStr) {
        return new Date(dateStr).toLocaleString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
        })
    }

    if (loading) {
        return (
            <div className="relative pb-12">
                <div className="pointer-events-none absolute inset-0 -z-10">
                    <div className="absolute inset-x-0 -top-32 h-64 bg-[radial-gradient(circle_at_top,_rgba(0,212,255,0.18),transparent_65%)] opacity-70" />
                    <div className="absolute -top-40 -left-32 w-[40rem] h-[40rem] bg-accent-cyan/18 rounded-full blur-3xl animate-float" />
                    <div className="absolute top-24 -right-40 w-[36rem] h-[36rem] bg-accent-purple/18 rounded-full blur-3xl animate-float" />
                </div>
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
                    <div className="mb-10 mt-6">
                        <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-white/5 backdrop-blur-2xl px-6 py-6 md:px-8 md:py-7 shadow-[0_18px_80px_rgba(15,23,42,0.95)]">
                            <div className="h-6 w-40 bg-gradient-to-r from-white/10 via-white/25 to-white/10 rounded-full animate-[shimmer_2.5s_linear_infinite] bg-[length:200%_100%]" />
                            <div className="mt-3 h-4 w-64 bg-gradient-to-r from-white/5 via-white/15 to-white/5 rounded-full animate-[shimmer_2.5s_linear_infinite] bg-[length:200%_100%]" />
                        </div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 auto-rows-[1fr]">
                        {Array.from({ length: 6 }).map((_, idx) => (
                            <div
                                key={idx}
                                className="h-full relative overflow-hidden rounded-3xl border border-white/12 bg-white/6 backdrop-blur-2xl p-6 shadow-[0_18px_70px_rgba(15,23,42,0.9)]"
                            >
                                <div className="absolute inset-0 bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.25),transparent)] bg-[length:200%_100%] animate-[shimmer_2.5s_linear_infinite] opacity-40" />
                                <div className="relative space-y-4">
                                    <div className="h-4 w-1/2 bg-white/10 rounded-full" />
                                    <div className="h-3 w-3/4 bg-white/8 rounded-full" />
                                    <div className="h-3 w-2/3 bg-white/6 rounded-full" />
                                    <div className="mt-6 flex justify-between">
                                        <div className="h-3 w-20 bg-white/6 rounded-full" />
                                        <div className="h-3 w-10 bg-white/8 rounded-full" />
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        )
    }

    // Framer Motion Variants
    const containerVariants = {
        hidden: { opacity: 0 },
        visible: { opacity: 1, transition: { staggerChildren: 0.1 } }
    }
    const itemVariants = {
        hidden: { opacity: 0, y: 20 },
        visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 300, damping: 24 } }
    }

    return (
        <div className="relative pb-12">
            {/* Ambient background glow & blobs */}
            <div className="pointer-events-none absolute inset-0 -z-10">
                <div className="absolute inset-x-0 -top-32 h-64 bg-[radial-gradient(circle_at_top,_rgba(0,212,255,0.18),transparent_65%)] opacity-70" />
                <div className="absolute -top-40 -left-32 w-[40rem] h-[40rem] bg-accent-cyan/18 rounded-full blur-3xl animate-float" />
                <div className="absolute top-24 -right-40 w-[36rem] h-[36rem] bg-accent-purple/18 rounded-full blur-3xl animate-float" />
            </div>

            {/* Header Area */}
            <div className="mb-10 relative z-10">
                <div className="relative overflow-hidden rounded-3xl border border-white/12 bg-white/6 backdrop-blur-2xl shadow-[0_18px_80px_rgba(15,23,42,0.95)] px-6 py-6 md:px-8 md:py-7">
                    <div className="absolute -right-24 -top-24 h-64 w-64 bg-accent-cyan/20 blur-3xl opacity-60" />
                    <div className="absolute -left-24 -bottom-24 h-64 w-64 bg-accent-purple/20 blur-3xl opacity-40" />

                    <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                        <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }}>
                            <h1 className="text-4xl md:text-5xl font-display font-black text-transparent bg-clip-text bg-gradient-to-r from-text-primary to-text-muted mb-3 tracking-tight">
                                Active Scans
                            </h1>
                            <p className="text-sm md:text-base text-text-muted flex items-center gap-2">
                                <Activity className="w-4 h-4 text-accent-cyan" />
                                Monitoring {flows.length} autonomous penetration tests
                            </p>
                        </motion.div>
                        <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}>
                            <Link
                                to="/new"
                                className="group relative inline-flex items-center justify-center gap-2 px-8 py-3.5 text-sm font-semibold text-primary-bg rounded-full overflow-hidden transition-all duration-300 hover:scale-105 hover:shadow-[0_0_24px_rgba(0,212,255,0.55)] bg-gradient-to-r from-accent-cyan via-accent-green to-accent-cyan"
                            >
                                <div className="absolute inset-0 w-full h-full bg-gradient-to-r from-white/40 via-transparent to-white/40 opacity-0 group-hover:opacity-100 transition-opacity duration-700 bg-[length:220%_100%] animate-[shimmer_3s_linear_infinite]" />
                                <Zap className="w-4 h-4 relative z-10" />
                                <span className="relative z-10 font-bold tracking-wide">Initiate New Attack</span>
                            </Link>
                        </motion.div>
                    </div>
                </div>
            </div>

            {/* Findings Overview */}
            {(findingsLoading || findings.length > 0) && (
                <div className="mb-8 relative z-10">
                    <div className="flex items-center justify-between mb-3">
                        <h2 className="text-xs font-mono font-bold tracking-widest uppercase text-text-muted flex items-center gap-2">
                            <span className="inline-block h-2 w-2 rounded-full bg-accent-cyan" />
                            Recent Findings
                        </h2>
                    </div>
                    {findingsLoading && findings.length === 0 ? (
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            {Array.from({ length: 3 }).map((_, idx) => (
                                <div
                                    key={idx}
                                    className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/5 backdrop-blur-xl p-4 shadow-[0_14px_50px_rgba(15,23,42,0.9)]"
                                >
                                    <div className="absolute inset-0 bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.25),transparent)] bg-[length:200%_100%] animate-[shimmer_2.5s_linear_infinite] opacity-40" />
                                    <div className="relative space-y-3">
                                        <div className="h-4 w-24 bg-white/12 rounded-full" />
                                        <div className="h-3 w-40 bg-white/8 rounded-full" />
                                        <div className="h-3 w-28 bg-white/6 rounded-full" />
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : findings.length === 0 ? (
                        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/4 backdrop-blur-xl p-4 text-xs text-text-muted flex items-center justify-between shadow-[0_10px_40px_rgba(15,23,42,0.9)]">
                            <span>No structured findings reported yet. Run or complete a scan to see highlights here.</span>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            {findings.slice(0, 6).map((finding) => {
                                const { severity } = finding
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

                                return (
                                    <Link
                                        key={finding.id}
                                        to={`/flow/${finding.flowId}`}
                                        className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/5 backdrop-blur-xl p-4 shadow-[0_14px_50px_rgba(15,23,42,0.9)] hover:border-accent-cyan/50 hover:shadow-[0_0_30px_rgba(0,212,255,0.4)] transition-all"
                                    >
                                        <div className="flex items-center justify-between mb-2 gap-2">
                                            <span
                                                className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest ${badgeClasses}`}
                                            >
                                                {severity}
                                            </span>
                                            <span className="text-[10px] font-mono text-text-muted truncate max-w-[120px]">
                                                {finding.flowName}
                                            </span>
                                        </div>
                                        <div className="text-sm font-semibold text-text-primary mb-1 truncate">{finding.title}</div>
                                        <div className="text-[11px] text-text-muted/80 line-clamp-2">
                                            {finding.content.replace(/\*\*Severity\*\*:[^\n]+/i, '').trim()}
                                        </div>
                                    </Link>
                                )
                            })}
                        </div>
                    )}
                </div>
            )}

            {/* Grid Area */}
            {flows.length === 0 ? (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col items-center justify-center min-h-[40vh] p-12 text-center border border-border/50 rounded-2xl bg-card-bg/30 backdrop-blur-sm">
                    <div className="w-20 h-20 bg-[#111827] rounded-full flex items-center justify-center mb-6 shadow-[inset_0_2px_10px_rgba(0,0,0,0.5)] border border-border">
                        <Search className="w-8 h-8 text-text-muted" />
                    </div>
                    <h2 className="text-2xl font-bold text-text-primary mb-3">No active traces detected</h2>
                    <p className="text-text-muted max-w-md mb-8">Deploy your first autonomous agent. Let Mirage handle the complex enumeration, exploitation, and reporting automatically.</p>
                </motion.div>
            ) : (
                <motion.div
                    variants={containerVariants}
                    initial="hidden"
                    animate="visible"
                    className="relative z-10 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 auto-rows-[1fr]"
                >
                    {flows.map((flow) => (
                        <motion.div key={flow.id} variants={itemVariants} className="h-full">
                            <Link to={`/flow/${flow.id}`} className="block h-full group">
                                <div className="h-full relative overflow-hidden rounded-3xl border border-white/15 bg-white/8 backdrop-blur-2xl p-6 shadow-[0_18px_80px_rgba(15,23,42,0.95)] transition-all duration-500 transform hover:-translate-y-1 hover:shadow-[0_0_45px_rgba(0,212,255,0.45)] hover:border-accent-cyan/60">
                                    {/* Glass light streak */}
                                    <div className="pointer-events-none absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500">
                                        <div className="absolute -inset-x-10 -top-10 h-24 bg-gradient-to-br from-white/40 via-white/5 to-transparent blur-2xl mix-blend-screen" />
                                    </div>

                                    <div className="relative z-10 flex flex-col h-full">
                                        <div className="flex justify-between items-start mb-4 gap-4">
                                            <h3 className="text-lg font-bold text-text-primary truncate" title={flow.name}>{flow.name}</h3>
                                            <div className="flex-shrink-0">
                                                <span className={getStatusBadge(flow.status)}>{flow.status}</span>
                                            </div>
                                        </div>

                                        {flow.description && (
                                            <p className="text-sm text-text-muted line-clamp-2 mb-6 flex-grow leading-relaxed">
                                                {flow.description}
                                            </p>
                                        )}

                                        <div className="flex items-center justify-between text-xs text-text-muted/80 mt-auto pt-4 border-t border-border/50">
                                            <div className="flex items-center gap-4">
                                                <div className="flex items-center gap-1.5" title="Target">
                                                    <Target className="w-3.5 h-3.5" />
                                                    <span className="truncate max-w-[100px]">{flow.target}</span>
                                                </div>
                                                <div className="flex items-center gap-1.5" title="Initiated">
                                                    <Clock className="w-3.5 h-3.5" />
                                                    <span>{formatDate(flow.created_at)}</span>
                                                </div>
                                            </div>

                                            <div className="w-8 h-8 rounded-full bg-[#111827] border border-border flex items-center justify-center opacity-0 group-hover:opacity-100 transform translate-x-4 group-hover:translate-x-0 transition-all duration-300">
                                                <ArrowRight className="w-4 h-4 text-accent-cyan" />
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </Link>
                        </motion.div>
                    ))}
                </motion.div>
            )}
        </div>
    )
}

export default Dashboard
