import React, { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Search, Zap, Clock, Activity, Target, ArrowRight, Trash2, X, ExternalLink, ChevronDown, ChevronUp, TrendingUp } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import TrendChart from '../components/TrendChart'
import StatsRow from '../components/StatsRow'
import remarkGfm from 'remark-gfm'

const API_BASE = '/api'

const CHIP_BASE = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

function Dashboard() {
    const [flows, setFlows] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [findings, setFindings] = useState([])
    const [findingsLoading, setFindingsLoading] = useState(false)
    const [statusFilter, setStatusFilter] = useState('all')
    const [findingsFilter, setFindingsFilter] = useState('all')
    const [activeTab, setActiveTab] = useState('scans') // 'scans' or 'findings'
    const [deleteConfirm, setDeleteConfirm] = useState(null)
    const [deleteError, setDeleteError] = useState(null)
    const [selectedFinding, setSelectedFinding] = useState(null)
    const [trendOpen, setTrendOpen] = useState(true)

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
        if (activeTab === 'findings') {
            fetchGlobalFindings()
        }
    }, [activeTab])

    async function fetchGlobalFindings() {
        try {
            setFindingsLoading(true)
            const res = await fetch(`${API_BASE}/findings`)
            if (res.ok) {
                const data = await res.json()
                setFindings(data || [])
            }
        } catch (err) {
            console.error('Failed to fetch findings:', err)
        } finally {
            setFindingsLoading(false)
        }
    }

    function openDeleteConfirm(flow) {
        setDeleteConfirm({ id: flow.id, status: flow.status, name: flow.name })
    }

    async function confirmDeleteFlow(flowId) {
        if (!flowId) return
        setDeleteConfirm(null)
        setDeleteError(null)
        try {
            const res = await fetch(`${API_BASE}/flows/${flowId}`, { method: 'DELETE' })
            if (res.ok) {
                setFlows((prev) => prev.filter((f) => f.id !== flowId))
                setFindings((prev) => prev.filter((f) => f.flowId !== flowId))
            } else {
                const text = await res.text()
                setDeleteError(text || 'Failed to delete flow.')
                setTimeout(() => setDeleteError(null), 5000)
            }
        } catch (err) {
            console.error('Failed to delete flow:', err)
            setDeleteError('Failed to delete flow: ' + (err.message || 'network error'))
            setTimeout(() => setDeleteError(null), 5000)
        }
    }

    function getStatusBadge(status) {
        const baseClasses = `${CHIP_BASE} px-3 gap-1.5 backdrop-blur-sm shadow-sm`
        switch (status) {
            case 'completed':
                return `${baseClasses} bg-accent-green/10 text-accent-green border-accent-green/30`
            case 'active':
                // Active but not yet completed - blue/cyan without pulse
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

    const filters = ['all', 'running', 'active', 'completed', 'failed']

    const statusCounts = flows.reduce(
        (acc, flow) => {
            const s = (flow.status || '').toLowerCase()
            if (s === 'running') acc.running++
            else if (s === 'active') acc.active++
            else if (s === 'completed') acc.completed++
            else if (s === 'failed') acc.failed++
            return acc
        },
        { all: flows.length, running: 0, active: 0, completed: 0, failed: 0 }
    )

    const filteredFlows = statusFilter === 'all'
        ? flows
        : flows.filter((flow) => (flow.status || '').toLowerCase() === statusFilter)

    const severities = ['all', 'critical', 'high', 'medium', 'low', 'info']

    const filteredFindings = findingsFilter === 'all'
        ? findings
        : findings.filter((f) => f.severity === findingsFilter)

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
            {/* In-UI error toast (replaces window.alert) */}
            {deleteError && (
                <div className="fixed top-4 right-4 z-[150] flex items-center gap-3 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400 font-mono shadow-xl backdrop-blur-sm max-w-sm">
                    <span className="flex-1">{deleteError}</span>
                    <button type="button" onClick={() => setDeleteError(null)} className="text-red-400/60 hover:text-red-400 transition-colors">
                        <X className="w-4 h-4" />
                    </button>
                </div>
            )}

            {/* Delete confirmation modal - in-app so it can't be closed by navigation */}
            {deleteConfirm && (
                <div
                    className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
                    onClick={() => setDeleteConfirm(null)}
                    role="dialog"
                    aria-modal="true"
                >
                    <div
                        className="relative rounded-2xl border border-white/20 bg-[#0f172a] p-6 shadow-2xl max-w-sm w-full"
                        onClick={(e) => e.stopPropagation()}
                        onMouseDown={(e) => e.stopPropagation()}
                    >
                        <h3 className="text-lg font-bold text-text-primary mb-2">Delete flow?</h3>
                        <p className="text-sm text-text-muted mb-4">
                            {deleteConfirm.status === 'active' || deleteConfirm.status === 'running'
                                ? 'This flow is still running. It will be stopped, then deleted.'
                                : 'This cannot be undone.'}
                        </p>
                        <p className="text-xs font-mono text-text-muted truncate mb-6" title={deleteConfirm.name}>
                            {deleteConfirm.name}
                        </p>
                        <div className="flex gap-3 justify-end">
                            <button
                                type="button"
                                onClick={(e) => { e.stopPropagation(); setDeleteConfirm(null); }}
                                className="px-4 py-2 rounded-lg text-sm font-medium text-text-primary bg-white/10 border border-white/20 hover:bg-white/15"
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={(e) => {
                                    e.preventDefault()
                                    e.stopPropagation()
                                    confirmDeleteFlow(deleteConfirm.id)
                                }}
                                className="px-4 py-2 rounded-lg text-sm font-medium text-white bg-accent-red border border-accent-red hover:opacity-90"
                            >
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Ambient background glow & blobs */}
            <div className="pointer-events-none absolute inset-0 -z-10">
                <div className="absolute inset-x-0 -top-32 h-64 bg-[radial-gradient(circle_at_top,_rgba(0,212,255,0.18),transparent_65%)] opacity-70" />
                <div className="absolute -top-40 -left-32 w-[40rem] h-[40rem] bg-accent-cyan/18 rounded-full blur-3xl animate-float" />
                <div className="absolute top-24 -right-40 w-[36rem] h-[36rem] bg-accent-purple/18 rounded-full blur-3xl animate-float" />
            </div>

            {/* Hero / Header Area */}
            <div className="mb-10 relative z-10">
                <div className="lg-surface-hero lg-halo-cyan px-7 py-8 md:px-10 md:py-10">
                    <div className="absolute -right-28 -top-28 h-72 w-72 bg-accent-cyan/25 blur-3xl opacity-70 pointer-events-none" />
                    <div className="absolute -left-28 -bottom-28 h-72 w-72 bg-accent-purple/25 blur-3xl opacity-60 pointer-events-none" />

                    <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                        <motion.div
                            initial={{ opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.35, ease: [0.2, 0.8, 0.2, 1] }}
                        >
                            <div className="inline-flex items-center gap-2 lg-pill mb-4 text-[10px] uppercase tracking-[0.22em] font-semibold">
                                <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-pulse" />
                                {activeTab === 'scans' ? 'Live Operations' : 'Threat Intelligence'}
                            </div>
                            <h1 className="text-4xl md:text-5xl lg:text-[56px] font-display font-semibold mb-3 tracking-[-0.02em] leading-[1.05] lg-gradient-text">
                                {activeTab === 'scans' ? 'Active Scans' : 'Global Findings'}
                            </h1>
                            <p className="text-sm md:text-base text-text-secondary flex items-center gap-2">
                                <Activity className="w-4 h-4 text-accent-cyan" />
                                {activeTab === 'scans'
                                    ? `Monitoring ${flows.length} autonomous penetration test${flows.length !== 1 ? 's' : ''}`
                                    : `Tracking ${findings.length} total discovered vulnerabilit${findings.length !== 1 ? 'ies' : 'y'}`}
                            </p>
                        </motion.div>
                        <motion.div
                            initial={{ opacity: 0, scale: 0.96 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ delay: 0.1, duration: 0.35, ease: [0.2, 0.8, 0.2, 1] }}
                        >
                            <Link to="/new" className="lg-btn cta-breathe text-[15px] px-6 py-3.5">
                                <Zap className="w-4 h-4 relative z-10" />
                                <span className="relative z-10 font-semibold tracking-wide">Initiate New Attack</span>
                            </Link>
                        </motion.div>
                    </div>
                </div>
            </div>

            {/* Stats Row */}
            <div className="relative z-10">
                <StatsRow flows={flows} findings={findings} />
            </div>

            {/* Top Level Tabs */}
            <div className="mb-8 relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div className="relative flex bg-white/[0.04] backdrop-blur-xl rounded-2xl p-1 border border-white/[0.08] shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
                    {['scans', 'findings'].map((tab) => {
                        const isActive = activeTab === tab
                        const label = tab === 'scans' ? 'Active Scans' : 'Global Findings'
                        const accent = tab === 'scans' ? 'text-accent-cyan' : 'text-accent-purple'
                        return (
                            <button
                                key={tab}
                                onClick={() => setActiveTab(tab)}
                                className={`relative px-6 py-2.5 rounded-xl text-sm font-semibold transition-colors duration-200 ${
                                    isActive ? accent : 'text-text-muted hover:text-text-primary'
                                }`}
                            >
                                {isActive && (
                                    <motion.span
                                        layoutId="dashboard-tab-active"
                                        transition={{ type: 'spring', stiffness: 420, damping: 32 }}
                                        className={`absolute inset-0 rounded-xl ${
                                            tab === 'scans'
                                                ? 'bg-accent-cyan/15 border border-accent-cyan/30 shadow-[0_0_24px_rgba(34,211,238,0.25),inset_0_1px_0_rgba(255,255,255,0.14)]'
                                                : 'bg-accent-purple/15 border border-accent-purple/30 shadow-[0_0_24px_rgba(167,139,250,0.25),inset_0_1px_0_rgba(255,255,255,0.14)]'
                                        }`}
                                    />
                                )}
                                <span className="relative z-10 flex items-center">
                                    {label}
                                    {tab === 'findings' && findings.length > 0 && (
                                        <span className="ml-2 inline-flex items-center justify-center px-1.5 py-0.5 rounded-full bg-accent-purple/25 text-[10px] text-accent-purple border border-accent-purple/30">
                                            {findings.length}
                                        </span>
                                    )}
                                </span>
                            </button>
                        )
                    })}
                </div>

                {/* Status Filter Bar for Scans */}
                {activeTab === 'scans' && flows.length > 0 && (
                    <div className="relative inline-flex items-center rounded-full bg-white/5 border border-white/10 p-0.5 text-[11px] font-mono overflow-hidden min-w-[260px]">
                        <div
                            className="absolute inset-y-0 left-0 rounded-full bg-accent-cyan shadow-[0_0_12px_rgba(0,212,255,0.6)] transition-transform duration-500 ease-out"
                            style={{
                                width: `${100 / filters.length}%`,
                                transform: `translateX(${filters.indexOf(statusFilter) * 100}%)`,
                            }}
                        />
                        {filters.map((key) => (
                            <button
                                key={key}
                                type="button"
                                onClick={() => setStatusFilter(key)}
                                className={`relative z-10 flex-1 px-3 py-1 rounded-full uppercase tracking-[0.16em] text-center transition-colors duration-200 ${statusFilter === key ? 'text-primary-bg' : 'text-text-muted hover:text-text-primary'
                                    }`}
                            >
                                {key}{' '}
                                <span className="ml-1 text-[10px] text-text-muted/80">
                                    ({statusCounts[key] || 0})
                                </span>
                            </button>
                        ))}
                    </div>
                )}

                {/* Status Filter Bar for Findings */}
                {activeTab === 'findings' && findings.length > 0 && (
                    <div className="relative inline-flex flex-wrap items-center rounded-2xl bg-white/5 border border-white/10 p-1 text-[11px] font-mono">
                        {severities.map((key) => {
                            const count = key === 'all' ? findings.length : findings.filter(f => f.severity === key).length;
                            return (
                                <button
                                    key={key}
                                    type="button"
                                    onClick={() => setFindingsFilter(key)}
                                    className={`relative z-10 px-3 py-1.5 rounded-xl uppercase tracking-[0.1em] text-center transition-colors duration-200 ${findingsFilter === key ? 'bg-white/10 text-white' : 'text-text-muted hover:text-text-primary hover:bg-white/5'
                                        }`}
                                >
                                    {key} <span className="opacity-50 ml-1">({count})</span>
                                </button>
                            )
                        })}
                    </div>
                )}
            </div>

            {activeTab === 'findings' ? (
                // Findings View
                <div className="relative z-10">
                    {findingsLoading ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            {Array.from({ length: 9 }).map((_, idx) => (
                                <div key={idx} className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/5 backdrop-blur-xl p-5 shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                                    <div className="absolute inset-0 bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.25),transparent)] bg-[length:200%_100%] animate-[shimmer_2.5s_linear_infinite] opacity-40" />
                                    <div className="h-4 w-24 bg-white/12 rounded-full mb-4" />
                                    <div className="space-y-3">
                                        <div className="h-4 w-3/4 bg-white/8 rounded-full" />
                                        <div className="h-3 w-full bg-white/6 rounded-full" />
                                        <div className="h-3 w-5/6 bg-white/6 rounded-full" />
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : filteredFindings.length === 0 ? (
                        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col items-center justify-center min-h-[40vh] p-12 text-center border border-border/50 rounded-2xl bg-card-bg/30 backdrop-blur-sm">
                            <div className="w-20 h-20 bg-[#111827] rounded-full flex items-center justify-center mb-6 shadow-[inset_0_2px_10px_rgba(0,0,0,0.5)] border border-border">
                                <Activity className="w-8 h-8 text-text-muted" />
                            </div>
                            <h2 className="text-2xl font-bold text-text-primary mb-3">No findings matching your criteria</h2>
                            <p className="text-text-muted max-w-md mb-8">Try adjusting your filters or initiate a new scan to discover vulnerabilities.</p>
                        </motion.div>
                    ) : (
                        <motion.div variants={containerVariants} initial="hidden" animate="visible" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 auto-rows-[1fr]">
                            {filteredFindings.map((finding) => {
                                const { severity } = finding
                                const severityClasses =
                                    severity === 'critical' ? 'bg-[#ff4757]/15 text-[#ff4757] border-[#ff4757]/40 shadow-[0_0_15px_rgba(255,71,87,0.15)]'
                                        : severity === 'high' ? 'bg-[#ff7f50]/15 text-[#ff7f50] border-[#ff7f50]/40 shadow-[0_0_15px_rgba(255,127,80,0.15)]'
                                            : severity === 'medium' ? 'bg-[#eccc68]/15 text-[#eccc68] border-[#eccc68]/40 shadow-[0_0_15px_rgba(236,204,104,0.15)]'
                                                : severity === 'low' ? 'bg-[#2ed573]/15 text-[#2ed573] border-[#2ed573]/40 shadow-[0_0_15px_rgba(46,213,115,0.15)]'
                                                    : 'bg-accent-cyan/15 text-accent-cyan border-accent-cyan/40 shadow-[0_0_15px_rgba(0,212,255,0.15)]'

                                return (
                                    <motion.div key={finding.id} variants={itemVariants}>
                                        <div
                                            onClick={() => setSelectedFinding(finding)}
                                            className="lg-surface lg-hover block h-full relative cursor-pointer p-6 group"
                                        >
                                            <div className="flex items-center justify-between mb-4 gap-2">
                                                <span className={`${CHIP_BASE} ${severityClasses} px-3 py-1 text-xs`}>
                                                    {severity}
                                                </span>
                                                <div className="flex items-center gap-1.5 text-text-muted bg-white/5 rounded-full px-2.5 py-1 text-xs" title="Target">
                                                    <Target className="w-3 h-3" />
                                                    <span className="truncate max-w-[150px] font-mono">{finding.target || finding.flowName}</span>
                                                </div>
                                            </div>
                                            <h3 className="text-lg font-bold text-text-primary mb-3 line-clamp-2">{finding.title}</h3>
                                            <div className="text-sm font-mono text-text-muted/80 line-clamp-4 leading-relaxed whitespace-pre-wrap">
                                                {finding.content.replace(/\*\*Severity\*\*:[^\n]+/i, '').trim()}
                                            </div>
                                            <div className="flex items-center justify-between mt-6 pt-4 border-t border-white/5 text-xs text-text-muted">
                                                <div className="flex items-center gap-1.5" title="Discovered At">
                                                    <Clock className="w-3.5 h-3.5" />
                                                    <span>{formatDate(finding.timestamp)}</span>
                                                </div>
                                                <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity text-accent-purple">
                                                    <span>Read Report</span>
                                                    <ArrowRight className="w-3 h-3" />
                                                </div>
                                            </div>
                                        </div>
                                    </motion.div>
                                )
                            })}
                        </motion.div>
                    )}
                </div>

            ) : (
                // Scans View
                <>
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
                            {filteredFlows.map((flow) => (
                                <motion.div key={flow.id} variants={itemVariants} className="h-full relative">
                                    <div className="lg-surface lg-hover h-full relative p-6 group">
                                        {/* Delete button outside Link so click never triggers navigation */}
                                        <button
                                            type="button"
                                            title="Delete flow"
                                            onMouseDown={(e) => {
                                                e.preventDefault()
                                                e.stopPropagation()
                                            }}
                                            onClick={(e) => {
                                                e.preventDefault()
                                                e.stopPropagation()
                                                openDeleteConfirm(flow)
                                            }}
                                            className="absolute top-5 right-5 z-20 inline-flex items-center justify-center w-7 h-7 rounded-full border border-white/15 bg-white/5 text-text-muted hover:text-accent-red hover:border-accent-red/60 hover:bg-accent-red/10 transition-colors"
                                        >
                                            <Trash2 className="w-3.5 h-3.5" />
                                        </button>

                                        <Link to={`/flow/${flow.id}`} className="block h-full group/link">
                                            {/* Glass light streak */}
                                            <div className="pointer-events-none absolute inset-0 opacity-0 group-hover/link:opacity-100 transition-opacity duration-500">
                                                <div className="absolute -inset-x-10 -top-10 h-24 bg-gradient-to-br from-white/40 via-white/5 to-transparent blur-2xl mix-blend-screen" />
                                            </div>

                                            <div className="relative z-10 flex flex-col h-full">
                                                <div className="flex justify-between items-start mb-4 gap-4 pr-10">
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

                                                <div className="flex items-center justify-between mt-auto">
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

                                                    <div className="w-8 h-8 rounded-full bg-[#111827] border border-border flex items-center justify-center opacity-0 group-hover/link:opacity-100 transform translate-x-4 group-hover/link:translate-x-0 transition-all duration-300">
                                                        <ArrowRight className="w-4 h-4 text-accent-cyan" />
                                                    </div>
                                                </div>
                                            </div>
                                        </Link>
                                    </div>
                                </motion.div>
                            ))}
                        </motion.div>
                    )}
                </>
            )}

            {/* Scan Trends Section */}
            {activeTab === 'scans' && flows.length > 0 && (
                <div className="relative z-10 mt-8">
                    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                        <button
                            type="button"
                            onClick={() => setTrendOpen((o) => !o)}
                            className="w-full flex items-center justify-between px-5 py-4 text-sm font-semibold text-text-muted hover:text-text-primary transition-colors"
                        >
                            <div className="flex items-center gap-2">
                                <TrendingUp className="w-4 h-4 text-accent-cyan" />
                                <span className="uppercase tracking-widest text-[11px] font-mono font-bold text-text-muted">Scan Trends</span>
                            </div>
                            {trendOpen ? (
                                <ChevronUp className="w-4 h-4 text-text-muted/60" />
                            ) : (
                                <ChevronDown className="w-4 h-4 text-text-muted/60" />
                            )}
                        </button>
                        {trendOpen && (
                            <div className="px-5 pb-5 border-t border-white/8">
                                <p className="text-[10px] font-mono text-text-muted/50 mt-3 mb-3 uppercase tracking-wider">
                                    Findings per scan · last {Math.min(flows.length, 10)} scans · colored by max severity
                                </p>
                                <TrendChart flows={flows} />
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Finding Detail Modal */}
            {selectedFinding && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6 overflow-hidden">
                    <div
                        className="absolute inset-0 bg-[#0f172a]/80 backdrop-blur-sm"
                        onClick={() => setSelectedFinding(null)}
                    />
                    <div
                        className="relative w-full max-w-4xl max-h-[90vh] flex flex-col rounded-3xl border border-white/15 bg-[#0b1121] shadow-[0_20px_80px_rgba(0,0,0,0.8)] overflow-hidden"
                    >
                        {/* Header */}
                        <div className="flex-shrink-0 flex items-start justify-between p-6 border-b border-white/10 bg-white/5 relative">
                            {/* Glow behind title */}
                            <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(ellipse_at_top_left,_rgba(168,85,247,0.15),transparent_50%)] pointer-events-none" />

                            <div className="relative pr-8">
                                <div className="flex items-center gap-3 mb-3">
                                    <span className={`${CHIP_BASE} ${selectedFinding.severity === 'critical' ? 'bg-[#ff4757]/15 text-[#ff4757] border-[#ff4757]/40'
                                        : selectedFinding.severity === 'high' ? 'bg-[#ff7f50]/15 text-[#ff7f50] border-[#ff7f50]/40'
                                            : selectedFinding.severity === 'medium' ? 'bg-[#eccc68]/15 text-[#eccc68] border-[#eccc68]/40'
                                                : selectedFinding.severity === 'low' ? 'bg-[#2ed573]/15 text-[#2ed573] border-[#2ed573]/40'
                                                    : 'bg-accent-cyan/15 text-accent-cyan border-accent-cyan/40'
                                        } px-3 py-1 text-xs shadow-sm`}>
                                        {selectedFinding.severity}
                                    </span>
                                    <div className="flex items-center gap-1.5 text-text-muted bg-white/5 rounded-full px-3 py-1 text-xs border border-white/5">
                                        <Target className="w-3.5 h-3.5" />
                                        <span className="font-mono">{selectedFinding.target || selectedFinding.flowName}</span>
                                    </div>
                                    <div className="flex items-center gap-1.5 text-text-muted bg-white/5 rounded-full px-3 py-1 text-xs border border-white/5">
                                        <Clock className="w-3.5 h-3.5" />
                                        <span>{formatDate(selectedFinding.timestamp)}</span>
                                    </div>
                                </div>
                                <h2 className="text-2xl font-bold text-text-primary leading-tight">
                                    {selectedFinding.title}
                                </h2>
                            </div>

                            <button
                                onClick={() => setSelectedFinding(null)}
                                className="absolute top-6 right-6 p-2 rounded-full hover:bg-white/10 text-text-muted hover:text-white transition-colors"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        {/* Body - Scrollable Markdown */}
                        <div className="flex-grow overflow-y-auto p-6 md:p-8 custom-scrollbar relative bg-[#0f172a]/50">
                            <div className="prose prose-invert prose-sm md:prose-base max-w-none text-text-muted leading-relaxed">
                                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                    {selectedFinding.content.replace(/\*\*Severity\*\*:[^\n]+/i, '').trim()}
                                </ReactMarkdown>

                                {selectedFinding.metadata?.screenshot && (
                                    <div className="mt-8 rounded-2xl overflow-hidden border border-white/10 shadow-2xl">
                                        <div className="bg-white/5 px-4 py-2 text-[10px] uppercase tracking-widest font-bold border-b border-white/10 flex items-center justify-between">
                                            <span className="flex items-center gap-2">
                                                <Activity className="w-3.5 h-3.5 text-accent-green" />
                                                Visual Evidence (Chromedp Captured)
                                            </span>
                                            <span className="text-accent-cyan tracking-[0.2em] animate-pulse">PHOENIX VALIDATED</span>
                                        </div>
                                        <img
                                            src={`/screenshots/${selectedFinding.metadata.screenshot}`}
                                            alt="Finding Screenshot"
                                            className="w-full h-auto cursor-zoom-in hover:scale-[1.01] transition-transform duration-500"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                window.open(`/screenshots/${selectedFinding.metadata.screenshot}`, '_blank');
                                            }}
                                        />
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Footer */}
                        <div className="flex-shrink-0 p-5 border-t border-white/10 bg-white/5 flex items-center justify-between">
                            <span className="text-xs text-text-muted">
                                Originated from scan flow: <span className="font-mono text-white/70">{selectedFinding.flowId.split('-')[0]}...</span>
                            </span>
                            <Link
                                to={`/flow/${selectedFinding.flowId}`}
                                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full bg-accent-purple text-white text-sm font-semibold hover:bg-accent-purple/90 transition-colors shadow-[0_0_20px_rgba(168,85,247,0.4)]"
                            >
                                View Context inside Flow
                                <ExternalLink className="w-4 h-4" />
                            </Link>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}

export default Dashboard
