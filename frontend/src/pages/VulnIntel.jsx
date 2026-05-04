import React, { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Search, Download, RefreshCw, Loader, Filter,
    AlertTriangle, ShieldOff, ChevronLeft, ChevronRight,
    BarChart2, TrendingUp, Target, X,
} from 'lucide-react'

// ── constants ─────────────────────────────────────────────────────────────────

const SEV = {
    critical: { label: 'Critical', color: '#ff4444', bg: 'rgba(255,68,68,0.12)' },
    high:     { label: 'High',     color: '#ff8800', bg: 'rgba(255,136,0,0.12)' },
    medium:   { label: 'Medium',   color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
    low:      { label: 'Low',      color: '#22d3ee', bg: 'rgba(34,211,238,0.12)' },
    info:     { label: 'Info',     color: '#6b7280', bg: 'rgba(107,114,128,0.12)' },
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

// ── small components ──────────────────────────────────────────────────────────

function SevBadge({ sev }) {
    const m = SEV[sev] ?? SEV.info
    return (
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider"
            style={{ color: m.color, backgroundColor: m.bg, border: `1px solid ${m.color}30` }}>
            {m.label}
        </span>
    )
}

// Horizontal bar (CSS width trick, no SVG)
function SevBar({ counts, total }) {
    return (
        <div className="space-y-3">
            {SEV_ORDER.map(s => {
                const n = counts[s] ?? 0
                const pct = total > 0 ? (n / total) * 100 : 0
                const m = SEV[s]
                return (
                    <div key={s} className="flex items-center gap-3">
                        <div className="w-16 text-[11px] font-medium text-right flex-shrink-0" style={{ color: m.color }}>{m.label}</div>
                        <div className="flex-1 h-2 rounded-full bg-white/[0.06] overflow-hidden">
                            <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${pct}%` }}
                                transition={{ duration: 0.7, ease: 'easeOut' }}
                                className="h-full rounded-full"
                                style={{ backgroundColor: m.color }}
                            />
                        </div>
                        <div className="w-8 text-[11px] text-text-muted font-mono text-right">{n}</div>
                    </div>
                )
            })}
        </div>
    )
}

// 30-day sparkline trend
function TrendChart({ trend }) {
    const max = Math.max(...trend.map(d => d.count), 1)
    const W = 320, H = 60, PAD = 4
    const pts = trend.map((d, i) => {
        const x = PAD + (i / (trend.length - 1)) * (W - PAD * 2)
        const y = H - PAD - (d.count / max) * (H - PAD * 2)
        return `${x},${y}`
    }).join(' ')
    const area = `M${PAD},${H} ` + trend.map((d, i) => {
        const x = PAD + (i / (trend.length - 1)) * (W - PAD * 2)
        const y = H - PAD - (d.count / max) * (H - PAD * 2)
        return `L${x},${y}`
    }).join(' ') + ` L${W - PAD},${H} Z`

    return (
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: 60 }}>
            <defs>
                <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.3" />
                    <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
                </linearGradient>
            </defs>
            <path d={area} fill="url(#trendGrad)" />
            <polyline points={pts} fill="none" stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
    )
}

// Donut-style severity mini chart
function SevDonut({ counts }) {
    const total = SEV_ORDER.reduce((s, k) => s + (counts[k] ?? 0), 0)
    if (total === 0) return (
        <div className="w-20 h-20 rounded-full border-4 border-white/[0.06] flex items-center justify-center">
            <span className="text-[10px] text-text-muted">—</span>
        </div>
    )
    const R = 30, C = 40, stroke = 8
    const circ = 2 * Math.PI * R
    let offset = 0
    const arcs = SEV_ORDER.map(s => {
        const n = counts[s] ?? 0
        const frac = n / total
        const dash = frac * circ
        const arc = { s, dash, offset, color: SEV[s].color }
        offset += dash
        return arc
    })
    return (
        <div className="relative">
            <svg width={C * 2} height={C * 2} viewBox={`0 0 ${C * 2} ${C * 2}`} style={{ transform: 'rotate(-90deg)' }}>
                {arcs.map(({ s, dash, offset: off, color }) => (
                    <circle key={s} cx={C} cy={C} r={R}
                        fill="none" stroke={color} strokeWidth={stroke}
                        strokeDasharray={`${dash} ${circ - dash}`}
                        strokeDashoffset={-off}
                        opacity="0.85"
                    />
                ))}
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-[16px] font-bold text-text-primary">{total}</span>
                <span className="text-[9px] text-text-muted font-mono uppercase">total</span>
            </div>
        </div>
    )
}

// ── finding row ───────────────────────────────────────────────────────────────

function FindingRow({ f, idx }) {
    const [open, setOpen] = useState(false)
    return (
        <>
            <tr
                className={`border-b border-white/[0.04] hover:bg-white/[0.025] transition-colors cursor-pointer ${idx % 2 === 0 ? '' : 'bg-white/[0.01]'}`}
                onClick={() => setOpen(o => !o)}
            >
                <td className="px-4 py-3"><SevBadge sev={f.severity} /></td>
                <td className="px-4 py-3 text-[13px] text-text-primary font-medium max-w-[240px] truncate">{f.title}</td>
                <td className="px-4 py-3 text-[12px] text-text-muted font-mono max-w-[180px] truncate">{f.target}</td>
                <td className="px-4 py-3 text-[12px] text-text-muted truncate max-w-[140px]">{f.flowName}</td>
                <td className="px-4 py-3 text-[11px] text-text-muted font-mono whitespace-nowrap">
                    {new Date(f.timestamp).toLocaleDateString()}
                </td>
            </tr>
            <AnimatePresence>
                {open && (
                    <tr>
                        <td colSpan={5} className="px-4 pb-4">
                            <motion.div
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                                className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-4 overflow-hidden"
                            >
                                <pre className="text-[12px] text-text-secondary whitespace-pre-wrap font-mono leading-relaxed max-h-48 overflow-y-auto">{f.content}</pre>
                            </motion.div>
                        </td>
                    </tr>
                )}
            </AnimatePresence>
        </>
    )
}

// ── main page ─────────────────────────────────────────────────────────────────

export default function VulnIntel() {
    const [stats, setStats] = useState(null)
    const [findings, setFindings] = useState([])
    const [total, setTotal] = useState(0)
    const [pages, setPages] = useState(1)
    const [page, setPage] = useState(1)
    const [loading, setLoading] = useState(true)
    const [searching, setSearching] = useState(false)

    // filters
    const [q, setQ] = useState('')
    const [sevFilter, setSevFilter] = useState('')
    const [targetFilter, setTargetFilter] = useState('')
    const debounceRef = useRef(null)

    const loadStats = useCallback(async () => {
        try {
            const r = await fetch('/api/findings/stats').then(r => r.json())
            setStats(r)
        } catch { /* silent */ }
    }, [])

    const loadFindings = useCallback(async (p = 1) => {
        setSearching(true)
        try {
            const params = new URLSearchParams({ page: p, limit: 50 })
            if (q) params.set('q', q)
            if (sevFilter) params.set('severity', sevFilter)
            if (targetFilter) params.set('target', targetFilter)
            const r = await fetch(`/api/findings/search?${params}`).then(r => r.json())
            setFindings(r.findings ?? [])
            setTotal(r.total ?? 0)
            setPages(r.pages ?? 1)
        } catch { /* silent */ } finally {
            setSearching(false)
            setLoading(false)
        }
    }, [q, sevFilter, targetFilter])

    useEffect(() => { loadStats() }, [loadStats])

    useEffect(() => {
        clearTimeout(debounceRef.current)
        debounceRef.current = setTimeout(() => { setPage(1); loadFindings(1) }, 280)
        return () => clearTimeout(debounceRef.current)
    }, [loadFindings])

    useEffect(() => { loadFindings(page) }, [page]) // eslint-disable-line react-hooks/exhaustive-deps

    function handleExport() {
        window.location.href = '/api/findings/export'
    }

    function clearFilters() {
        setQ(''); setSevFilter(''); setTargetFilter('')
    }

    const hasFilters = q || sevFilter || targetFilter

    return (
        <div className="px-6 py-8 max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex items-start justify-between mb-8">
                <div>
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-9 h-9 rounded-xl bg-red-500/15 border border-red-500/20 flex items-center justify-center">
                            <ShieldOff className="w-[18px] h-[18px] text-red-400" />
                        </div>
                        <h1 className="text-[22px] font-semibold" style={{ background: 'linear-gradient(135deg, #ff6b6b, #ff4444)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                            Vulnerability Intelligence
                        </h1>
                    </div>
                    <p className="text-[13px] text-text-muted ml-12">
                        Cross-scan analytics, trend tracking, and searchable finding database
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <button type="button" onClick={() => { loadStats(); loadFindings(page) }}
                        className="p-2 rounded-xl text-text-muted hover:text-text-primary hover:bg-white/[0.06] transition-all">
                        <RefreshCw className="w-4 h-4" />
                    </button>
                    <button type="button" onClick={handleExport}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl text-[13px] font-medium bg-white/[0.05] border border-white/10 text-text-secondary hover:text-text-primary hover:border-white/20 transition-all">
                        <Download className="w-4 h-4" /> Export CSV
                    </button>
                </div>
            </div>

            {/* Top analytics row */}
            {stats && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                    {/* Severity overview */}
                    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6">
                        <div className="flex items-center justify-between mb-5">
                            <p className="text-[11px] font-mono uppercase tracking-widest text-text-muted flex items-center gap-2">
                                <BarChart2 className="w-3.5 h-3.5 text-red-400" /> Severity Breakdown
                            </p>
                            <SevDonut counts={stats.by_severity} />
                        </div>
                        <SevBar counts={stats.by_severity} total={stats.total} />
                    </div>

                    {/* Trend */}
                    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6">
                        <p className="text-[11px] font-mono uppercase tracking-widest text-text-muted flex items-center gap-2 mb-4">
                            <TrendingUp className="w-3.5 h-3.5 text-accent-cyan" /> 30-Day Finding Trend
                        </p>
                        {stats.trend?.length > 0
                            ? <TrendChart trend={stats.trend} />
                            : <div className="h-16 flex items-center justify-center text-[12px] text-text-muted">No trend data yet</div>
                        }
                        <div className="flex justify-between mt-2 text-[10px] text-text-muted font-mono">
                            <span>{stats.trend?.[0]?.date ?? '—'}</span>
                            <span>{stats.trend?.[stats.trend.length - 1]?.date ?? '—'}</span>
                        </div>
                    </div>

                    {/* Top types + targets */}
                    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6">
                        <p className="text-[11px] font-mono uppercase tracking-widest text-text-muted flex items-center gap-2 mb-4">
                            <Target className="w-3.5 h-3.5 text-accent-purple" /> Top Finding Types
                        </p>
                        <div className="space-y-2">
                            {(stats.top_types ?? []).slice(0, 7).map((t, i) => (
                                <div key={t.name} className="flex items-center gap-2">
                                    <span className="text-[10px] font-mono text-text-muted w-4 text-right">{i + 1}</span>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center justify-between gap-1 mb-0.5">
                                            <span className="text-[11px] text-text-secondary truncate">{t.name}</span>
                                            <span className="text-[11px] font-mono text-text-muted flex-shrink-0">{t.count}</span>
                                        </div>
                                        <div className="h-1 rounded-full bg-white/[0.06] overflow-hidden">
                                            <motion.div
                                                initial={{ width: 0 }}
                                                animate={{ width: `${(t.count / (stats.top_types?.[0]?.count ?? 1)) * 100}%` }}
                                                transition={{ duration: 0.6, ease: 'easeOut', delay: i * 0.04 }}
                                                className="h-full rounded-full bg-accent-purple/60"
                                            />
                                        </div>
                                    </div>
                                </div>
                            ))}
                            {(stats.top_types ?? []).length === 0 && (
                                <p className="text-[12px] text-text-muted text-center py-4">No findings yet</p>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Search & filters */}
            <div className="flex flex-wrap items-center gap-3 mb-5">
                <div className="relative flex-1 min-w-[200px]">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
                    <input
                        type="text"
                        value={q}
                        onChange={e => setQ(e.target.value)}
                        placeholder="Search findings…"
                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl pl-9 pr-4 py-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors"
                    />
                </div>

                {/* Severity filter */}
                <div className="flex items-center gap-1.5">
                    {SEV_ORDER.map(s => (
                        <button
                            key={s}
                            type="button"
                            onClick={() => setSevFilter(sevFilter === s ? '' : s)}
                            className={`px-3 py-1.5 rounded-xl text-[11px] font-semibold uppercase tracking-wider border transition-all ${
                                sevFilter === s
                                    ? 'border-opacity-60'
                                    : 'border-white/[0.08] bg-white/[0.02] text-text-muted hover:border-white/20'
                            }`}
                            style={sevFilter === s ? {
                                color: SEV[s].color,
                                backgroundColor: SEV[s].bg,
                                borderColor: SEV[s].color + '60',
                            } : {}}
                        >
                            {SEV[s].label}
                        </button>
                    ))}
                </div>

                {/* Target filter */}
                <div className="relative">
                    <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
                    <input
                        type="text"
                        value={targetFilter}
                        onChange={e => setTargetFilter(e.target.value)}
                        placeholder="Filter by target…"
                        className="bg-white/[0.04] border border-white/10 rounded-xl pl-8 pr-3 py-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors w-44"
                    />
                </div>

                {hasFilters && (
                    <button type="button" onClick={clearFilters}
                        className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-[12px] text-text-muted hover:text-red-400 hover:bg-red-400/10 border border-white/[0.06] transition-all">
                        <X className="w-3 h-3" /> Clear
                    </button>
                )}

                <div className="ml-auto text-[12px] text-text-muted">
                    {searching ? <Loader className="w-3.5 h-3.5 animate-spin" /> : `${total} finding${total !== 1 ? 's' : ''}`}
                </div>
            </div>

            {/* Findings table */}
            <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.02] backdrop-blur-xl">
                {loading ? (
                    <div className="flex items-center justify-center py-20">
                        <Loader className="w-6 h-6 text-accent-cyan animate-spin" />
                    </div>
                ) : findings.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-20 text-center">
                        <AlertTriangle className="w-8 h-8 text-text-muted mb-3" />
                        <p className="text-[14px] font-medium text-text-primary mb-1">
                            {hasFilters ? 'No findings match your filters' : 'No findings yet'}
                        </p>
                        <p className="text-[12px] text-text-muted">
                            {hasFilters ? 'Try adjusting your search or filters.' : 'Run a scan to start collecting findings.'}
                        </p>
                    </div>
                ) : (
                    <>
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="border-b border-white/[0.06]">
                                        {['Severity', 'Title', 'Target', 'Scan', 'Date'].map(h => (
                                            <th key={h} className="px-4 py-3 text-left text-[10px] font-mono uppercase tracking-widest text-text-muted">{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {findings.map((f, i) => <FindingRow key={f.id} f={f} idx={i} />)}
                                </tbody>
                            </table>
                        </div>

                        {/* Pagination */}
                        {pages > 1 && (
                            <div className="flex items-center justify-between px-4 py-3 border-t border-white/[0.06]">
                                <span className="text-[12px] text-text-muted">
                                    Page {page} of {pages} · {total} results
                                </span>
                                <div className="flex items-center gap-2">
                                    <button type="button" disabled={page <= 1} onClick={() => setPage(p => p - 1)}
                                        className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.06] disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                                        <ChevronLeft className="w-4 h-4" />
                                    </button>
                                    {Array.from({ length: Math.min(pages, 7) }, (_, i) => {
                                        const p = Math.max(1, Math.min(pages - 6, page - 3)) + i
                                        return (
                                            <button key={p} type="button" onClick={() => setPage(p)}
                                                className={`w-7 h-7 rounded-lg text-[12px] font-mono transition-all ${
                                                    p === page
                                                        ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30'
                                                        : 'text-text-muted hover:bg-white/[0.06] hover:text-text-primary'
                                                }`}>
                                                {p}
                                            </button>
                                        )
                                    })}
                                    <button type="button" disabled={page >= pages} onClick={() => setPage(p => p + 1)}
                                        className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.06] disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                                        <ChevronRight className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        )}
                    </>
                )}
            </div>
        </div>
    )
}
