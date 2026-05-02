import React, { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import {
    Shield, TrendingUp, TrendingDown, AlertTriangle, CheckCircle,
    Clock, Target, Activity, Zap, RefreshCw, ArrowRight
} from 'lucide-react'

const API_BASE = '/api'

const SEVERITY_COLOR = {
    critical: '#ff4757',
    high:     '#ff7f50',
    medium:   '#eccc68',
    low:      '#2ed573',
    info:     '#67e8f9',
}

const GRADE_CONFIG = {
    A: { color: '#6ee7b7', bg: '#6ee7b712', label: 'Excellent' },
    B: { color: '#67e8f9', bg: '#67e8f912', label: 'Good' },
    C: { color: '#fbbf24', bg: '#fbbf2412', label: 'Fair' },
    D: { color: '#ff7f50', bg: '#ff7f5012', label: 'Poor' },
    F: { color: '#ff4757', bg: '#ff475712', label: 'Critical' },
}

// ── Score Gauge (SVG arc) ────────────────────────────────────────────────────

function ScoreGauge({ score, grade }) {
    const r = 80
    const cx = 110
    const cy = 105
    const strokeW = 12
    // 240° sweep from 210° to 330° (clockwise, bottom-left to bottom-right)
    const sweep = 240
    const startDeg = 210
    const arcLen = (sweep / 360) * (2 * Math.PI * r)

    function polar(deg) {
        const rad = (deg * Math.PI) / 180
        return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) }
    }

    const s = polar(startDeg)
    const e = polar(startDeg + sweep)

    // Track arc (full)
    const trackD = `M ${s.x} ${s.y} A ${r} ${r} 0 1 1 ${e.x} ${e.y}`

    // Fill arc (proportional to score)
    const fillSweep = (score / 100) * sweep
    const fe = polar(startDeg + fillSweep)
    const largeArc = fillSweep > 180 ? 1 : 0
    const fillD = score > 0
        ? `M ${s.x} ${s.y} A ${r} ${r} 0 ${largeArc} 1 ${fe.x} ${fe.y}`
        : null

    const gc = GRADE_CONFIG[grade] || GRADE_CONFIG.F

    return (
        <div className="relative flex flex-col items-center">
            <svg width={220} height={190} className="overflow-visible">
                {/* Track */}
                <path d={trackD} fill="none" stroke="rgba(255,255,255,0.06)"
                    strokeWidth={strokeW} strokeLinecap="round" />
                {/* Glow layer */}
                {fillD && (
                    <path d={fillD} fill="none" stroke={gc.color}
                        strokeWidth={strokeW + 4} strokeLinecap="round" opacity="0.15" />
                )}
                {/* Fill */}
                {fillD && (
                    <path d={fillD} fill="none" stroke={gc.color}
                        strokeWidth={strokeW} strokeLinecap="round" />
                )}
                {/* Score text */}
                <text x={cx} y={cy - 4} textAnchor="middle"
                    className="font-mono font-bold" fill="white"
                    fontSize={42}>{Math.round(score)}</text>
                <text x={cx} y={cy + 18} textAnchor="middle"
                    fill="rgba(148,163,184,0.8)" fontSize={11}>out of 100</text>
                {/* Grade badge */}
                <g transform={`translate(${cx - 20}, ${cy + 34})`}>
                    <rect width={40} height={22} rx={6}
                        fill={gc.bg} stroke={gc.color} strokeWidth={1} strokeOpacity={0.4} />
                    <text x={20} y={15} textAnchor="middle" fill={gc.color}
                        fontSize={13} fontWeight="700" fontFamily="monospace">{grade}</text>
                </g>
                {/* Min/max labels */}
                <text x={s.x - 10} y={s.y + 14} fill="rgba(100,116,139,0.7)" fontSize={9}>0</text>
                <text x={e.x + 2} y={e.y + 14} fill="rgba(100,116,139,0.7)" fontSize={9}>100</text>
            </svg>
            <p className="text-sm font-medium -mt-2" style={{ color: gc.color }}>{gc.label}</p>
        </div>
    )
}

// ── Sparkline ────────────────────────────────────────────────────────────────

function Sparkline({ history }) {
    if (!history || history.length < 2) {
        return <div className="flex items-center justify-center h-16 text-xs text-text-muted">Collecting history…</div>
    }
    const W = 320, H = 64, PAD = 8
    const scores = history.map(h => h.score)
    const minS = Math.min(...scores) - 5
    const maxS = Math.max(...scores) + 5
    const range = maxS - minS || 10

    const pts = scores.map((s, i) => {
        const x = PAD + (i / (scores.length - 1)) * (W - PAD * 2)
        const y = H - PAD - ((s - minS) / range) * (H - PAD * 2)
        return `${x},${y}`
    })
    const polyline = pts.join(' ')
    const last = pts[pts.length - 1].split(',')

    const latest = scores[scores.length - 1]
    const prev = scores[scores.length - 2]
    const delta = latest - prev
    const color = delta >= 0 ? '#6ee7b7' : '#ff4757'

    return (
        <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
                <span className="text-text-muted font-mono">30-day trend</span>
                <span className="flex items-center gap-1 font-mono" style={{ color }}>
                    {delta >= 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                    {delta >= 0 ? '+' : ''}{delta.toFixed(1)}
                </span>
            </div>
            <svg width={W} height={H} className="w-full overflow-visible" viewBox={`0 0 ${W} ${H}`}>
                <defs>
                    <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#67e8f9" stopOpacity="0.2" />
                        <stop offset="100%" stopColor="#67e8f9" stopOpacity="0" />
                    </linearGradient>
                </defs>
                <polygon
                    points={`${PAD},${H - PAD} ${polyline} ${W - PAD},${H - PAD}`}
                    fill="url(#spark-fill)"
                />
                <polyline points={polyline} fill="none" stroke="#67e8f9" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
                <circle cx={parseFloat(last[0])} cy={parseFloat(last[1])} r={3} fill="#67e8f9" />
            </svg>
        </div>
    )
}

// ── Component bar ────────────────────────────────────────────────────────────

function ComponentBar({ label, score, color, weight }) {
    return (
        <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">{label}</span>
                <div className="flex items-center gap-2">
                    <span className="text-[10px] text-text-muted font-mono">{weight}%</span>
                    <span className="font-mono font-semibold" style={{ color }}>{Math.round(score)}</span>
                </div>
            </div>
            <div className="h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
                <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${score}%` }}
                    transition={{ duration: 0.8, ease: 'easeOut' }}
                    className="h-full rounded-full"
                    style={{ background: color }}
                />
            </div>
        </div>
    )
}

// ── OWASP grid ───────────────────────────────────────────────────────────────

function OWASPGrid({ categories }) {
    if (!categories?.length) return null
    return (
        <div className="grid grid-cols-2 gap-2">
            {categories.map(cat => {
                const c = cat.exposed
                    ? (SEVERITY_COLOR[cat.severity] || '#fbbf24')
                    : 'rgba(255,255,255,0.08)'
                const textColor = cat.exposed ? c : 'rgba(100,116,139,0.7)'
                return (
                    <div key={cat.id}
                        className="rounded-xl border px-3 py-2 transition-colors"
                        style={{ borderColor: `${c}30`, background: `${c}0a` }}>
                        <div className="flex items-center gap-1.5 mb-0.5">
                            {cat.exposed
                                ? <AlertTriangle className="w-3 h-3 flex-shrink-0" style={{ color: c }} />
                                : <CheckCircle className="w-3 h-3 flex-shrink-0 text-text-muted opacity-40" />
                            }
                            <span className="text-[9px] font-mono" style={{ color: textColor }}>{cat.id}</span>
                        </div>
                        <p className="text-[11px] leading-tight" style={{ color: cat.exposed ? 'rgba(226,232,240,0.9)' : 'rgba(100,116,139,0.6)' }}>
                            {cat.name}
                        </p>
                    </div>
                )
            })}
        </div>
    )
}

// ── Action item ───────────────────────────────────────────────────────────────

function ActionItem({ action }) {
    const c = SEVERITY_COLOR[action.severity] || '#94a3b8'
    return (
        <div className="flex gap-3 p-3 rounded-xl border transition-colors"
            style={{ borderColor: `${c}20`, background: `${c}08` }}>
            <div className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 text-[10px] font-bold font-mono mt-0.5"
                style={{ background: `${c}20`, color: c }}>{action.priority}</div>
            <div>
                <p className="text-xs font-semibold text-text-primary mb-0.5">{action.title}</p>
                <p className="text-[11px] text-text-muted leading-relaxed">{action.description}</p>
            </div>
        </div>
    )
}

// ── Benchmark row ─────────────────────────────────────────────────────────────

function BenchmarkBar({ label, value, peer, color }) {
    const max = Math.max(value, peer, 100)
    return (
        <div className="space-y-1">
            <div className="flex items-center justify-between text-[11px]">
                <span className="text-text-muted">{label}</span>
                <div className="flex items-center gap-3">
                    <span className="flex items-center gap-1 text-text-muted">
                        <span className="w-2 h-2 rounded-full bg-white/20 inline-block" />
                        Peer avg {peer}
                    </span>
                    <span className="font-mono font-semibold" style={{ color }}>{value}</span>
                </div>
            </div>
            <div className="relative h-2 rounded-full bg-white/[0.05]">
                <motion.div initial={{ width: 0 }} animate={{ width: `${(peer / max) * 100}%` }}
                    transition={{ duration: 0.6 }}
                    className="absolute h-full rounded-full bg-white/15" />
                <motion.div initial={{ width: 0 }} animate={{ width: `${(value / max) * 100}%` }}
                    transition={{ duration: 0.8, ease: 'easeOut' }}
                    className="absolute h-full rounded-full"
                    style={{ background: color }} />
            </div>
        </div>
    )
}

// ── Page root ─────────────────────────────────────────────────────────────────

export default function Posture() {
    const [snap, setSnap] = useState(null)
    const [history, setHistory] = useState([])
    const [loading, setLoading] = useState(true)
    const [lastRefresh, setLastRefresh] = useState(null)

    async function load() {
        setLoading(true)
        try {
            const [snapData, histData] = await Promise.all([
                fetch(`${API_BASE}/posture`).then(r => r.json()),
                fetch(`${API_BASE}/posture/history`).then(r => r.json()).catch(() => ({ history: [] })),
            ])
            setSnap(snapData)
            setHistory(histData.history || [])
            setLastRefresh(new Date())
        } catch (e) {
            console.error(e)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => { load() }, [])

    const gc = snap ? (GRADE_CONFIG[snap.grade] || GRADE_CONFIG.F) : null

    // Peer benchmarks (simulated industry averages for a SaaS company)
    const peerScore = 62
    const peerBenchmarks = [
        { label: 'Posture Score', value: snap?.score ?? 0, peer: peerScore, color: gc?.color || '#67e8f9' },
        { label: 'Remediation Progress', value: Math.round(snap?.components.remediation_progress ?? 0), peer: 55, color: '#c4b5fd' },
        { label: 'SLA Compliance', value: Math.round(snap?.components.sla_health ?? 0), peer: 70, color: '#6ee7b7' },
        { label: 'Monitoring Coverage', value: Math.round(snap?.components.monitoring_coverage ?? 0), peer: 45, color: '#67e8f9' },
    ]

    return (
        <div className="relative pb-12">
            {/* Ambient */}
            <div className="pointer-events-none absolute inset-0 -z-10">
                <div className="absolute -top-40 -left-32 w-[40rem] h-[40rem] bg-accent-cyan/10 rounded-full blur-3xl" />
                <div className="absolute top-24 -right-40 w-[36rem] h-[36rem] bg-accent-purple/10 rounded-full blur-3xl" />
            </div>

            {/* Hero */}
            <div className="mb-8 relative z-10">
                <div className="lg-surface-hero px-7 py-8 md:px-10 md:py-10">
                    <div className="absolute -right-20 -top-20 h-64 w-64 blur-3xl opacity-40 pointer-events-none"
                        style={{ background: `radial-gradient(circle, ${gc?.color || '#67e8f9'}60, transparent 70%)` }} />
                    <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
                            <div className="inline-flex items-center gap-2 lg-pill mb-4 text-[10px] uppercase tracking-[0.22em] font-semibold">
                                <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-pulse" />
                                Security Posture
                            </div>
                            <h1 className="text-4xl md:text-5xl font-display font-semibold mb-3 tracking-[-0.02em] lg-gradient-text">
                                Posture Dashboard
                            </h1>
                            <p className="text-sm text-text-secondary flex items-center gap-2">
                                <Shield className="w-4 h-4 text-accent-cyan" />
                                Composite security score · OWASP coverage · Industry benchmark
                                {lastRefresh && <span className="text-text-muted text-[11px] font-mono ml-2">Updated {lastRefresh.toLocaleTimeString()}</span>}
                            </p>
                        </motion.div>
                        <button onClick={load} disabled={loading}
                            className="flex-shrink-0 flex items-center gap-2 px-4 py-2.5 rounded-xl border border-white/10 bg-white/[0.04] text-sm text-text-muted hover:text-text-primary hover:bg-white/[0.07] transition-all disabled:opacity-50">
                            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
                        </button>
                    </div>
                </div>
            </div>

            {loading && !snap ? (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {[1, 2, 3].map(i => <div key={i} className="h-64 rounded-2xl bg-white/[0.03] border border-white/[0.06] animate-pulse" />)}
                </div>
            ) : snap ? (
                <div className="relative z-10 space-y-6">
                    {/* Row 1: Gauge + Components + Actions */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Gauge panel */}
                        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6 flex flex-col items-center">
                            <div className="absolute inset-0 pointer-events-none"
                                style={{ background: `radial-gradient(circle at 50% 30%, ${gc?.color || '#67e8f9'}0a, transparent 65%)` }} />
                            <p className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-4">Composite Score</p>
                            <ScoreGauge score={snap.score} grade={snap.grade} />
                            <div className="mt-4 w-full grid grid-cols-3 gap-2 text-center">
                                {[
                                    { label: 'Critical', value: snap.finding_counts?.critical || 0, color: '#ff4757' },
                                    { label: 'High', value: snap.finding_counts?.high || 0, color: '#ff7f50' },
                                    { label: 'Medium', value: snap.finding_counts?.medium || 0, color: '#eccc68' },
                                ].map(({ label, value, color }) => (
                                    <div key={label} className="rounded-xl bg-white/[0.03] border border-white/[0.06] py-2">
                                        <div className="text-lg font-bold font-mono" style={{ color }}>{value}</div>
                                        <div className="text-[9px] text-text-muted uppercase tracking-wider">{label}</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Component scores */}
                        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6">
                            <p className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-5">Score Breakdown</p>
                            <div className="space-y-4">
                                <ComponentBar label="Critical Exposure"     score={snap.components.critical_exposure}    color="#ff7f50" weight={35} />
                                <ComponentBar label="Remediation Progress"  score={snap.components.remediation_progress} color="#c4b5fd" weight={25} />
                                <ComponentBar label="SLA Health"            score={snap.components.sla_health}           color="#6ee7b7" weight={20} />
                                <ComponentBar label="Monitoring Coverage"   score={snap.components.monitoring_coverage}  color="#67e8f9" weight={10} />
                                <ComponentBar label="Attack Surface"        score={snap.components.attack_surface}       color="#fbbf24" weight={10} />
                            </div>
                            <div className="mt-5 pt-4 border-t border-white/[0.06]">
                                <Sparkline history={history} />
                            </div>
                        </div>

                        {/* Urgent actions */}
                        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6">
                            <p className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-4 flex items-center gap-2">
                                <Zap className="w-3.5 h-3.5 text-yellow-400" /> Urgent Actions
                            </p>
                            <div className="space-y-2">
                                {(snap.urgent_actions || []).map((a, i) => (
                                    <ActionItem key={i} action={a} />
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Row 2: OWASP + Benchmark */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* OWASP Top 10 coverage */}
                        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6">
                            <div className="flex items-center justify-between mb-5">
                                <p className="text-[11px] font-mono uppercase tracking-widest text-text-muted flex items-center gap-2">
                                    <Target className="w-3.5 h-3.5 text-accent-purple" /> OWASP Top 10 2021
                                </p>
                                <div className="flex items-center gap-3 text-[10px] text-text-muted">
                                    <span className="flex items-center gap-1"><AlertTriangle className="w-2.5 h-2.5 text-[#ff7f50]" /> Exposed</span>
                                    <span className="flex items-center gap-1"><CheckCircle className="w-2.5 h-2.5 opacity-30" /> Not assessed</span>
                                </div>
                            </div>
                            <OWASPGrid categories={snap.owasp_coverage} />
                        </div>

                        {/* Industry benchmark */}
                        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6">
                            <p className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-1 flex items-center gap-2">
                                <Activity className="w-3.5 h-3.5 text-accent-green" /> Industry Benchmark
                            </p>
                            <p className="text-[10px] text-text-muted mb-5">vs. SaaS/Cloud peer group (simulated)</p>
                            <div className="space-y-5">
                                {peerBenchmarks.map(b => (
                                    <BenchmarkBar key={b.label} {...b} />
                                ))}
                            </div>
                            <div className="mt-5 pt-4 border-t border-white/[0.06] flex items-center justify-between text-[11px] text-text-muted">
                                <span className="flex items-center gap-1.5">
                                    {snap.score >= peerScore
                                        ? <><TrendingUp className="w-3.5 h-3.5 text-accent-green" /><span className="text-accent-green">Above peer average</span></>
                                        : <><TrendingDown className="w-3.5 h-3.5 text-[#ff4757]" /><span className="text-[#ff4757]">Below peer average</span></>
                                    }
                                </span>
                                <span className="font-mono">Peer avg: {peerScore}</span>
                            </div>
                        </div>
                    </div>
                </div>
            ) : (
                <div className="flex items-center justify-center py-32 text-text-muted text-sm">
                    Failed to load posture data.
                </div>
            )}
        </div>
    )
}
