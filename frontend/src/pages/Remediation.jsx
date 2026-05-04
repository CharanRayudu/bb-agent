import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    CheckCircle, Clock, AlertTriangle, Plus, ChevronRight,
    ExternalLink, MessageSquare, RefreshCw, Shield, BarChart2,
    Tag, User, Trash2, ArrowRight, TrendingDown,
    GitPullRequest, Ticket
} from 'lucide-react'

const API_BASE = '/api'

const STATUSES = [
    { id: 'all',          label: 'All',         color: '#94a3b8' },
    { id: 'open',         label: 'Open',        color: '#ff4757' },
    { id: 'triaged',      label: 'Triaged',     color: '#fbbf24' },
    { id: 'in_progress',  label: 'In Progress', color: '#67e8f9' },
    { id: 'fixed',        label: 'Fixed',       color: '#6ee7b7' },
    { id: 'verified',     label: 'Verified',    color: '#a78bfa' },
    { id: 'accepted',     label: 'Accepted',    color: '#94a3b8' },
    { id: 'false_positive', label: 'False +',   color: '#6b7280' },
]

const SEVERITY_COLOR = {
    critical: '#ff4757',
    high:     '#ff7f50',
    medium:   '#eccc68',
    low:      '#2ed573',
    info:     '#67e8f9',
}

const CHIP = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

function severityChip(sev) {
    const c = SEVERITY_COLOR[sev] || '#94a3b8'
    return <span className={CHIP} style={{ color: c, borderColor: `${c}40`, background: `${c}12` }}>{sev}</span>
}

function statusBadge(status) {
    const s = STATUSES.find(x => x.id === status) || STATUSES[0]
    return <span className={CHIP} style={{ color: s.color, borderColor: `${s.color}40`, background: `${s.color}12` }}>{s.label}</span>
}

function SLAChip({ item }) {
    if (!item.sla_deadline) return null
    const remaining = new Date(item.sla_deadline) - Date.now()
    const breached = remaining < 0
    const dueSoon = !breached && remaining < 24 * 3600 * 1000
    const days = Math.abs(Math.ceil(remaining / (24 * 3600 * 1000)))
    const color = breached ? '#ff4757' : dueSoon ? '#fbbf24' : '#6ee7b7'
    const label = breached ? `${days}d overdue` : dueSoon ? `${days}d left` : `${days}d`
    return (
        <span className={CHIP} style={{ color, borderColor: `${color}40`, background: `${color}12` }}>
            <Clock className="w-2.5 h-2.5" /> {label}
        </span>
    )
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color, icon: Icon }) {
    return (
        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-4">
            <div className="absolute -top-8 -right-8 w-24 h-24 rounded-full blur-3xl opacity-25"
                style={{ background: `radial-gradient(circle, ${color}, transparent 70%)` }} />
            <div className="relative z-10 flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl flex items-center justify-center border flex-shrink-0"
                    style={{ background: `${color}15`, borderColor: `${color}35` }}>
                    <Icon className="w-4 h-4" style={{ color }} />
                </div>
                <div>
                    <div className="text-2xl font-bold font-mono leading-none" style={{ color }}>{value}</div>
                    <div className="text-[10px] text-text-muted mt-0.5">{label}</div>
                    {sub && <div className="text-[10px] text-text-muted opacity-60">{sub}</div>}
                </div>
            </div>
        </div>
    )
}

// ── Item card ─────────────────────────────────────────────────────────────────

function ItemCard({ item, onRefresh }) {
    const [expanded, setExpanded] = useState(false)
    const [note, setNote] = useState('')
    const [addingNote, setAddingNote] = useState(false)
    const [ticketModal, setTicketModal] = useState(false)

    async function transition(status) {
        await fetch(`${API_BASE}/remediation/items/${item.id}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status }),
        })
        onRefresh()
    }

    async function submitNote() {
        if (!note.trim()) return
        await fetch(`${API_BASE}/remediation/items/${item.id}/notes`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ author: 'analyst', content: note }),
        })
        setNote('')
        setAddingNote(false)
        onRefresh()
    }

    async function deleteItem() {
        if (!confirm('Delete this remediation item?')) return
        await fetch(`${API_BASE}/remediation/items/${item.id}`, { method: 'DELETE' })
        onRefresh()
    }

    const nextStatuses = {
        open:           ['triaged', 'in_progress', 'accepted', 'false_positive'],
        triaged:        ['in_progress', 'accepted', 'false_positive'],
        in_progress:    ['fixed', 'accepted'],
        fixed:          ['verified', 'open'],
        verified:       [],
        accepted:       ['open'],
        false_positive: ['open'],
    }[item.status] || []

    return (
        <motion.div
            layout
            className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.025] backdrop-blur-xl"
        >
            {/* Main row */}
            <div className="flex items-start gap-4 px-5 py-4">
                {/* Severity indicator */}
                <div className="mt-0.5 w-1.5 h-1.5 rounded-full flex-shrink-0 mt-2"
                    style={{ background: SEVERITY_COLOR[item.severity] || '#94a3b8', boxShadow: `0 0 6px ${SEVERITY_COLOR[item.severity] || '#94a3b8'}` }} />

                <div className="flex-1 min-w-0">
                    <div className="flex items-start gap-2 flex-wrap mb-2">
                        <span className="text-sm font-medium text-text-primary">{item.title}</span>
                        {severityChip(item.severity)}
                        {statusBadge(item.status)}
                        <SLAChip item={item} />
                        {item.jira_key && (
                            <a href={item.jira_url} target="_blank" rel="noreferrer"
                                className={`${CHIP} text-[#1d7aff] border-[#1d7aff]/30 bg-[#1d7aff]/10 hover:opacity-80`}>
                                <Ticket className="w-2.5 h-2.5" /> {item.jira_key}
                            </a>
                        )}
                        {item.github_issue > 0 && (
                            <a href={item.github_url} target="_blank" rel="noreferrer"
                                className={`${CHIP} text-[#e6edf3] border-white/20 bg-white/[0.06] hover:opacity-80`}>
                                <GitPullRequest className="w-2.5 h-2.5" /> #{item.github_issue}
                            </a>
                        )}
                    </div>
                    <div className="flex items-center gap-3 text-[11px] text-text-muted font-mono flex-wrap">
                        <span>{item.finding_type}</span>
                        <span className="opacity-40">·</span>
                        <span>{item.target}</span>
                        {item.assignee && <><span className="opacity-40">·</span><span className="flex items-center gap-1"><User className="w-2.5 h-2.5" />{item.assignee}</span></>}
                        {item.notes?.length > 0 && <><span className="opacity-40">·</span><span className="flex items-center gap-1"><MessageSquare className="w-2.5 h-2.5" />{item.notes.length}</span></>}
                    </div>
                </div>

                <div className="flex items-center gap-2 flex-shrink-0">
                    {/* Quick transition buttons */}
                    {nextStatuses.slice(0, 2).map(st => {
                        const s = STATUSES.find(x => x.id === st)
                        return (
                            <button key={st} onClick={() => transition(st)}
                                className="text-[10px] font-mono px-2.5 py-1 rounded-lg border transition-all hover:opacity-90"
                                style={{ color: s?.color, borderColor: `${s?.color}40`, background: `${s?.color}12` }}>
                                {s?.label}
                            </button>
                        )
                    })}
                    <button onClick={() => setExpanded(!expanded)}
                        className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.05] transition-colors">
                        <ChevronRight className={`w-4 h-4 transition-transform ${expanded ? 'rotate-90' : ''}`} />
                    </button>
                </div>
            </div>

            {/* Expanded detail */}
            <AnimatePresence>
                {expanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden border-t border-white/[0.06]"
                    >
                        <div className="px-5 py-4 space-y-4">
                            {/* Description */}
                            {item.description && (
                                <p className="text-xs text-text-secondary leading-relaxed">{item.description}</p>
                            )}

                            {/* All status transitions */}
                            {nextStatuses.length > 0 && (
                                <div className="flex items-center gap-2 flex-wrap">
                                    <span className="text-[10px] text-text-muted font-mono uppercase tracking-wider">Move to:</span>
                                    {nextStatuses.map(st => {
                                        const s = STATUSES.find(x => x.id === st)
                                        return (
                                            <button key={st} onClick={() => transition(st)}
                                                className="text-[11px] font-mono px-2.5 py-1 rounded-lg border transition-all hover:opacity-90 flex items-center gap-1"
                                                style={{ color: s?.color, borderColor: `${s?.color}40`, background: `${s?.color}12` }}>
                                                <ArrowRight className="w-3 h-3" /> {s?.label}
                                            </button>
                                        )
                                    })}
                                </div>
                            )}

                            {/* Notes */}
                            {item.notes?.length > 0 && (
                                <div className="space-y-2">
                                    <p className="text-[10px] font-mono uppercase tracking-wider text-text-muted">Notes</p>
                                    {item.notes.map(n => (
                                        <div key={n.id} className="flex gap-2 text-xs">
                                            <div className="w-5 h-5 rounded-full bg-accent-cyan/20 border border-accent-cyan/25 flex items-center justify-center flex-shrink-0 mt-0.5">
                                                <User className="w-2.5 h-2.5 text-accent-cyan" />
                                            </div>
                                            <div>
                                                <span className="text-text-muted font-mono">{n.author}</span>
                                                <span className="text-text-muted opacity-50 mx-1">·</span>
                                                <span className="text-text-muted opacity-50">{new Date(n.created_at).toLocaleString()}</span>
                                                <p className="text-text-secondary mt-0.5">{n.content}</p>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Add note */}
                            {addingNote ? (
                                <div className="flex gap-2">
                                    <input
                                        autoFocus
                                        value={note}
                                        onChange={e => setNote(e.target.value)}
                                        onKeyDown={e => e.key === 'Enter' && submitNote()}
                                        placeholder="Add a note…"
                                        className="flex-1 bg-white/[0.04] border border-white/10 rounded-xl px-3 py-2 text-xs text-text-primary outline-none focus:border-accent-cyan/40"
                                    />
                                    <button onClick={submitNote} className="px-3 py-2 rounded-xl bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan text-xs hover:bg-accent-cyan/20 transition-colors">Save</button>
                                    <button onClick={() => { setAddingNote(false); setNote('') }} className="px-3 py-2 rounded-xl border border-white/10 text-text-muted text-xs hover:bg-white/[0.04] transition-colors">Cancel</button>
                                </div>
                            ) : (
                                <div className="flex items-center gap-3">
                                    <button onClick={() => setAddingNote(true)}
                                        className="flex items-center gap-1.5 text-[11px] text-text-muted hover:text-text-secondary transition-colors">
                                        <MessageSquare className="w-3 h-3" /> Add note
                                    </button>
                                    <button onClick={() => setTicketModal(true)}
                                        className="flex items-center gap-1.5 text-[11px] text-text-muted hover:text-text-secondary transition-colors">
                                        <Ticket className="w-3 h-3" /> Create ticket
                                    </button>
                                    <button onClick={deleteItem}
                                        className="flex items-center gap-1.5 text-[11px] text-[#ff4757]/60 hover:text-[#ff4757] transition-colors ml-auto">
                                        <Trash2 className="w-3 h-3" /> Delete
                                    </button>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {ticketModal && <TicketModal item={item} onClose={() => setTicketModal(false)} onRefresh={onRefresh} />}
        </motion.div>
    )
}

// ── Ticket creation modal ─────────────────────────────────────────────────────

function TicketModal({ item, onClose, onRefresh }) {
    const [provider, setProvider] = useState('github')
    const [fields, setFields] = useState({})
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null)

    function set(k, v) { setFields(f => ({ ...f, [k]: v })) }

    async function submit() {
        setLoading(true)
        try {
            const resp = await fetch(`${API_BASE}/remediation/items/${item.id}/ticket`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, config: fields }),
            })
            const data = await resp.json()
            setResult(data)
            if (data.status === 'ok') onRefresh()
        } catch (e) {
            setResult({ status: 'error', error: e.message })
        } finally {
            setLoading(false)
        }
    }

    const Field = ({ label, k, placeholder, type = 'text' }) => (
        <div>
            <label className="block text-[11px] text-text-muted mb-1">{label}</label>
            <input type={type} value={fields[k] || ''} onChange={e => set(k, e.target.value)}
                placeholder={placeholder}
                className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-3 py-2 text-sm text-text-primary outline-none focus:border-accent-cyan/40" />
        </div>
    )

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-md" onClick={onClose}>
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
                className="relative bg-[#0d1117]/95 border border-white/10 rounded-2xl p-6 w-full max-w-md shadow-[0_24px_64px_rgba(0,0,0,0.7)]"
                onClick={e => e.stopPropagation()}>
                <h2 className="text-sm font-bold text-text-primary mb-4 flex items-center gap-2">
                    <Ticket className="w-4 h-4 text-accent-cyan" /> Create Ticket
                </h2>

                {/* Provider selector */}
                <div className="flex gap-2 mb-4">
                    {['github', 'jira'].map(p => (
                        <button key={p} onClick={() => setProvider(p)}
                            className={`flex-1 py-2 rounded-xl border text-xs font-mono uppercase tracking-wider transition-all ${
                                provider === p
                                    ? 'bg-accent-cyan/15 border-accent-cyan/35 text-accent-cyan'
                                    : 'bg-white/[0.03] border-white/10 text-text-muted hover:text-text-secondary'
                            }`}>
                            {p === 'github' ? 'GitHub Issues' : 'Jira'}
                        </button>
                    ))}
                </div>

                <div className="space-y-3">
                    {provider === 'github' ? (
                        <>
                            <Field label="GitHub Token" k="token" placeholder="ghp_..." type="password" />
                            <Field label="Owner" k="owner" placeholder="org or username" />
                            <Field label="Repository" k="repo" placeholder="repo-name" />
                        </>
                    ) : (
                        <>
                            <Field label="Jira Base URL" k="base_url" placeholder="https://your-org.atlassian.net" />
                            <Field label="Email" k="email" placeholder="you@company.com" />
                            <Field label="API Token" k="api_token" placeholder="ATATT..." type="password" />
                            <Field label="Project Key" k="project" placeholder="SEC" />
                        </>
                    )}
                </div>

                {result && (
                    <div className={`mt-4 rounded-xl border px-3 py-2 text-xs ${
                        result.status === 'ok'
                            ? 'bg-accent-green/10 border-accent-green/30 text-accent-green'
                            : 'bg-[#ff4757]/10 border-[#ff4757]/30 text-[#ff4757]'
                    }`}>
                        {result.status === 'ok'
                            ? <span>Created! <a href={result.url} target="_blank" rel="noreferrer" className="underline">View ticket <ExternalLink className="w-3 h-3 inline" /></a></span>
                            : result.error
                        }
                    </div>
                )}

                <div className="flex gap-3 mt-5">
                    <button onClick={submit} disabled={loading}
                        className="flex-1 lg-btn py-2.5 text-sm disabled:opacity-50">
                        {loading ? <div className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin mx-auto" /> : 'Create'}
                    </button>
                    <button onClick={onClose} className="px-4 py-2.5 rounded-xl border border-white/10 text-text-muted text-sm hover:text-text-primary hover:bg-white/[0.04] transition-colors">
                        Cancel
                    </button>
                </div>
            </motion.div>
        </div>
    )
}

// ── Page root ─────────────────────────────────────────────────────────────────

export default function Remediation() {
    const [items, setItems] = useState([])
    const [metrics, setMetrics] = useState(null)
    const [filter, setFilter] = useState('all')
    const [loading, setLoading] = useState(true)
    const [promoting, setPromoting] = useState(false)

    const load = useCallback(async () => {
        const [itemsData, metricsData] = await Promise.all([
            fetch(`${API_BASE}/remediation/items`).then(r => r.json()).catch(() => ({ items: [] })),
            fetch(`${API_BASE}/remediation/metrics`).then(r => r.json()).catch(() => null),
        ])
        setItems(itemsData.items || [])
        setMetrics(metricsData)
        setLoading(false)
    }, [])

    useEffect(() => { load() }, [load])

    async function autoPromote() {
        setPromoting(true)
        await fetch(`${API_BASE}/remediation/promote`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ auto_promote: true }),
        })
        await load()
        setPromoting(false)
    }

    const visibleItems = filter === 'all' ? items : items.filter(it => it.status === filter)

    return (
        <div className="relative pb-12">
            {/* Ambient */}
            <div className="pointer-events-none absolute inset-0 -z-10">
                <div className="absolute -top-40 -left-32 w-[40rem] h-[40rem] bg-accent-green/12 rounded-full blur-3xl" />
                <div className="absolute top-24 -right-40 w-[36rem] h-[36rem] bg-accent-purple/10 rounded-full blur-3xl" />
            </div>

            {/* Hero */}
            <div className="mb-8 relative z-10">
                <div className="lg-surface-hero px-7 py-8 md:px-10 md:py-10">
                    <div className="absolute -right-28 -top-28 h-72 w-72 bg-accent-green/20 blur-3xl opacity-50 pointer-events-none" />
                    <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
                            <div className="inline-flex items-center gap-2 lg-pill mb-4 text-[10px] uppercase tracking-[0.22em] font-semibold">
                                <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
                                Remediation
                            </div>
                            <h1 className="text-4xl md:text-5xl font-display font-semibold mb-3 tracking-[-0.02em] lg-gradient-text">
                                Remediation Tracking
                            </h1>
                            <p className="text-sm text-text-secondary flex items-center gap-2">
                                <Shield className="w-4 h-4 text-accent-green" />
                                {items.length} items tracked · SLA management · Jira & GitHub Issues
                            </p>
                        </motion.div>
                        <button
                            onClick={autoPromote}
                            disabled={promoting}
                            className="lg-btn px-5 py-3 text-sm flex-shrink-0 disabled:opacity-50"
                        >
                            {promoting
                                ? <div className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin relative z-10" />
                                : <Plus className="w-4 h-4 relative z-10" />
                            }
                            <span className="relative z-10 font-semibold">Promote Critical &amp; High</span>
                        </button>
                    </div>
                </div>
            </div>

            {/* Metrics row */}
            {metrics && (
                <div className="relative z-10 grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4 mb-8">
                    <StatCard label="Total Items"    value={metrics.total}             color="#67e8f9" icon={Tag} />
                    <StatCard label="SLA Breached"   value={metrics.sla_breached}      color="#ff4757" icon={AlertTriangle} />
                    <StatCard label="Fixed This Week" value={metrics.fixed_this_week}  color="#6ee7b7" icon={CheckCircle} />
                    <StatCard label="MTTR"
                        value={metrics.mttr_days > 0 ? `${metrics.mttr_days.toFixed(1)}d` : '—'}
                        color="#c4b5fd" icon={Clock}
                        sub="mean time to fix" />
                    <StatCard label="Risk Reduced"
                        value={metrics.risk_reduced > 0 ? metrics.risk_reduced.toFixed(0) : '0'}
                        color="#fbbf24" icon={TrendingDown}
                        sub="cumulative score" />
                    <StatCard label="Open Risk"
                        value={metrics.open_risk > 0 ? metrics.open_risk.toFixed(0) : '0'}
                        color="#ff7f50" icon={BarChart2} />
                </div>
            )}

            {/* Status tabs */}
            <div className="relative z-10 flex items-center gap-1 mb-5 bg-white/[0.03] border border-white/[0.08] rounded-2xl p-1 w-fit flex-wrap">
                {STATUSES.map(st => {
                    const count = st.id === 'all' ? items.length : items.filter(it => it.status === st.id).length
                    const active = filter === st.id
                    return (
                        <button key={st.id} onClick={() => setFilter(st.id)}
                            className={`relative flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                                active ? 'text-text-primary' : 'text-text-muted hover:text-text-secondary'
                            }`}>
                            {active && (
                                <motion.span layoutId="rem-tab"
                                    className="absolute inset-0 rounded-xl bg-white/[0.08] border border-white/10"
                                    transition={{ type: 'spring', stiffness: 400, damping: 30 }} />
                            )}
                            <span className="relative z-10" style={{ color: active ? st.color : undefined }}>{st.label}</span>
                            {count > 0 && (
                                <span className="relative z-10 text-[9px] font-mono px-1.5 py-0.5 rounded-full border"
                                    style={{ color: active ? st.color : '#6b7280', borderColor: active ? `${st.color}30` : 'rgba(255,255,255,0.08)', background: active ? `${st.color}12` : 'rgba(255,255,255,0.03)' }}>
                                    {count}
                                </span>
                            )}
                        </button>
                    )
                })}
                <button onClick={load} className="ml-auto p-2 rounded-xl text-text-muted hover:text-text-primary hover:bg-white/[0.05] transition-colors">
                    <RefreshCw className="w-3.5 h-3.5" />
                </button>
            </div>

            {/* Items list */}
            <div className="relative z-10 space-y-3">
                {loading ? (
                    Array.from({ length: 3 }, (_, i) => (
                        <div key={i} className="h-20 rounded-2xl bg-white/[0.03] border border-white/[0.06] animate-pulse" />
                    ))
                ) : visibleItems.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-20 text-center gap-4 rounded-2xl border border-white/[0.06] bg-white/[0.02]">
                        <div className="w-14 h-14 rounded-2xl bg-accent-green/10 border border-accent-green/20 flex items-center justify-center">
                            <CheckCircle className="w-6 h-6 text-accent-green" />
                        </div>
                        <div>
                            <p className="text-sm font-medium text-text-secondary mb-1">
                                {filter === 'all' ? 'No remediation items yet' : `No ${filter.replace('_', ' ')} items`}
                            </p>
                            <p className="text-xs text-text-muted max-w-xs">
                                {filter === 'all'
                                    ? 'Click "Promote Critical & High" to auto-create items from your findings.'
                                    : 'Try a different status filter.'}
                            </p>
                        </div>
                    </div>
                ) : (
                    <AnimatePresence>
                        {visibleItems.map(item => (
                            <ItemCard key={item.id} item={item} onRefresh={load} />
                        ))}
                    </AnimatePresence>
                )}
            </div>
        </div>
    )
}
