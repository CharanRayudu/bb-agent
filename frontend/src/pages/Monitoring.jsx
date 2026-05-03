import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Activity, Plus, Play, Pause, Trash2, Bell,
    AlertTriangle, ArrowUpRight,
    ArrowDownRight, Minus, RefreshCw, Loader, Clock,
    Zap, ChevronDown, ChevronRight,
    Slack, MessageSquare, Globe, Target
} from 'lucide-react'

const API_BASE = '/api'
const CHIP = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

const SEV_CHIP = {
    critical: 'bg-[#ff4757]/12 text-[#ff4757] border-[#ff4757]/35',
    high:     'bg-[#ff7f50]/12 text-[#ff7f50] border-[#ff7f50]/35',
    medium:   'bg-[#eccc68]/12 text-[#eccc68] border-[#eccc68]/35',
    low:      'bg-[#2ed573]/12 text-[#2ed573] border-[#2ed573]/35',
    info:     'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30',
}

const STATUS_STYLES = {
    active:  { dot: 'bg-emerald-400', label: 'text-emerald-400', text: 'Active' },
    paused:  { dot: 'bg-yellow-400',  label: 'text-yellow-400',  text: 'Paused' },
    error:   { dot: 'bg-[#ff4757]',   label: 'text-[#ff4757]',   text: 'Error'  },
}

const CHANNEL_ICONS = {
    slack:     Slack,
    teams:     MessageSquare,
    pagerduty: Bell,
    webhook:   Globe,
}

const CRON_PRESETS = [
    { label: 'Every hour',   value: '0 * * * *' },
    { label: 'Every 6h',     value: '0 */6 * * *' },
    { label: 'Daily 06:00',  value: '0 6 * * *' },
    { label: 'Daily 02:00',  value: '0 2 * * *' },
    { label: 'Weekly Mon',   value: '0 6 * * 1' },
]

// ── Delta badge ──────────────────────────────────────────────────────────────
function DeltaBadge({ delta }) {
    if (!delta) return null
    const newCount = delta.new_findings?.length || 0
    const resolved = delta.resolved_findings?.length || 0
    const regressions = delta.regressions?.length || 0

    return (
        <div className="flex items-center gap-2 text-xs">
            {newCount > 0 && (
                <span className="flex items-center gap-0.5 text-[#ff7f50]">
                    <ArrowUpRight className="w-3 h-3" />{newCount} new
                </span>
            )}
            {regressions > 0 && (
                <span className="flex items-center gap-0.5 text-[#ff4757]">
                    <AlertTriangle className="w-3 h-3" />{regressions} regressed
                </span>
            )}
            {resolved > 0 && (
                <span className="flex items-center gap-0.5 text-[#2ed573]">
                    <ArrowDownRight className="w-3 h-3" />{resolved} resolved
                </span>
            )}
            {newCount === 0 && regressions === 0 && resolved === 0 && (
                <span className="flex items-center gap-0.5 text-text-muted">
                    <Minus className="w-3 h-3" />No change
                </span>
            )}
        </div>
    )
}

// ── Monitor Card ─────────────────────────────────────────────────────────────
function MonitorCard({ monitor, onTrigger, onBaseline, onDelete, onToggle }) {
    const [expanded, setExpanded] = useState(false)
    const [deltas, setDeltas] = useState(null)
    const [loading, setLoading] = useState(false)
    const ss = STATUS_STYLES[monitor.status] || STATUS_STYLES.active

    async function loadDeltas() {
        if (deltas !== null) return
        setLoading(true)
        try {
            const res = await fetch(`${API_BASE}/monitors/${monitor.id}/deltas`)
            const data = await res.json()
            setDeltas(data.deltas || [])
        } finally {
            setLoading(false)
        }
    }

    function toggle() {
        setExpanded(e => {
            if (!e) loadDeltas()
            return !e
        })
    }

    const latestDelta = deltas?.[0]

    return (
        <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-2xl border border-white/[0.08] bg-white/[0.02] overflow-hidden"
        >
            {/* Header row */}
            <div className="flex items-center gap-3 px-4 py-3">
                <button type="button" onClick={toggle} className="flex items-center gap-3 flex-1 min-w-0 text-left">
                    <span className="relative flex-shrink-0">
                        <span className={`absolute inset-0 rounded-full animate-ping opacity-40 ${ss.dot}`} />
                        <span className={`relative w-2 h-2 rounded-full ${ss.dot} inline-block`} />
                    </span>
                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-semibold text-text-primary truncate">{monitor.name}</span>
                            <span className={`text-[9px] font-mono uppercase ${ss.label}`}>{ss.text}</span>
                        </div>
                        <div className="text-[11px] text-text-muted font-mono truncate">{monitor.target}</div>
                    </div>
                </button>

                <div className="flex-shrink-0 flex items-center gap-3">
                    {monitor.last_scan_at && (
                        <div className="hidden sm:flex items-center gap-1 text-[10px] text-text-muted">
                            <Clock className="w-3 h-3" />
                            {new Date(monitor.last_scan_at).toLocaleString()}
                        </div>
                    )}
                    {latestDelta && <DeltaBadge delta={latestDelta} />}
                    <div className="flex items-center gap-1">
                        <button type="button" onClick={() => onTrigger(monitor.id)} title="Trigger scan" className="p-1.5 rounded-lg hover:bg-white/[0.06] text-text-muted hover:text-accent-cyan transition-colors">
                            <Play className="w-3.5 h-3.5" />
                        </button>
                        <button type="button" onClick={() => onBaseline(monitor.id)} title="Set baseline" className="p-1.5 rounded-lg hover:bg-white/[0.06] text-text-muted hover:text-[#eccc68] transition-colors">
                            <Target className="w-3.5 h-3.5" />
                        </button>
                        <button type="button" onClick={() => onToggle(monitor)} title={monitor.status === 'active' ? 'Pause' : 'Resume'} className="p-1.5 rounded-lg hover:bg-white/[0.06] text-text-muted hover:text-text-primary transition-colors">
                            {monitor.status === 'active' ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                        </button>
                        <button type="button" onClick={() => onDelete(monitor.id)} title="Delete" className="p-1.5 rounded-lg hover:bg-white/[0.06] text-text-muted hover:text-[#ff4757] transition-colors">
                            <Trash2 className="w-3.5 h-3.5" />
                        </button>
                    </div>
                    <button type="button" onClick={toggle} className="p-1 text-text-muted">
                        {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </button>
                </div>
            </div>

            {/* Expanded delta history */}
            {expanded && (
                <div className="border-t border-white/[0.06] px-4 pb-4 space-y-3">
                    <div className="pt-3 grid grid-cols-3 gap-3 text-xs">
                        <div className="p-2 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                            <div className="text-[9px] text-text-muted uppercase">Schedule</div>
                            <div className="font-mono text-text-primary mt-0.5">{monitor.cron_expr || '—'}</div>
                        </div>
                        <div className="p-2 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                            <div className="text-[9px] text-text-muted uppercase">Baseline Findings</div>
                            <div className="font-bold text-text-primary mt-0.5">{monitor.finding_count ?? '—'}</div>
                        </div>
                        <div className="p-2 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                            <div className="text-[9px] text-text-muted uppercase">New Since Baseline</div>
                            <div className={`font-bold mt-0.5 ${monitor.new_since_baseline > 0 ? 'text-[#ff7f50]' : 'text-[#2ed573]'}`}>
                                {monitor.new_since_baseline ?? 0}
                            </div>
                        </div>
                    </div>

                    <div>
                        <h4 className="text-[10px] font-semibold text-text-muted uppercase tracking-widest mb-2">Delta History</h4>
                        {loading ? (
                            <div className="flex items-center gap-2 py-2 text-text-muted text-xs">
                                <Loader className="w-3.5 h-3.5 animate-spin" /> Loading…
                            </div>
                        ) : deltas?.length > 0 ? (
                            <div className="space-y-1.5">
                                {deltas.slice(0, 5).map((d, i) => (
                                    <div key={i} className="flex items-start gap-3 p-2.5 rounded-lg bg-black/20 border border-white/[0.05]">
                                        <Clock className="w-3 h-3 text-text-muted flex-shrink-0 mt-0.5" />
                                        <div className="flex-1 min-w-0">
                                            <div className="text-[10px] text-text-muted">{new Date(d.computed_at).toLocaleString()}</div>
                                            <div className="text-xs text-text-secondary mt-0.5">{d.summary}</div>
                                        </div>
                                        {(d.new_findings?.length > 0 || d.regressions?.length > 0) && (
                                            <span className={`${CHIP} ${SEV_CHIP[d.has_critical ? 'critical' : d.has_high ? 'high' : 'medium']}`}>
                                                {d.has_critical ? 'critical' : d.has_high ? 'high' : 'medium'}
                                            </span>
                                        )}
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <p className="text-xs text-text-muted italic">No deltas recorded yet — trigger a scan to start tracking changes</p>
                        )}
                    </div>
                </div>
            )}
        </motion.div>
    )
}

// ── Create Monitor Modal ─────────────────────────────────────────────────────
function CreateMonitorModal({ channels, onClose, onCreate }) {
    const [form, setForm] = useState({ name: '', target: '', profile: 'full', cron_expr: '0 6 * * *', alert_channels: [] })
    const [creating, setCreating] = useState(false)
    const [error, setError] = useState(null)

    async function submit() {
        if (!form.target) { setError('Target URL is required'); return }
        setCreating(true)
        setError(null)
        try {
            const res = await fetch(`${API_BASE}/monitors`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(form),
            })
            const data = await res.json()
            if (!res.ok) setError(data.error || `HTTP ${res.status}`)
            else { onCreate(data); onClose() }
        } catch (e) { setError(e.message) }
        finally { setCreating(false) }
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" onClick={onClose}>
            <motion.div
                initial={{ opacity: 0, scale: 0.97 }}
                animate={{ opacity: 1, scale: 1 }}
                className="w-full max-w-lg rounded-2xl border border-white/10 bg-[#0f1117] shadow-2xl p-6 space-y-4"
                onClick={e => e.stopPropagation()}
            >
                <h2 className="text-base font-bold text-text-primary">New Monitor</h2>

                <div className="space-y-3">
                    <div>
                        <label className="block text-[10px] text-text-muted uppercase tracking-widest mb-1">Name</label>
                        <input value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))} placeholder="Production API"
                            className="w-full px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-sm text-text-primary placeholder:text-text-muted outline-none focus:border-accent-cyan/40" />
                    </div>
                    <div>
                        <label className="block text-[10px] text-text-muted uppercase tracking-widest mb-1">Target URL *</label>
                        <input value={form.target} onChange={e => setForm(f => ({...f, target: e.target.value}))} placeholder="https://api.example.com"
                            className="w-full px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-sm text-text-primary font-mono placeholder:text-text-muted outline-none focus:border-accent-cyan/40" />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                        <div>
                            <label className="block text-[10px] text-text-muted uppercase tracking-widest mb-1">Profile</label>
                            <select value={form.profile} onChange={e => setForm(f => ({...f, profile: e.target.value}))}
                                className="w-full px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-sm text-text-primary outline-none focus:border-accent-cyan/40">
                                <option value="full">Full</option>
                                <option value="quick">Quick</option>
                                <option value="stealth">Stealth</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-[10px] text-text-muted uppercase tracking-widest mb-1">Schedule</label>
                            <select value={form.cron_expr} onChange={e => setForm(f => ({...f, cron_expr: e.target.value}))}
                                className="w-full px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-sm text-text-primary outline-none focus:border-accent-cyan/40">
                                {CRON_PRESETS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                            </select>
                        </div>
                    </div>
                    {channels.length > 0 && (
                        <div>
                            <label className="block text-[10px] text-text-muted uppercase tracking-widest mb-1">Alert Channels</label>
                            <div className="space-y-1.5">
                                {channels.map(ch => (
                                    <label key={ch.id} className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={form.alert_channels.includes(ch.id)}
                                            onChange={e => setForm(f => ({
                                                ...f,
                                                alert_channels: e.target.checked
                                                    ? [...f.alert_channels, ch.id]
                                                    : f.alert_channels.filter(id => id !== ch.id)
                                            }))}
                                            className="rounded"
                                        />
                                        <span className="text-sm text-text-secondary">{ch.name}</span>
                                        <span className="text-[10px] text-text-muted font-mono">{ch.type}</span>
                                    </label>
                                ))}
                            </div>
                        </div>
                    )}
                </div>

                {error && <p className="text-xs text-[#ff4757]">{error}</p>}

                <div className="flex justify-end gap-2">
                    <button type="button" onClick={onClose} className="px-4 py-2 rounded-xl border border-white/10 text-sm text-text-muted hover:text-text-primary transition-colors">Cancel</button>
                    <button type="button" onClick={submit} disabled={creating}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan text-sm font-medium hover:bg-accent-cyan/20 transition-all disabled:opacity-40">
                        {creating ? <Loader className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                        Create Monitor
                    </button>
                </div>
            </motion.div>
        </div>
    )
}

// ── Alert Channels Panel ─────────────────────────────────────────────────────
function ChannelsPanel({ channels, onAdd, onDelete, onTest: _onTest }) {
    const [showAdd, setShowAdd] = useState(false)
    const [form, setForm] = useState({ name: '', type: 'slack', url: '', min_severity: 'high' })
    const [testing, setTesting] = useState(null)

    async function add() {
        if (!form.url) return
        const res = await fetch(`${API_BASE}/alerting/channels`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(form),
        })
        const data = await res.json()
        onAdd(data)
        setShowAdd(false)
        setForm({ name: '', type: 'slack', url: '', min_severity: 'high' })
    }

    async function test(id) {
        setTesting(id)
        try {
            await fetch(`${API_BASE}/alerting/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ channel_id: id }),
            })
        } finally { setTesting(null) }
    }

    return (
        <div className="rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                    <Bell className="w-4 h-4 text-accent-cyan" /> Alert Channels
                </h3>
                <button type="button" onClick={() => setShowAdd(s => !s)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] border border-white/10 text-xs text-text-secondary hover:text-text-primary transition-colors">
                    <Plus className="w-3.5 h-3.5" /> Add Channel
                </button>
            </div>

            {showAdd && (
                <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4 space-y-3">
                    <div className="grid grid-cols-2 gap-2">
                        <div>
                            <label className="block text-[9px] text-text-muted uppercase tracking-widest mb-1">Name</label>
                            <input value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))} placeholder="Slack #alerts"
                                className="w-full px-2.5 py-1.5 rounded-lg bg-black/20 border border-white/10 text-xs text-text-primary placeholder:text-text-muted outline-none focus:border-accent-cyan/40" />
                        </div>
                        <div>
                            <label className="block text-[9px] text-text-muted uppercase tracking-widest mb-1">Type</label>
                            <select value={form.type} onChange={e => setForm(f => ({...f, type: e.target.value}))}
                                className="w-full px-2.5 py-1.5 rounded-lg bg-black/20 border border-white/10 text-xs text-text-primary outline-none">
                                <option value="slack">Slack</option>
                                <option value="teams">Teams</option>
                                <option value="pagerduty">PagerDuty</option>
                                <option value="webhook">Webhook</option>
                            </select>
                        </div>
                    </div>
                    <div>
                        <label className="block text-[9px] text-text-muted uppercase tracking-widest mb-1">Webhook URL / Routing Key</label>
                        <input value={form.url} onChange={e => setForm(f => ({...f, url: e.target.value}))} placeholder="https://hooks.slack.com/…"
                            className="w-full px-2.5 py-1.5 rounded-lg bg-black/20 border border-white/10 text-xs font-mono text-text-primary placeholder:text-text-muted outline-none focus:border-accent-cyan/40" />
                    </div>
                    <div className="flex items-center justify-between gap-2">
                        <div>
                            <label className="block text-[9px] text-text-muted uppercase tracking-widest mb-1">Min Severity</label>
                            <select value={form.min_severity} onChange={e => setForm(f => ({...f, min_severity: e.target.value}))}
                                className="px-2.5 py-1.5 rounded-lg bg-black/20 border border-white/10 text-xs text-text-primary outline-none">
                                {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
                            </select>
                        </div>
                        <button type="button" onClick={add}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan text-xs font-medium hover:bg-accent-cyan/20 transition-all">
                            <Plus className="w-3 h-3" /> Save
                        </button>
                    </div>
                </div>
            )}

            {channels.length === 0 ? (
                <p className="text-xs text-text-muted italic">No alert channels configured yet</p>
            ) : (
                <div className="space-y-2">
                    {channels.map(ch => {
                        const Icon = CHANNEL_ICONS[ch.type] || Globe
                        return (
                            <div key={ch.id} className="flex items-center gap-3 p-3 rounded-xl bg-black/20 border border-white/[0.06]">
                                <Icon className="w-4 h-4 text-text-muted flex-shrink-0" />
                                <div className="flex-1 min-w-0">
                                    <div className="text-sm font-medium text-text-primary">{ch.name}</div>
                                    <div className="text-[10px] text-text-muted font-mono truncate">{ch.url}</div>
                                </div>
                                <span className={`${CHIP} ${SEV_CHIP[ch.min_severity] || SEV_CHIP.info}`}>{ch.min_severity}+</span>
                                <button type="button" onClick={() => test(ch.id)} disabled={testing === ch.id}
                                    className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] bg-white/[0.04] border border-white/10 text-text-muted hover:text-text-primary transition-colors disabled:opacity-40">
                                    {testing === ch.id ? <Loader className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
                                    Test
                                </button>
                                <button type="button" onClick={() => onDelete(ch.id)} className="p-1.5 rounded-lg hover:bg-white/[0.06] text-text-muted hover:text-[#ff4757] transition-colors">
                                    <Trash2 className="w-3.5 h-3.5" />
                                </button>
                            </div>
                        )
                    })}
                </div>
            )}
        </div>
    )
}

// ── Main Page ────────────────────────────────────────────────────────────────
export default function Monitoring() {
    const [monitors, setMonitors] = useState([])
    const [channels, setChannels] = useState([])
    const [loading, setLoading] = useState(true)
    const [showCreate, setShowCreate] = useState(false)
    const [tab, setTab] = useState('monitors')

    const fetchData = useCallback(async () => {
        setLoading(true)
        try {
            const [mRes, cRes] = await Promise.all([
                fetch(`${API_BASE}/monitors`),
                fetch(`${API_BASE}/alerting/channels`),
            ])
            const [mData, cData] = await Promise.all([mRes.json(), cRes.json()])
            setMonitors(mData.monitors || [])
            setChannels(cData.channels || [])
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { fetchData() }, [fetchData])

    async function triggerScan(id) {
        await fetch(`${API_BASE}/monitors/${id}/trigger`, { method: 'POST' })
        setTimeout(fetchData, 3000)
    }

    async function setBaseline(id) {
        await fetch(`${API_BASE}/monitors/${id}/baseline`, { method: 'POST' })
        fetchData()
    }

    async function deleteMonitor(id) {
        await fetch(`${API_BASE}/monitors/${id}`, { method: 'DELETE' })
        setMonitors(ms => ms.filter(m => m.id !== id))
    }

    async function toggleMonitor(monitor) {
        const newStatus = monitor.status === 'active' ? 'paused' : 'active'
        await fetch(`${API_BASE}/monitors/${monitor.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus }),
        })
        setMonitors(ms => ms.map(m => m.id === monitor.id ? { ...m, status: newStatus } : m))
    }

    function deleteChannel(id) {
        fetch(`${API_BASE}/alerting/channels/${id}`, { method: 'DELETE' })
        setChannels(cs => cs.filter(c => c.id !== id))
    }

    const activeCount = monitors.filter(m => m.status === 'active').length
    const newTotal = monitors.reduce((acc, m) => acc + (m.new_since_baseline || 0), 0)

    return (
        <div className="p-6 space-y-6 max-w-4xl">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <div className="flex items-center gap-3 mb-1">
                        <span className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-400/20 to-accent-cyan/15 border border-white/20 flex items-center justify-center">
                            <Activity className="w-5 h-5 text-emerald-400" />
                        </span>
                        <div>
                            <h1 className="text-xl font-bold text-text-primary">Continuous Monitoring</h1>
                            <p className="text-xs text-text-muted">Scheduled rescans · Delta detection · Slack / PagerDuty / Teams alerts</p>
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <button type="button" onClick={fetchData} disabled={loading}
                        className="p-2 rounded-lg bg-white/[0.04] border border-white/10 text-text-muted hover:text-text-primary transition-all disabled:opacity-40">
                        {loading ? <Loader className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                    </button>
                    <button type="button" onClick={() => setShowCreate(true)}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan text-sm font-medium hover:bg-accent-cyan/20 transition-all">
                        <Plus className="w-4 h-4" /> New Monitor
                    </button>
                </div>
            </div>

            {/* Summary Row */}
            <div className="grid grid-cols-3 gap-3">
                {[
                    { label: 'Active Monitors', value: activeCount, color: '#2ed573', icon: Activity },
                    { label: 'Total Monitors', value: monitors.length, color: '#22d3ee', icon: Target },
                    { label: 'New Since Baseline', value: newTotal, color: newTotal > 0 ? '#ff7f50' : '#2ed573', icon: AlertTriangle },
                ].map(item => {
                    const Icon = item.icon
                    return (
                        <div key={item.label} className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.08] flex items-center gap-3">
                            <span className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${item.color}18` }}>
                                <Icon className="w-4 h-4" style={{ color: item.color }} />
                            </span>
                            <div>
                                <div className="text-xl font-bold text-text-primary">{item.value}</div>
                                <div className="text-[10px] text-text-muted uppercase tracking-widest">{item.label}</div>
                            </div>
                        </div>
                    )
                })}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-white/[0.08]">
                {[
                    { id: 'monitors', label: 'Monitors', icon: Activity },
                    { id: 'channels', label: 'Alert Channels', icon: Bell },
                ].map(t => {
                    const Icon = t.icon
                    const active = tab === t.id
                    return (
                        <button key={t.id} type="button" onClick={() => setTab(t.id)}
                            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-all border-b-2 -mb-px ${
                                active ? 'text-accent-cyan border-accent-cyan' : 'text-text-muted border-transparent hover:text-text-secondary'
                            }`}>
                            <Icon className="w-3.5 h-3.5" />
                            {t.label}
                            {t.id === 'monitors' && monitors.length > 0 && (
                                <span className="px-1.5 py-0.5 rounded-full text-[9px] font-mono bg-white/[0.06] border border-white/10 text-text-muted">{monitors.length}</span>
                            )}
                        </button>
                    )
                })}
            </div>

            {/* Tab content */}
            {tab === 'monitors' && (
                <div className="space-y-3">
                    {loading ? (
                        <div className="flex items-center justify-center py-12">
                            <Loader className="w-6 h-6 text-text-muted animate-spin" />
                        </div>
                    ) : monitors.length > 0 ? (
                        monitors.map(m => (
                            <MonitorCard
                                key={m.id}
                                monitor={m}
                                onTrigger={triggerScan}
                                onBaseline={setBaseline}
                                onDelete={deleteMonitor}
                                onToggle={toggleMonitor}
                            />
                        ))
                    ) : (
                        <div className="text-center py-16 text-text-muted">
                            <Activity className="w-10 h-10 mx-auto mb-3 opacity-25" />
                            <p className="text-sm font-medium text-text-secondary">No monitors configured</p>
                            <p className="text-xs mt-1">Create a monitor to start continuous attack surface tracking</p>
                            <button type="button" onClick={() => setShowCreate(true)}
                                className="mt-4 flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan text-sm font-medium hover:bg-accent-cyan/20 transition-all mx-auto">
                                <Plus className="w-4 h-4" /> Create First Monitor
                            </button>
                        </div>
                    )}
                </div>
            )}

            {tab === 'channels' && (
                <ChannelsPanel
                    channels={channels}
                    onAdd={ch => setChannels(cs => [...cs, ch])}
                    onDelete={deleteChannel}
                    onTest={() => {}}
                />
            )}

            {/* Create modal */}
            <AnimatePresence>
                {showCreate && (
                    <CreateMonitorModal
                        channels={channels}
                        onClose={() => setShowCreate(false)}
                        onCreate={m => { setMonitors(ms => [...ms, m]); fetchData() }}
                    />
                )}
            </AnimatePresence>
        </div>
    )
}
