import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Clock, Plus, Play, Trash2, ToggleLeft, ToggleRight,
    RefreshCw, CheckCircle, XCircle, Loader, Calendar,
    Target, Tag, ChevronDown, X, Edit2, AlertTriangle,
} from 'lucide-react'

// ── helpers ──────────────────────────────────────────────────────────────────

const CRON_PRESETS = [
    { value: '@hourly',   label: 'Every hour' },
    { value: '@every6h',  label: 'Every 6 hours' },
    { value: '@every12h', label: 'Every 12 hours' },
    { value: '@daily',    label: 'Daily' },
    { value: '@weekly',   label: 'Weekly' },
    { value: '@monthly',  label: 'Monthly' },
]

function fmtCountdown(nextRunISO) {
    if (!nextRunISO) return '—'
    const ms = new Date(nextRunISO) - Date.now()
    if (ms < 0) return 'overdue'
    const s = Math.floor(ms / 1000)
    const m = Math.floor(s / 60)
    const h = Math.floor(m / 60)
    const d = Math.floor(h / 24)
    if (d > 0) return `in ${d}d ${h % 24}h`
    if (h > 0) return `in ${h}h ${m % 60}m`
    if (m > 0) return `in ${m}m`
    return 'in <1m'
}

function fmtAgo(isoStr) {
    if (!isoStr) return 'Never'
    const ms = Date.now() - new Date(isoStr)
    const m = Math.floor(ms / 60000)
    if (m < 1) return 'just now'
    if (m < 60) return `${m}m ago`
    const h = Math.floor(m / 60)
    if (h < 24) return `${h}h ago`
    return `${Math.floor(h / 24)}d ago`
}

function StatusBadge({ status }) {
    if (status === 'running') return (
        <span className="flex items-center gap-1.5 text-accent-cyan text-[11px] font-medium">
            <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full rounded-full bg-accent-cyan opacity-75 animate-ping" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-accent-cyan" />
            </span>
            Running
        </span>
    )
    if (status === 'ok') return (
        <span className="flex items-center gap-1.5 text-emerald-400 text-[11px] font-medium">
            <CheckCircle className="w-3 h-3" /> Last run OK
        </span>
    )
    if (status === 'error') return (
        <span className="flex items-center gap-1.5 text-red-400 text-[11px] font-medium">
            <XCircle className="w-3 h-3" /> Last run failed
        </span>
    )
    return (
        <span className="flex items-center gap-1.5 text-text-muted text-[11px]">
            <Clock className="w-3 h-3" /> Never run
        </span>
    )
}

// ── Schedule card ─────────────────────────────────────────────────────────────

function ScheduleCard({ sc, onToggle, onRun, onEdit, onDelete, now }) {
    const isRunning = sc.last_status === 'running'
    const overdue = sc.enabled && sc.next_run && new Date(sc.next_run) < now

    return (
        <motion.div
            layout
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96 }}
            className={`relative overflow-hidden rounded-2xl border bg-white/[0.03] backdrop-blur-xl transition-all ${
                sc.enabled
                    ? 'border-white/10 hover:border-white/[0.18]'
                    : 'border-white/[0.05] opacity-60'
            }`}
        >
            {/* Running shimmer */}
            {isRunning && (
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-accent-cyan/[0.04] to-transparent animate-shimmer pointer-events-none" />
            )}
            {/* Overdue stripe */}
            {overdue && !isRunning && (
                <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-yellow-500/60 via-yellow-400/80 to-yellow-500/60" />
            )}

            <div className="p-5">
                {/* Header row */}
                <div className="flex items-start justify-between gap-3 mb-4">
                    <div className="min-w-0">
                        <h3 className="text-[15px] font-semibold text-text-primary truncate">{sc.name}</h3>
                        <div className="flex items-center gap-2 mt-1 flex-wrap">
                            <span className="text-[11px] text-text-muted font-mono truncate max-w-[200px]">{sc.target}</span>
                            {sc.profile_name && (
                                <>
                                    <span className="text-white/20">·</span>
                                    <span className="flex items-center gap-1 text-[11px] text-accent-cyan/80">
                                        <Tag className="w-2.5 h-2.5" />{sc.profile_name}
                                    </span>
                                </>
                            )}
                        </div>
                    </div>

                    {/* Toggle */}
                    <button
                        type="button"
                        onClick={() => onToggle(sc.id)}
                        className="flex-shrink-0 text-text-muted hover:text-text-primary transition-colors"
                        title={sc.enabled ? 'Disable schedule' : 'Enable schedule'}
                    >
                        {sc.enabled
                            ? <ToggleRight className="w-6 h-6 text-accent-cyan" />
                            : <ToggleLeft className="w-6 h-6" />}
                    </button>
                </div>

                {/* Stats row */}
                <div className="grid grid-cols-3 gap-3 mb-4">
                    <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-3">
                        <div className="text-[9px] font-mono uppercase tracking-widest text-text-muted mb-1">Frequency</div>
                        <div className="text-[12px] font-medium text-text-primary">{sc.cron_label || sc.cron}</div>
                    </div>
                    <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-3">
                        <div className="text-[9px] font-mono uppercase tracking-widest text-text-muted mb-1">Next Run</div>
                        <div className={`text-[12px] font-medium ${overdue ? 'text-yellow-400' : 'text-text-primary'}`}>
                            {sc.enabled ? fmtCountdown(sc.next_run) : 'Paused'}
                        </div>
                    </div>
                    <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-3">
                        <div className="text-[9px] font-mono uppercase tracking-widest text-text-muted mb-1">Runs</div>
                        <div className="text-[12px] font-medium text-text-primary">{sc.run_count ?? 0}</div>
                    </div>
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <StatusBadge status={sc.last_status} />
                        {sc.last_run && (
                            <span className="text-[10px] text-text-muted font-mono">{fmtAgo(sc.last_run)}</span>
                        )}
                    </div>

                    <div className="flex items-center gap-1">
                        <button
                            type="button"
                            onClick={() => onRun(sc.id)}
                            disabled={isRunning}
                            title="Run now"
                            className="p-1.5 rounded-lg text-text-muted hover:text-accent-cyan hover:bg-accent-cyan/10 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                            {isRunning ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                        </button>
                        <button
                            type="button"
                            onClick={() => onEdit(sc)}
                            title="Edit"
                            className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.06] transition-all"
                        >
                            <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        <button
                            type="button"
                            onClick={() => onDelete(sc.id)}
                            title="Delete"
                            className="p-1.5 rounded-lg text-text-muted hover:text-red-400 hover:bg-red-400/10 transition-all"
                        >
                            <Trash2 className="w-3.5 h-3.5" />
                        </button>
                    </div>
                </div>
            </div>
        </motion.div>
    )
}

// ── Create / Edit modal ───────────────────────────────────────────────────────

function ScheduleModal({ editing, profiles, onClose, onSave }) {
    const [form, setForm] = useState({
        name:         editing?.name ?? '',
        target:       editing?.target ?? '',
        profile_id:   editing?.profile_id ?? '',
        profile_name: editing?.profile_name ?? '',
        cron:         editing?.cron ?? '@daily',
    })
    const [profileOpen, setProfileOpen] = useState(false)
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState('')

    function set(k, v) { setForm(f => ({ ...f, [k]: v })) }

    function pickProfile(p) {
        set('profile_id', p.id)
        set('profile_name', p.name)
        setProfileOpen(false)
    }

    async function handleSave() {
        if (!form.name.trim() || !form.target.trim()) {
            setError('Name and target are required.')
            return
        }
        setSaving(true)
        setError('')
        try {
            await onSave(form)
            onClose()
        } catch (e) {
            setError(e.message || 'Save failed.')
        } finally {
            setSaving(false)
        }
    }

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-md"
            onClick={onClose}
        >
            <motion.div
                initial={{ opacity: 0, scale: 0.95, y: 10 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95, y: 10 }}
                transition={{ duration: 0.18, ease: [0.2, 0.8, 0.2, 1] }}
                className="w-full max-w-lg relative overflow-hidden rounded-2xl border border-white/10 bg-[#0e1117] shadow-2xl"
                onClick={e => e.stopPropagation()}
            >
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-5 border-b border-white/[0.08]">
                    <div>
                        <h2 className="text-[16px] font-semibold text-text-primary">
                            {editing ? 'Edit Schedule' : 'New Schedule'}
                        </h2>
                        <p className="text-[12px] text-text-muted mt-0.5">Automate recurring scans</p>
                    </div>
                    <button type="button" onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/[0.06] text-text-muted hover:text-text-primary transition-all">
                        <X className="w-4 h-4" />
                    </button>
                </div>

                <div className="px-6 py-5 space-y-4">
                    {/* Name */}
                    <div>
                        <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Schedule Name</label>
                        <input
                            type="text"
                            value={form.name}
                            onChange={e => set('name', e.target.value)}
                            placeholder="e.g. Nightly production scan"
                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors"
                        />
                    </div>

                    {/* Target */}
                    <div>
                        <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Target</label>
                        <input
                            type="text"
                            value={form.target}
                            onChange={e => set('target', e.target.value)}
                            placeholder="https://example.com"
                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors"
                        />
                    </div>

                    {/* Profile picker */}
                    <div>
                        <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Scan Profile</label>
                        <div className="relative">
                            <button
                                type="button"
                                onClick={() => setProfileOpen(o => !o)}
                                className="w-full flex items-center justify-between gap-3 bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-left hover:border-white/20 transition-colors"
                            >
                                <span className={form.profile_name ? 'text-text-primary' : 'text-text-muted'}>
                                    {form.profile_name || 'No profile (use default scan)'}
                                </span>
                                <ChevronDown className={`w-4 h-4 text-text-muted flex-shrink-0 transition-transform ${profileOpen ? 'rotate-180' : ''}`} />
                            </button>
                            <AnimatePresence>
                                {profileOpen && (
                                    <motion.div
                                        initial={{ opacity: 0, y: -4 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        exit={{ opacity: 0, y: -4 }}
                                        transition={{ duration: 0.12 }}
                                        className="absolute top-full mt-1 left-0 right-0 z-10 bg-[#0e1117] border border-white/10 rounded-xl shadow-xl overflow-hidden max-h-48 overflow-y-auto"
                                    >
                                        <button
                                            type="button"
                                            onClick={() => { set('profile_id', ''); set('profile_name', ''); setProfileOpen(false) }}
                                            className="w-full text-left px-4 py-2.5 text-[13px] text-text-muted hover:bg-white/[0.06] transition-colors"
                                        >
                                            No profile
                                        </button>
                                        {profiles.map(p => (
                                            <button
                                                key={p.id}
                                                type="button"
                                                onClick={() => pickProfile(p)}
                                                className={`w-full text-left px-4 py-2.5 text-[13px] hover:bg-white/[0.06] transition-colors flex items-center gap-3 ${form.profile_id === p.id ? 'text-accent-cyan bg-accent-cyan/[0.06]' : 'text-text-secondary'}`}
                                            >
                                                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: p.color }} />
                                                {p.name}
                                                <span className="ml-auto text-[10px] text-text-muted font-mono">{p.category}</span>
                                            </button>
                                        ))}
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>
                    </div>

                    {/* Cron preset */}
                    <div>
                        <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Frequency</label>
                        <div className="grid grid-cols-3 gap-2">
                            {CRON_PRESETS.map(p => (
                                <button
                                    key={p.value}
                                    type="button"
                                    onClick={() => set('cron', p.value)}
                                    className={`px-3 py-2 rounded-xl text-[12px] font-medium border transition-all text-left ${
                                        form.cron === p.value
                                            ? 'border-accent-cyan/50 bg-accent-cyan/10 text-accent-cyan'
                                            : 'border-white/[0.08] bg-white/[0.03] text-text-secondary hover:border-white/20 hover:text-text-primary'
                                    }`}
                                >
                                    {p.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    {error && (
                        <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-[12px]">
                            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />{error}
                        </div>
                    )}
                </div>

                <div className="px-6 py-4 border-t border-white/[0.08] flex items-center justify-end gap-3">
                    <button type="button" onClick={onClose} className="px-4 py-2 rounded-xl text-[13px] text-text-secondary hover:text-text-primary hover:bg-white/[0.06] transition-all">
                        Cancel
                    </button>
                    <button
                        type="button"
                        onClick={handleSave}
                        disabled={saving}
                        className="flex items-center gap-2 px-5 py-2 rounded-xl text-[13px] font-medium bg-accent-cyan/20 border border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/30 transition-all disabled:opacity-50"
                    >
                        {saving ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}
                        {editing ? 'Save changes' : 'Create schedule'}
                    </button>
                </div>
            </motion.div>
        </div>
    )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ScheduledScans() {
    const [schedules, setSchedules] = useState([])
    const [profiles, setProfiles] = useState([])
    const [loading, setLoading] = useState(true)
    const [showModal, setShowModal] = useState(false)
    const [editing, setEditing] = useState(null)
    const [now, setNow] = useState(new Date())

    // Tick every 30s to refresh countdowns
    useEffect(() => {
        const id = setInterval(() => setNow(new Date()), 30000)
        return () => clearInterval(id)
    }, [])

    const load = useCallback(async () => {
        try {
            const [sr, pr] = await Promise.all([
                fetch('/api/schedule-plans').then(r => r.json()),
                fetch('/api/profiles').then(r => r.json()),
            ])
            setSchedules(sr.schedules ?? [])
            setProfiles(pr.profiles ?? [])
        } catch { /* silent */ } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { load() }, [load])

    // Auto-refresh every 30s to pick up status changes
    useEffect(() => {
        const id = setInterval(load, 30000)
        return () => clearInterval(id)
    }, [load])

    async function handleToggle(id) {
        await fetch(`/api/schedule-plans/${id}/toggle`, { method: 'POST' })
        load()
    }

    async function handleRun(id) {
        await fetch(`/api/schedule-plans/${id}/run`, { method: 'POST' })
        load()
    }

    async function handleDelete(id) {
        if (!confirm('Delete this schedule?')) return
        await fetch(`/api/schedule-plans/${id}`, { method: 'DELETE' })
        load()
    }

    async function handleSave(form) {
        if (editing) {
            const r = await fetch(`/api/schedule-plans/${editing.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(form),
            })
            if (!r.ok) throw new Error(await r.text())
        } else {
            const r = await fetch('/api/schedule-plans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(form),
            })
            if (!r.ok) throw new Error(await r.text())
        }
        load()
    }

    const active = schedules.filter(s => s.enabled)
    const runsToday = schedules.reduce((n, s) => {
        if (!s.last_run) return n
        const d = new Date(s.last_run)
        const today = new Date()
        return (d.toDateString() === today.toDateString()) ? n + 1 : n
    }, 0)
    const lastRun = schedules
        .filter(s => s.last_run)
        .sort((a, b) => new Date(b.last_run) - new Date(a.last_run))[0]

    return (
        <div className="px-6 py-8 max-w-6xl mx-auto">
            {/* Page header */}
            <div className="flex items-start justify-between mb-8">
                <div>
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-9 h-9 rounded-xl bg-accent-cyan/15 border border-accent-cyan/20 flex items-center justify-center">
                            <Calendar className="w-4.5 h-4.5 text-accent-cyan" />
                        </div>
                        <h1 className="text-[22px] font-semibold lg-gradient-text-cyan">Scheduled Scans</h1>
                    </div>
                    <p className="text-[13px] text-text-muted ml-12">
                        Automate recurring scans with profile templates and configurable intervals
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        type="button"
                        onClick={load}
                        className="p-2 rounded-xl text-text-muted hover:text-text-primary hover:bg-white/[0.06] transition-all"
                        title="Refresh"
                    >
                        <RefreshCw className="w-4 h-4" />
                    </button>
                    <button
                        type="button"
                        onClick={() => { setEditing(null); setShowModal(true) }}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl text-[13px] font-medium bg-accent-cyan/20 border border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/30 transition-all"
                    >
                        <Plus className="w-4 h-4" /> New Schedule
                    </button>
                </div>
            </div>

            {/* Stats strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
                {[
                    { label: 'Total', value: schedules.length, icon: Calendar, color: 'text-accent-cyan' },
                    { label: 'Active', value: active.length, icon: ToggleRight, color: 'text-emerald-400' },
                    { label: 'Runs Today', value: runsToday, icon: Play, color: 'text-accent-purple' },
                    { label: 'Last Run', value: lastRun ? fmtAgo(lastRun.last_run) : '—', icon: Clock, color: 'text-text-muted' },
                ].map(({ label, value, icon: Icon, color }) => (
                    <div key={label} className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5">
                        <div className={`text-[10px] font-mono uppercase tracking-widest ${color} mb-3 flex items-center gap-2`}>
                            <Icon className="w-3 h-3" />{label}
                        </div>
                        <div className="text-[22px] font-bold text-text-primary">{value}</div>
                    </div>
                ))}
            </div>

            {/* Schedule grid */}
            {loading ? (
                <div className="flex items-center justify-center py-24">
                    <Loader className="w-6 h-6 text-accent-cyan animate-spin" />
                </div>
            ) : schedules.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-24 text-center">
                    <div className="w-14 h-14 rounded-2xl bg-white/[0.03] border border-white/[0.06] flex items-center justify-center mb-4">
                        <Calendar className="w-6 h-6 text-text-muted" />
                    </div>
                    <h3 className="text-[15px] font-semibold text-text-primary mb-2">No schedules yet</h3>
                    <p className="text-[13px] text-text-muted mb-6 max-w-xs">
                        Create a schedule to automate recurring security scans on your targets.
                    </p>
                    <button
                        type="button"
                        onClick={() => { setEditing(null); setShowModal(true) }}
                        className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-[13px] font-medium bg-accent-cyan/20 border border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/30 transition-all"
                    >
                        <Plus className="w-4 h-4" /> Create first schedule
                    </button>
                </div>
            ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
                    <AnimatePresence>
                        {schedules.map(sc => (
                            <ScheduleCard
                                key={sc.id}
                                sc={sc}
                                now={now}
                                onToggle={handleToggle}
                                onRun={handleRun}
                                onEdit={s => { setEditing(s); setShowModal(true) }}
                                onDelete={handleDelete}
                            />
                        ))}
                    </AnimatePresence>
                </div>
            )}

            {/* Modal */}
            <AnimatePresence>
                {showModal && (
                    <ScheduleModal
                        editing={editing}
                        profiles={profiles}
                        onClose={() => { setShowModal(false); setEditing(null) }}
                        onSave={handleSave}
                    />
                )}
            </AnimatePresence>
        </div>
    )
}
