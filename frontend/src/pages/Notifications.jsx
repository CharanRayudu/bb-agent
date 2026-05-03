import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Bell, Plus, Trash2, Send, CheckCircle, XCircle,
    Loader, RefreshCw, X, AlertTriangle, Slack, Globe,
    Mail, ToggleLeft, ToggleRight, Edit2, Zap,
} from 'lucide-react'

// ── constants ─────────────────────────────────────────────────────────────────

const CHANNEL_TYPES = [
    {
        value: 'slack',
        label: 'Slack',
        icon: Slack,
        color: '#4A154B',
        accent: '#36C5F0',
        desc: 'Post alerts via Slack Incoming Webhook',
    },
    {
        value: 'webhook',
        label: 'HTTP Webhook',
        icon: Globe,
        color: '#1a2332',
        accent: '#67e8f9',
        desc: 'POST JSON payload to any HTTP endpoint',
    },
    {
        value: 'email',
        label: 'Email / SMTP',
        icon: Mail,
        color: '#1a1a2e',
        accent: '#c4b5fd',
        desc: 'Send alerts via SMTP to one or more recipients',
    },
]

const EVENT_META = {
    critical_finding: { label: 'Critical Finding',  color: '#ff4444', icon: '🚨' },
    high_finding:     { label: 'High Finding',       color: '#ff8800', icon: '⚠️' },
    scan_complete:    { label: 'Scan Complete',      color: '#00cc44', icon: '✅' },
    sla_breach:       { label: 'SLA Breach',         color: '#ff6600', icon: '⏰' },
    schedule_fired:   { label: 'Schedule Fired',     color: '#22d3ee', icon: '🔁' },
    monitor_alert:    { label: 'Monitor Alert',      color: '#a78bfa', icon: '📡' },
}

function typeInfo(type) {
    return CHANNEL_TYPES.find(t => t.value === type) ?? CHANNEL_TYPES[1]
}

function fmtDate(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
}

// ── Channel card ──────────────────────────────────────────────────────────────

function ChannelCard({ ch, onToggle, onTest, onEdit, onDelete, testing }) {
    const info = typeInfo(ch.type)
    const Icon = info.icon

    return (
        <motion.div
            layout
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96 }}
            className={`relative overflow-hidden rounded-2xl border bg-white/[0.03] backdrop-blur-xl transition-all ${
                ch.enabled ? 'border-white/10 hover:border-white/[0.18]' : 'border-white/[0.05] opacity-55'
            }`}
        >
            {/* Type accent bar */}
            <div className="absolute top-0 left-0 right-0 h-0.5" style={{ backgroundColor: info.accent + '80' }} />

            <div className="p-5">
                {/* Header */}
                <div className="flex items-start justify-between gap-3 mb-4">
                    <div className="flex items-center gap-3 min-w-0">
                        <div className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 border border-white/10"
                            style={{ backgroundColor: info.color }}>
                            <Icon className="w-4 h-4" style={{ color: info.accent }} />
                        </div>
                        <div className="min-w-0">
                            <h3 className="text-[14px] font-semibold text-text-primary truncate">{ch.name}</h3>
                            <p className="text-[11px] text-text-muted font-mono">{info.label}</p>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={() => onToggle(ch)}
                        className="flex-shrink-0 text-text-muted hover:text-text-primary transition-colors"
                        title={ch.enabled ? 'Disable' : 'Enable'}
                    >
                        {ch.enabled
                            ? <ToggleRight className="w-6 h-6" style={{ color: info.accent }} />
                            : <ToggleLeft className="w-6 h-6" />}
                    </button>
                </div>

                {/* Event subscriptions */}
                <div className="flex flex-wrap gap-1.5 mb-4">
                    {(ch.events ?? []).length === 0
                        ? <span className="text-[10px] text-text-muted italic">No events subscribed</span>
                        : (ch.events ?? []).map(e => {
                            const meta = EVENT_META[e] ?? { label: e, color: '#666', icon: '•' }
                            return (
                                <span key={e} className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium border border-white/[0.08]"
                                    style={{ color: meta.color, backgroundColor: meta.color + '18' }}>
                                    {meta.icon} {meta.label}
                                </span>
                            )
                        })
                    }
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between">
                    <span className="text-[10px] text-text-muted font-mono">
                        {ch.tested_at ? `Tested ${fmtDate(ch.tested_at)}` : 'Not tested yet'}
                    </span>
                    <div className="flex items-center gap-1">
                        <button type="button" onClick={() => onTest(ch.id)}
                            disabled={testing === ch.id}
                            title="Send test"
                            className="p-1.5 rounded-lg text-text-muted hover:text-accent-cyan hover:bg-accent-cyan/10 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1 text-[11px]">
                            {testing === ch.id
                                ? <Loader className="w-3.5 h-3.5 animate-spin" />
                                : <Send className="w-3.5 h-3.5" />}
                        </button>
                        <button type="button" onClick={() => onEdit(ch)}
                            title="Edit"
                            className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.06] transition-all">
                            <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        <button type="button" onClick={() => onDelete(ch.id)}
                            title="Delete"
                            className="p-1.5 rounded-lg text-text-muted hover:text-red-400 hover:bg-red-400/10 transition-all">
                            <Trash2 className="w-3.5 h-3.5" />
                        </button>
                    </div>
                </div>
            </div>
        </motion.div>
    )
}

// ── Create / Edit modal ───────────────────────────────────────────────────────

function ChannelModal({ editing, allEvents, onClose, onSave }) {
    const [step, setStep] = useState(editing ? 1 : 0)
    const [form, setForm] = useState({
        name:    editing?.name ?? '',
        type:    editing?.type ?? '',
        enabled: editing?.enabled ?? true,
        config:  editing?.config ?? {},
        events:  editing?.events ?? [],
    })
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState('')

    function set(k, v) { setForm(f => ({ ...f, [k]: v })) }
    function setCfg(k, v) { setForm(f => ({ ...f, config: { ...f.config, [k]: v } })) }

    function toggleEvent(e) {
        setForm(f => ({
            ...f,
            events: f.events.includes(e) ? f.events.filter(x => x !== e) : [...f.events, e],
        }))
    }

    async function handleSave() {
        if (!form.name.trim()) { setError('Name is required.'); return }
        setSaving(true); setError('')
        try {
            await onSave(form)
            onClose()
        } catch (e) {
            setError(e.message || 'Save failed.')
        } finally {
            setSaving(false)
        }
    }

    const _selectedType = CHANNEL_TYPES.find(t => t.value === form.type)

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-md" onClick={onClose}>
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
                            {editing ? 'Edit Channel' : 'New Channel'}
                        </h2>
                        <p className="text-[12px] text-text-muted mt-0.5">
                            {step === 0 ? 'Choose a channel type' : step === 1 ? 'Configure connection' : 'Subscribe to events'}
                        </p>
                    </div>
                    <button type="button" onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/[0.06] text-text-muted">
                        <X className="w-4 h-4" />
                    </button>
                </div>

                <div className="px-6 py-5 space-y-4 min-h-[280px]">
                    {/* Step 0: type picker */}
                    {step === 0 && (
                        <div className="space-y-3">
                            {CHANNEL_TYPES.map(t => {
                                const TIcon = t.icon
                                return (
                                    <button key={t.value} type="button"
                                        onClick={() => { set('type', t.value); setStep(1) }}
                                        className="w-full flex items-center gap-4 p-4 rounded-xl border border-white/10 hover:border-white/20 bg-white/[0.02] hover:bg-white/[0.04] transition-all text-left group">
                                        <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 border border-white/10"
                                            style={{ backgroundColor: t.color }}>
                                            <TIcon className="w-4.5 h-4.5" style={{ color: t.accent }} />
                                        </div>
                                        <div>
                                            <div className="text-[14px] font-semibold text-text-primary group-hover:text-white transition-colors">{t.label}</div>
                                            <div className="text-[12px] text-text-muted">{t.desc}</div>
                                        </div>
                                    </button>
                                )
                            })}
                        </div>
                    )}

                    {/* Step 1: config */}
                    {step === 1 && (
                        <div className="space-y-4">
                            <div>
                                <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Channel Name</label>
                                <input type="text" value={form.name} onChange={e => set('name', e.target.value)}
                                    placeholder="e.g. Security Team Slack"
                                    className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                            </div>

                            {/* Slack */}
                            {form.type === 'slack' && <>
                                <div>
                                    <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Incoming Webhook URL</label>
                                    <input type="text" value={form.config.webhook_url ?? ''} onChange={e => setCfg('webhook_url', e.target.value)}
                                        placeholder="https://hooks.slack.com/services/..."
                                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                </div>
                                <div>
                                    <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Channel (optional override)</label>
                                    <input type="text" value={form.config.slack_channel ?? ''} onChange={e => setCfg('slack_channel', e.target.value)}
                                        placeholder="#security-alerts"
                                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                </div>
                            </>}

                            {/* Webhook */}
                            {form.type === 'webhook' && <>
                                <div>
                                    <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Endpoint URL</label>
                                    <input type="text" value={form.config.webhook_url ?? ''} onChange={e => setCfg('webhook_url', e.target.value)}
                                        placeholder="https://your-app.example.com/hooks/mirage"
                                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                </div>
                                <div>
                                    <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Authorization Header (optional)</label>
                                    <input type="text" value={form.config.headers?.Authorization ?? ''} onChange={e => setCfg('headers', { ...form.config.headers, Authorization: e.target.value })}
                                        placeholder="Bearer your-token"
                                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                </div>
                            </>}

                            {/* Email */}
                            {form.type === 'email' && <>
                                <div className="grid grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">SMTP Host</label>
                                        <input type="text" value={form.config.smtp_host ?? ''} onChange={e => setCfg('smtp_host', e.target.value)}
                                            placeholder="smtp.gmail.com"
                                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                    </div>
                                    <div>
                                        <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Port</label>
                                        <input type="number" value={form.config.smtp_port ?? 587} onChange={e => setCfg('smtp_port', parseInt(e.target.value))}
                                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                    </div>
                                </div>
                                <div className="grid grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Username</label>
                                        <input type="text" value={form.config.username ?? ''} onChange={e => setCfg('username', e.target.value)}
                                            placeholder="user@gmail.com"
                                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                    </div>
                                    <div>
                                        <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">Password / App Key</label>
                                        <input type="password" value={form.config.password ?? ''} onChange={e => setCfg('password', e.target.value)}
                                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                    </div>
                                </div>
                                <div>
                                    <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">From</label>
                                    <input type="text" value={form.config.from ?? ''} onChange={e => setCfg('from', e.target.value)}
                                        placeholder="mirage@yourcompany.com"
                                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                </div>
                                <div>
                                    <label className="block text-[11px] font-mono uppercase tracking-widest text-text-muted mb-2">To (comma-separated)</label>
                                    <input type="text"
                                        value={Array.isArray(form.config.to) ? form.config.to.join(', ') : (form.config.to ?? '')}
                                        onChange={e => setCfg('to', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                                        placeholder="security@yourcompany.com, cto@yourcompany.com"
                                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-4 py-2.5 text-[14px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-cyan/40 transition-colors" />
                                </div>
                            </>}
                        </div>
                    )}

                    {/* Step 2: events */}
                    {step === 2 && (
                        <div className="space-y-3">
                            <p className="text-[12px] text-text-muted">Choose which events trigger this channel:</p>
                            <div className="grid grid-cols-2 gap-2">
                                {allEvents.map(e => {
                                    const meta = EVENT_META[e] ?? { label: e, color: '#666', icon: '•' }
                                    const active = form.events.includes(e)
                                    return (
                                        <button key={e} type="button" onClick={() => toggleEvent(e)}
                                            className={`flex items-center gap-2.5 px-3 py-2.5 rounded-xl border text-left transition-all ${
                                                active
                                                    ? 'border-opacity-50 text-white'
                                                    : 'border-white/[0.08] bg-white/[0.02] text-text-secondary hover:border-white/20'
                                            }`}
                                            style={active ? { borderColor: meta.color + '80', backgroundColor: meta.color + '18', color: meta.color } : {}}>
                                            <span className="text-[14px]">{meta.icon}</span>
                                            <span className="text-[12px] font-medium">{meta.label}</span>
                                            {active && <CheckCircle className="w-3 h-3 ml-auto flex-shrink-0" />}
                                        </button>
                                    )
                                })}
                            </div>
                        </div>
                    )}

                    {error && (
                        <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-[12px]">
                            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />{error}
                        </div>
                    )}
                </div>

                {/* Footer nav */}
                <div className="px-6 py-4 border-t border-white/[0.08] flex items-center justify-between gap-3">
                    <div>
                        {step > 0 && (
                            <button type="button" onClick={() => setStep(s => s - 1)}
                                className="px-4 py-2 rounded-xl text-[13px] text-text-secondary hover:text-text-primary hover:bg-white/[0.06] transition-all">
                                Back
                            </button>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                        <button type="button" onClick={onClose}
                            className="px-4 py-2 rounded-xl text-[13px] text-text-secondary hover:text-text-primary hover:bg-white/[0.06] transition-all">
                            Cancel
                        </button>
                        {step < 2 ? (
                            <button type="button"
                                disabled={step === 1 && !form.name.trim()}
                                onClick={() => setStep(s => s + 1)}
                                className="px-5 py-2 rounded-xl text-[13px] font-medium bg-accent-cyan/20 border border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/30 transition-all disabled:opacity-40">
                                Next →
                            </button>
                        ) : (
                            <button type="button" onClick={handleSave} disabled={saving}
                                className="flex items-center gap-2 px-5 py-2 rounded-xl text-[13px] font-medium bg-accent-cyan/20 border border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/30 transition-all disabled:opacity-50">
                                {saving ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}
                                {editing ? 'Save changes' : 'Create channel'}
                            </button>
                        )}
                    </div>
                </div>
            </motion.div>
        </div>
    )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Notifications() {
    const [channels, setChannels] = useState([])
    const [allEvents, setAllEvents] = useState([])
    const [loading, setLoading] = useState(true)
    const [showModal, setShowModal] = useState(false)
    const [editing, setEditing] = useState(null)
    const [testing, setTesting] = useState(null)
    const [testResult, setTestResult] = useState(null)

    const load = useCallback(async () => {
        try {
            const r = await fetch('/api/notify/channels').then(r => r.json())
            setChannels(r.channels ?? [])
            setAllEvents(r.events ?? [])
        } catch { /* silent */ } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { load() }, [load])

    async function handleToggle(ch) {
        const updated = { ...ch, enabled: !ch.enabled }
        await fetch(`/api/notify/channels/${ch.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updated),
        })
        load()
    }

    async function handleTest(id) {
        setTesting(id)
        setTestResult(null)
        try {
            const r = await fetch(`/api/notify/channels/${id}/test`, { method: 'POST' })
            setTestResult({ id, ok: r.ok, msg: r.ok ? 'Test sent!' : 'Delivery failed.' })
        } catch {
            setTestResult({ id, ok: false, msg: 'Network error.' })
        } finally {
            setTesting(null)
            setTimeout(() => setTestResult(null), 4000)
        }
    }

    async function handleDelete(id) {
        if (!confirm('Delete this channel?')) return
        await fetch(`/api/notify/channels/${id}`, { method: 'DELETE' })
        load()
    }

    async function handleSave(form) {
        if (editing) {
            const r = await fetch(`/api/notify/channels/${editing.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(form),
            })
            if (!r.ok) throw new Error(await r.text())
        } else {
            const r = await fetch('/api/notify/channels', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(form),
            })
            if (!r.ok) throw new Error(await r.text())
        }
        load()
    }

    const enabledCount = channels.filter(c => c.enabled).length
    const typeCounts = CHANNEL_TYPES.reduce((acc, t) => {
        acc[t.value] = channels.filter(c => c.type === t.value).length
        return acc
    }, {})

    return (
        <div className="px-6 py-8 max-w-6xl mx-auto">
            {/* Header */}
            <div className="flex items-start justify-between mb-8">
                <div>
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-9 h-9 rounded-xl bg-accent-purple/15 border border-accent-purple/20 flex items-center justify-center">
                            <Bell className="w-4.5 h-4.5 text-accent-purple" />
                        </div>
                        <h1 className="text-[22px] font-semibold" style={{ background: 'linear-gradient(135deg, #c4b5fd, #a78bfa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                            Notification Channels
                        </h1>
                    </div>
                    <p className="text-[13px] text-text-muted ml-12">
                        Route security alerts to Slack, webhooks, or email based on event type
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <button type="button" onClick={load} className="p-2 rounded-xl text-text-muted hover:text-text-primary hover:bg-white/[0.06] transition-all">
                        <RefreshCw className="w-4 h-4" />
                    </button>
                    <button type="button" onClick={() => { setEditing(null); setShowModal(true) }}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl text-[13px] font-medium bg-accent-purple/20 border border-accent-purple/30 text-accent-purple hover:bg-accent-purple/30 transition-all">
                        <Plus className="w-4 h-4" /> Add Channel
                    </button>
                </div>
            </div>

            {/* Stats + test result */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
                {[
                    { label: 'Total', value: channels.length, icon: Bell, color: 'text-accent-purple' },
                    { label: 'Active', value: enabledCount, icon: Zap, color: 'text-emerald-400' },
                    ...CHANNEL_TYPES.slice(0, 2).map(t => ({
                        label: t.label,
                        value: typeCounts[t.value] ?? 0,
                        icon: t.icon,
                        color: 'text-text-muted',
                        accent: t.accent,
                    })),
                ].map(({ label, value, icon: Icon, color, accent }) => (
                    <div key={label} className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5">
                        <div className={`text-[10px] font-mono uppercase tracking-widest ${color} mb-3 flex items-center gap-2`}>
                            <Icon className="w-3 h-3" style={accent ? { color: accent } : {}} />{label}
                        </div>
                        <div className="text-[22px] font-bold text-text-primary">{value}</div>
                    </div>
                ))}
            </div>

            {/* Test result toast */}
            <AnimatePresence>
                {testResult && (
                    <motion.div
                        initial={{ opacity: 0, y: -8 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -8 }}
                        className={`flex items-center gap-3 px-4 py-3 rounded-xl mb-6 border text-[13px] font-medium ${
                            testResult.ok
                                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                                : 'border-red-500/30 bg-red-500/10 text-red-400'
                        }`}
                    >
                        {testResult.ok ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                        {testResult.msg}
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Channel grid */}
            {loading ? (
                <div className="flex items-center justify-center py-24">
                    <Loader className="w-6 h-6 text-accent-purple animate-spin" />
                </div>
            ) : channels.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-24 text-center">
                    <div className="w-14 h-14 rounded-2xl bg-white/[0.03] border border-white/[0.06] flex items-center justify-center mb-4">
                        <Bell className="w-6 h-6 text-text-muted" />
                    </div>
                    <h3 className="text-[15px] font-semibold text-text-primary mb-2">No channels configured</h3>
                    <p className="text-[13px] text-text-muted mb-6 max-w-xs">
                        Add a Slack, webhook, or email channel to receive real-time security alerts.
                    </p>
                    <button type="button" onClick={() => { setEditing(null); setShowModal(true) }}
                        className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-[13px] font-medium bg-accent-purple/20 border border-accent-purple/30 text-accent-purple hover:bg-accent-purple/30 transition-all">
                        <Plus className="w-4 h-4" /> Add first channel
                    </button>
                </div>
            ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
                    <AnimatePresence>
                        {channels.map(ch => (
                            <ChannelCard
                                key={ch.id}
                                ch={ch}
                                testing={testing}
                                onToggle={handleToggle}
                                onTest={handleTest}
                                onEdit={c => { setEditing(c); setShowModal(true) }}
                                onDelete={handleDelete}
                            />
                        ))}
                    </AnimatePresence>
                </div>
            )}

            {/* Modal */}
            <AnimatePresence>
                {showModal && (
                    <ChannelModal
                        editing={editing}
                        allEvents={allEvents.length ? allEvents : Object.keys(EVENT_META)}
                        onClose={() => { setShowModal(false); setEditing(null) }}
                        onSave={handleSave}
                    />
                )}
            </AnimatePresence>
        </div>
    )
}
