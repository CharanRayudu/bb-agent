import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ClipboardList, Search, RefreshCw, ChevronDown, ChevronUp, User, Globe, Clock, Filter, X, Download } from 'lucide-react'

const ACTION_COLOR = {
    scan_started:      { bg: 'bg-accent-cyan/10',   border: 'border-accent-cyan/30',   text: 'text-accent-cyan' },
    scan_completed:    { bg: 'bg-accent-green/10',  border: 'border-accent-green/30',  text: 'text-accent-green' },
    scan_failed:       { bg: 'bg-red-500/10',        border: 'border-red-500/30',       text: 'text-red-400' },
    finding_created:   { bg: 'bg-yellow-500/10',     border: 'border-yellow-500/30',    text: 'text-yellow-400' },
    schedule_fired:    { bg: 'bg-accent-purple/10',  border: 'border-accent-purple/30', text: 'text-accent-purple' },
    scan_deleted:      { bg: 'bg-red-500/10',        border: 'border-red-500/30',       text: 'text-red-400' },
    config_updated:    { bg: 'bg-blue-500/10',       border: 'border-blue-500/30',      text: 'text-blue-400' },
    login:             { bg: 'bg-accent-green/10',   border: 'border-accent-green/30',  text: 'text-accent-green' },
}

function actionStyle(action) {
    return ACTION_COLOR[action] || { bg: 'bg-white/[0.04]', border: 'border-white/[0.10]', text: 'text-text-muted' }
}

function fmtTime(ts) {
    if (!ts) return '—'
    const d = new Date(ts)
    return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function fmtRelative(ts) {
    if (!ts) return ''
    const diff = (Date.now() - new Date(ts).getTime()) / 1000
    if (diff < 60) return `${Math.floor(diff)}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
    return `${Math.floor(diff / 86400)}d ago`
}

function EventRow({ event }) {
    const [open, setOpen] = useState(false)
    const style = actionStyle(event.action)
    const hasDetails = event.details && Object.keys(event.details).length > 0

    return (
        <div className={`rounded-xl border transition-colors ${open ? 'border-white/[0.14] bg-white/[0.04]' : 'border-white/[0.06] bg-white/[0.02] hover:bg-white/[0.04]'}`}>
            <button
                type="button"
                onClick={() => hasDetails && setOpen(o => !o)}
                className="w-full flex items-center gap-3 px-4 py-3 text-left"
                disabled={!hasDetails}
            >
                {/* Action badge */}
                <span className={`flex-shrink-0 px-2 py-0.5 rounded-md border text-[10px] font-mono uppercase tracking-widest ${style.bg} ${style.border} ${style.text}`}>
                    {event.action.replace(/_/g, ' ')}
                </span>

                {/* Resource */}
                <span className="flex-1 min-w-0 text-[12px] text-text-secondary font-mono truncate">
                    {event.resource || '—'}
                </span>

                {/* Actor */}
                <span className="flex items-center gap-1.5 text-[11px] text-text-muted flex-shrink-0">
                    <User className="w-3 h-3" />
                    {event.actor || 'system'}
                </span>

                {/* IP */}
                {event.ip_address && (
                    <span className="hidden md:flex items-center gap-1.5 text-[11px] text-text-muted flex-shrink-0">
                        <Globe className="w-3 h-3" />
                        {event.ip_address}
                    </span>
                )}

                {/* Time */}
                <span className="flex items-center gap-1.5 text-[11px] text-text-muted flex-shrink-0" title={fmtTime(event.timestamp)}>
                    <Clock className="w-3 h-3" />
                    {fmtRelative(event.timestamp)}
                </span>

                {hasDetails && (
                    open ? <ChevronUp className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                         : <ChevronDown className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                )}
            </button>

            <AnimatePresence>
                {open && hasDetails && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.18 }}
                        className="overflow-hidden"
                    >
                        <pre className="px-4 pb-4 text-[11px] text-text-secondary font-mono leading-relaxed overflow-x-auto">
                            {JSON.stringify(event.details, null, 2)}
                        </pre>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    )
}

const PAGE_SIZE = 50

export default function AuditLog() {
    const [events, setEvents] = useState([])
    const [loading, setLoading] = useState(true)
    const [query, setQuery] = useState('')
    const [actorFilter, setActorFilter] = useState('')
    const [actionFilter, setActionFilter] = useState('')
    const [page, setPage] = useState(1)

    const fetchEvents = useCallback(async () => {
        try {
            const params = new URLSearchParams()
            if (actorFilter) params.set('actor', actorFilter)
            const res = await fetch(`/api/audit${params.toString() ? '?' + params : ''}`)
            if (res.ok) {
                const data = await res.json()
                setEvents((data || []).slice().reverse())
            }
        } catch {
            // silent
        } finally {
            setLoading(false)
        }
    }, [actorFilter])

    useEffect(() => {
        setLoading(true)
        fetchEvents()
        const id = setInterval(fetchEvents, 20000)
        return () => clearInterval(id)
    }, [fetchEvents])

    // Unique action types for filter dropdown
    const actionTypes = [...new Set(events.map(e => e.action))].sort()

    const filtered = events.filter(e => {
        const q = query.toLowerCase()
        if (q && !e.action.includes(q) && !(e.resource || '').toLowerCase().includes(q) && !(e.actor || '').toLowerCase().includes(q)) return false
        if (actionFilter && e.action !== actionFilter) return false
        return true
    })

    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
    const pageEvents = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

    function exportCSV() {
        const rows = [['ID', 'Timestamp', 'Actor', 'Action', 'Resource', 'IP']]
        filtered.forEach(e => rows.push([e.id, e.timestamp, e.actor, e.action, e.resource, e.ip_address || '']))
        const csv = rows.map(r => r.map(c => `"${(c || '').toString().replace(/"/g, '""')}"`).join(',')).join('\n')
        const blob = new Blob([csv], { type: 'text/csv' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = 'audit-log.csv'; a.click()
        URL.revokeObjectURL(url)
    }

    return (
        <div className="px-6 py-8 max-w-6xl mx-auto space-y-6">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-semibold text-text-primary flex items-center gap-2.5">
                        <ClipboardList className="w-6 h-6 text-accent-cyan" />
                        Audit Log
                    </h1>
                    <p className="text-sm text-text-muted mt-1">Platform-wide event trail — every scan, finding, config change, and schedule fire.</p>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        type="button"
                        onClick={exportCSV}
                        className="lg-pill text-[11px]"
                        title="Export filtered events as CSV"
                    >
                        <Download className="w-3.5 h-3.5" />
                        Export CSV
                    </button>
                    <button
                        type="button"
                        onClick={() => { setLoading(true); fetchEvents() }}
                        className="lg-pill text-[11px]"
                        title="Refresh"
                    >
                        <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                </div>
            </div>

            {/* Stats strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                    { label: 'Total Events', value: events.length },
                    { label: 'Filtered', value: filtered.length },
                    { label: 'Action Types', value: actionTypes.length },
                    { label: 'Actors', value: [...new Set(events.map(e => e.actor))].length },
                ].map(({ label, value }) => (
                    <div key={label} className="lg-surface-card px-4 py-3 rounded-xl text-center">
                        <div className="text-xl font-semibold text-text-primary">{value}</div>
                        <div className="text-[10px] text-text-muted uppercase tracking-widest mt-0.5">{label}</div>
                    </div>
                ))}
            </div>

            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-48">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
                    <input
                        value={query}
                        onChange={e => { setQuery(e.target.value); setPage(1) }}
                        placeholder="Search events, actors, resources…"
                        className="w-full pl-9 pr-3 py-2 rounded-xl bg-white/[0.04] border border-white/[0.08] text-sm text-text-primary placeholder:text-text-muted outline-none focus:border-accent-cyan/40 transition-colors"
                    />
                    {query && (
                        <button type="button" onClick={() => { setQuery(''); setPage(1) }} className="absolute right-3 top-1/2 -translate-y-1/2">
                            <X className="w-3.5 h-3.5 text-text-muted hover:text-text-primary" />
                        </button>
                    )}
                </div>

                <div className="relative">
                    <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted pointer-events-none" />
                    <select
                        value={actionFilter}
                        onChange={e => { setActionFilter(e.target.value); setPage(1) }}
                        className="pl-9 pr-8 py-2 rounded-xl bg-white/[0.04] border border-white/[0.08] text-sm text-text-primary outline-none focus:border-accent-cyan/40 appearance-none cursor-pointer"
                    >
                        <option value="">All actions</option>
                        {actionTypes.map(a => (
                            <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>
                        ))}
                    </select>
                </div>

                <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted pointer-events-none" />
                    <input
                        value={actorFilter}
                        onChange={e => { setActorFilter(e.target.value); setPage(1) }}
                        placeholder="Filter by actor…"
                        className="pl-9 pr-3 py-2 rounded-xl bg-white/[0.04] border border-white/[0.08] text-sm text-text-primary placeholder:text-text-muted outline-none focus:border-accent-cyan/40 transition-colors w-44"
                    />
                </div>
            </div>

            {/* Event list */}
            <div className="space-y-1.5">
                {loading ? (
                    Array.from({ length: 8 }).map((_, i) => (
                        <div key={i} className="h-12 rounded-xl bg-white/[0.03] animate-pulse" />
                    ))
                ) : pageEvents.length === 0 ? (
                    <div className="text-center py-20 text-text-muted text-sm">
                        {events.length === 0 ? 'No audit events recorded yet. Events appear as scans run.' : 'No events match the current filters.'}
                    </div>
                ) : (
                    pageEvents.map(event => <EventRow key={event.id} event={event} />)
                )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-between pt-2">
                    <span className="text-[11px] text-text-muted">
                        Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, filtered.length)} of {filtered.length}
                    </span>
                    <div className="flex items-center gap-1.5">
                        <button
                            type="button"
                            disabled={page === 1}
                            onClick={() => setPage(p => p - 1)}
                            className="px-3 py-1.5 rounded-lg text-[12px] bg-white/[0.04] border border-white/[0.08] text-text-secondary disabled:opacity-30 hover:bg-white/[0.08] transition-colors"
                        >
                            Prev
                        </button>
                        {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                            const p = totalPages <= 7 ? i + 1 : page <= 4 ? i + 1 : page >= totalPages - 3 ? totalPages - 6 + i : page - 3 + i
                            return (
                                <button
                                    key={p}
                                    type="button"
                                    onClick={() => setPage(p)}
                                    className={`w-8 h-8 rounded-lg text-[12px] transition-colors ${p === page ? 'bg-accent-cyan/20 border border-accent-cyan/40 text-accent-cyan' : 'bg-white/[0.04] border border-white/[0.08] text-text-secondary hover:bg-white/[0.08]'}`}
                                >
                                    {p}
                                </button>
                            )
                        })}
                        <button
                            type="button"
                            disabled={page === totalPages}
                            onClick={() => setPage(p => p + 1)}
                            className="px-3 py-1.5 rounded-lg text-[12px] bg-white/[0.04] border border-white/[0.08] text-text-secondary disabled:opacity-30 hover:bg-white/[0.08] transition-colors"
                        >
                            Next
                        </button>
                    </div>
                </div>
            )}
        </div>
    )
}
