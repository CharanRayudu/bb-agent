import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Zap, Shield, Code2, Globe, GitPullRequest, BookOpen, Target,
    Settings, Plus, Copy, Trash2, ArrowRight, Tag, Star,
    Check, X, ChevronDown
} from 'lucide-react'

const API_BASE = '/api'

const CATEGORY_TABS = [
    { id: 'all',        label: 'All' },
    { id: 'web',        label: 'Web App' },
    { id: 'api',        label: 'API' },
    { id: 'cloud',      label: 'Cloud' },
    { id: 'devsecops',  label: 'DevSecOps' },
    { id: 'compliance', label: 'Compliance' },
    { id: 'custom',     label: 'Custom' },
]

const ICON_MAP = {
    Zap, Shield, Code2, Globe, GitPullRequest, BookOpen, Target, Settings,
}

const CHIP = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

// ── Profile card ─────────────────────────────────────────────────────────────

function ProfileCard({ profile, onUse, onClone, onDelete, onEdit }) {
    const [cloning, setCloning] = useState(false)
    const Icon = ICON_MAP[profile.icon] || Settings
    const c = profile.color || '#67e8f9'

    async function handleClone() {
        setCloning(true)
        await onClone(profile.id)
        setCloning(false)
    }

    return (
        <motion.div
            layout
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.025] backdrop-blur-xl flex flex-col group"
        >
            {/* Glow */}
            <div className="absolute -top-12 -right-12 w-32 h-32 rounded-full blur-3xl opacity-20 transition-opacity group-hover:opacity-35"
                style={{ background: `radial-gradient(circle, ${c}, transparent 70%)` }} />

            {/* Header */}
            <div className="relative z-10 flex items-start gap-3 p-5 pb-3">
                <div className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0 border transition-all"
                    style={{ background: `${c}18`, borderColor: `${c}35`, boxShadow: `0 0 16px ${c}20` }}>
                    <Icon className="w-5 h-5" style={{ color: c }} />
                </div>
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                        <h3 className="text-sm font-bold text-text-primary truncate">{profile.name}</h3>
                        {profile.builtin && (
                            <span className={CHIP} style={{ color: c, borderColor: `${c}40`, background: `${c}12` }}>
                                <Star className="w-2 h-2" /> built-in
                            </span>
                        )}
                    </div>
                    <p className="text-[11px] text-text-muted capitalize">{profile.category.replace('-', ' ')}</p>
                </div>
                {profile.use_count > 0 && (
                    <span className="text-[10px] font-mono text-text-muted flex-shrink-0">{profile.use_count}× used</span>
                )}
            </div>

            {/* Description */}
            <div className="relative z-10 px-5 pb-3">
                <p className="text-xs text-text-muted leading-relaxed line-clamp-2">{profile.description}</p>
            </div>

            {/* Tags */}
            <div className="relative z-10 px-5 pb-4 flex flex-wrap gap-1.5">
                {(profile.tags || []).slice(0, 4).map(tag => (
                    <span key={tag} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/[0.05] border border-white/[0.08] text-text-muted">
                        {tag}
                    </span>
                ))}
                {profile.agents?.length > 0 && (
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/[0.05] border border-white/[0.08] text-text-muted flex items-center gap-1">
                        <Zap className="w-2 h-2" /> {profile.agents.filter(a => a.enabled).length} agents
                    </span>
                )}
            </div>

            {/* Actions */}
            <div className="relative z-10 mt-auto border-t border-white/[0.06] flex items-center">
                <button
                    onClick={() => onUse(profile)}
                    className="flex-1 flex items-center justify-center gap-2 py-3 text-xs font-semibold transition-all hover:bg-white/[0.04]"
                    style={{ color: c }}
                >
                    <ArrowRight className="w-3.5 h-3.5" /> Use Profile
                </button>
                <div className="w-px h-6 bg-white/[0.08]" />
                <button onClick={handleClone} disabled={cloning}
                    className="px-4 py-3 text-text-muted hover:text-text-primary transition-colors"
                    title="Clone">
                    {cloning ? <div className="w-3.5 h-3.5 border border-current border-t-transparent rounded-full animate-spin" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                {!profile.builtin && (
                    <>
                        <div className="w-px h-6 bg-white/[0.08]" />
                        <button onClick={() => onEdit(profile)}
                            className="px-4 py-3 text-text-muted hover:text-text-primary transition-colors"
                            title="Edit">
                            <Settings className="w-3.5 h-3.5" />
                        </button>
                        <div className="w-px h-6 bg-white/[0.08]" />
                        <button onClick={() => onDelete(profile.id)}
                            className="px-4 py-3 text-text-muted hover:text-[#ff4757] transition-colors"
                            title="Delete">
                            <Trash2 className="w-3.5 h-3.5" />
                        </button>
                    </>
                )}
            </div>
        </motion.div>
    )
}

// ── Create / Edit modal ───────────────────────────────────────────────────────

const AGENT_SUGGESTIONS = [
    'reconnaissance', 'web_spider', 'xss_scanner', 'sqli_scanner', 'ssrf_scanner',
    'lfi_scanner', 'idor_scanner', 'auth_tester', 'cors_analyzer', 'header_analyzer',
    'tls_analyzer', 'api_fuzzer', 'devsecops', 'cloud_enum', 'mass_assignment',
]

const COLOR_PRESETS = ['#67e8f9', '#c4b5fd', '#6ee7b7', '#fbbf24', '#f87171', '#ff7f50', '#a78bfa', '#34d399']

function ProfileModal({ initial, onSave, onClose }) {
    const isEdit = !!initial?.id && !initial?.builtin
    const [name, setName] = useState(initial?.name || '')
    const [description, setDescription] = useState(initial?.description || '')
    const [category, setCategory] = useState(initial?.category || 'custom')
    const [color, setColor] = useState(initial?.color || '#67e8f9')
    const [tags, setTags] = useState((initial?.tags || []).join(', '))
    const [agents, setAgents] = useState(
        (initial?.agents || []).map(a => a.id).join(', ')
    )
    const [saving, setSaving] = useState(false)

    async function submit() {
        if (!name.trim()) return
        setSaving(true)
        const agentList = agents.split(',').map(s => s.trim()).filter(Boolean)
            .map(id => ({ id, enabled: true }))
        const tagList = tags.split(',').map(s => s.trim()).filter(Boolean)
        await onSave({ name: name.trim(), description, category, color, agents: agentList, tags: tagList })
        setSaving(false)
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-md" onClick={onClose}>
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
                className="bg-[#0d1117]/95 border border-white/10 rounded-2xl p-6 w-full max-w-lg shadow-[0_24px_64px_rgba(0,0,0,0.7)]"
                onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between mb-5">
                    <h2 className="text-sm font-bold text-text-primary">
                        {isEdit ? 'Edit Profile' : 'Create Custom Profile'}
                    </h2>
                    <button onClick={onClose} className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.05] transition-colors">
                        <X className="w-4 h-4" />
                    </button>
                </div>

                <div className="space-y-4">
                    {/* Name */}
                    <div>
                        <label className="block text-[11px] text-text-muted mb-1.5">Profile Name *</label>
                        <input value={name} onChange={e => setName(e.target.value)}
                            placeholder="My Custom Profile"
                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-3 py-2 text-sm text-text-primary outline-none focus:border-accent-cyan/40" />
                    </div>

                    {/* Description */}
                    <div>
                        <label className="block text-[11px] text-text-muted mb-1.5">Description</label>
                        <textarea value={description} onChange={e => setDescription(e.target.value)}
                            rows={2} placeholder="What this profile scans for…"
                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-3 py-2 text-sm text-text-secondary outline-none focus:border-accent-cyan/40 resize-none" />
                    </div>

                    {/* Category + Color */}
                    <div className="grid grid-cols-2 gap-3">
                        <div>
                            <label className="block text-[11px] text-text-muted mb-1.5">Category</label>
                            <div className="relative">
                                <select value={category} onChange={e => setCategory(e.target.value)}
                                    className="w-full appearance-none bg-white/[0.04] border border-white/10 rounded-xl px-3 py-2 text-sm text-text-secondary outline-none focus:border-accent-cyan/40 pr-7">
                                    {['web', 'api', 'cloud', 'devsecops', 'compliance', 'custom'].map(c => (
                                        <option key={c} value={c}>{c}</option>
                                    ))}
                                </select>
                                <ChevronDown className="absolute right-2.5 top-2.5 w-3.5 h-3.5 text-text-muted pointer-events-none" />
                            </div>
                        </div>
                        <div>
                            <label className="block text-[11px] text-text-muted mb-1.5">Accent Color</label>
                            <div className="flex gap-1.5 flex-wrap">
                                {COLOR_PRESETS.map(c => (
                                    <button key={c} onClick={() => setColor(c)}
                                        className="w-6 h-6 rounded-lg border-2 transition-all"
                                        style={{ background: c, borderColor: color === c ? 'white' : 'transparent' }}>
                                        {color === c && <Check className="w-3 h-3 text-black mx-auto" />}
                                    </button>
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Agents */}
                    <div>
                        <label className="block text-[11px] text-text-muted mb-1.5">Agents (comma-separated)</label>
                        <input value={agents} onChange={e => setAgents(e.target.value)}
                            placeholder="reconnaissance, xss_scanner, sqli_scanner"
                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-3 py-2 text-sm text-text-primary outline-none focus:border-accent-cyan/40 font-mono" />
                        <div className="mt-1.5 flex flex-wrap gap-1">
                            {AGENT_SUGGESTIONS.map(a => (
                                <button key={a} type="button"
                                    onClick={() => {
                                        const cur = agents.split(',').map(s => s.trim()).filter(Boolean)
                                        if (!cur.includes(a)) setAgents([...cur, a].join(', '))
                                    }}
                                    className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-text-muted hover:text-text-secondary hover:border-white/20 transition-colors">
                                    + {a}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Tags */}
                    <div>
                        <label className="block text-[11px] text-text-muted mb-1.5">Tags (comma-separated)</label>
                        <input value={tags} onChange={e => setTags(e.target.value)}
                            placeholder="web, custom, quarterly"
                            className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-3 py-2 text-sm text-text-secondary outline-none focus:border-accent-cyan/40" />
                    </div>
                </div>

                <div className="flex gap-3 mt-6">
                    <button onClick={submit} disabled={!name.trim() || saving}
                        className="flex-1 lg-btn py-2.5 text-sm disabled:opacity-50">
                        {saving
                            ? <div className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin mx-auto" />
                            : isEdit ? 'Save Changes' : 'Create Profile'
                        }
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

export default function ScanProfiles() {
    const navigate = useNavigate()
    const [profileList, setProfileList] = useState([])
    const [category, setCategory] = useState('all')
    const [loading, setLoading] = useState(true)
    const [showModal, setShowModal] = useState(false)
    const [editProfile, setEditProfile] = useState(null)

    const load = useCallback(async () => {
        const data = await fetch(`${API_BASE}/profiles`).then(r => r.json()).catch(() => ({ profiles: [] }))
        setProfileList(data.profiles || [])
        setLoading(false)
    }, [])

    useEffect(() => { load() }, [load])

    const visible = category === 'all' ? profileList : profileList.filter(p => p.category === category)

    // Sort: builtin first, then by use_count desc
    const sorted = [...visible].sort((a, b) => {
        if (a.builtin !== b.builtin) return a.builtin ? -1 : 1
        return b.use_count - a.use_count
    })

    function handleUse(profile) {
        fetch(`${API_BASE}/profiles/${profile.id}/use`, { method: 'POST' }).catch(() => {})
        navigate(`/new?profile=${profile.id}&profileName=${encodeURIComponent(profile.name)}`)
    }

    async function handleClone(id) {
        await fetch(`${API_BASE}/profiles/${id}/clone`, { method: 'POST' })
        load()
    }

    async function handleDelete(id) {
        if (!confirm('Delete this profile?')) return
        await fetch(`${API_BASE}/profiles/${id}`, { method: 'DELETE' })
        load()
    }

    async function handleSave(data) {
        if (editProfile) {
            await fetch(`${API_BASE}/profiles/${editProfile.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            })
        } else {
            await fetch(`${API_BASE}/profiles`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            })
        }
        setShowModal(false)
        setEditProfile(null)
        load()
    }

    return (
        <div className="relative pb-12">
            {/* Ambient */}
            <div className="pointer-events-none absolute inset-0 -z-10">
                <div className="absolute -top-40 -left-32 w-[40rem] h-[40rem] bg-accent-purple/12 rounded-full blur-3xl" />
                <div className="absolute top-24 -right-40 w-[36rem] h-[36rem] bg-accent-cyan/8 rounded-full blur-3xl" />
            </div>

            {/* Hero */}
            <div className="mb-8 relative z-10">
                <div className="lg-surface-hero px-7 py-8 md:px-10 md:py-10">
                    <div className="absolute -right-28 -top-28 h-72 w-72 bg-accent-purple/20 blur-3xl opacity-50 pointer-events-none" />
                    <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
                            <div className="inline-flex items-center gap-2 lg-pill mb-4 text-[10px] uppercase tracking-[0.22em] font-semibold">
                                <span className="w-1.5 h-1.5 rounded-full bg-accent-purple animate-pulse" />
                                Scan Profiles
                            </div>
                            <h1 className="text-4xl md:text-5xl font-display font-semibold mb-3 tracking-[-0.02em] lg-gradient-text">
                                Scan Profiles
                            </h1>
                            <p className="text-sm text-text-secondary flex items-center gap-2">
                                <Tag className="w-4 h-4 text-accent-purple" />
                                {profileList.length} profiles · {profileList.filter(p => p.builtin).length} built-in · reusable scan configurations
                            </p>
                        </motion.div>
                        <button
                            onClick={() => { setEditProfile(null); setShowModal(true) }}
                            className="lg-btn px-5 py-3 text-sm flex-shrink-0"
                        >
                            <Plus className="w-4 h-4 relative z-10" />
                            <span className="relative z-10 font-semibold">New Profile</span>
                        </button>
                    </div>
                </div>
            </div>

            {/* Category filter */}
            <div className="relative z-10 flex items-center gap-1 mb-6 bg-white/[0.03] border border-white/[0.08] rounded-2xl p-1 w-fit flex-wrap">
                {CATEGORY_TABS.map(tab => {
                    const count = tab.id === 'all' ? profileList.length : profileList.filter(p => p.category === tab.id).length
                    const active = category === tab.id
                    return (
                        <button key={tab.id} onClick={() => setCategory(tab.id)}
                            className={`relative flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                                active ? 'text-text-primary' : 'text-text-muted hover:text-text-secondary'
                            }`}>
                            {active && (
                                <motion.span layoutId="profile-tab"
                                    className="absolute inset-0 rounded-xl bg-white/[0.08] border border-white/10"
                                    transition={{ type: 'spring', stiffness: 400, damping: 30 }} />
                            )}
                            <span className="relative z-10">{tab.label}</span>
                            {count > 0 && (
                                <span className="relative z-10 text-[9px] font-mono px-1 py-0.5 rounded text-text-muted">
                                    {count}
                                </span>
                            )}
                        </button>
                    )
                })}
            </div>

            {/* Profile grid */}
            <div className="relative z-10">
                {loading ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
                        {Array.from({ length: 6 }, (_, i) => (
                            <div key={i} className="h-52 rounded-2xl bg-white/[0.03] border border-white/[0.06] animate-pulse" />
                        ))}
                    </div>
                ) : sorted.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-24 text-center gap-4 rounded-2xl border border-white/[0.06] bg-white/[0.02]">
                        <Settings className="w-10 h-10 text-text-muted" />
                        <div>
                            <p className="text-sm font-medium text-text-secondary mb-1">No profiles in this category</p>
                            <p className="text-xs text-text-muted">Create a custom profile or switch categories.</p>
                        </div>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
                        <AnimatePresence>
                            {sorted.map(p => (
                                <ProfileCard
                                    key={p.id}
                                    profile={p}
                                    onUse={handleUse}
                                    onClone={handleClone}
                                    onDelete={handleDelete}
                                    onEdit={prof => { setEditProfile(prof); setShowModal(true) }}
                                />
                            ))}
                        </AnimatePresence>
                    </div>
                )}
            </div>

            {/* Modal */}
            <AnimatePresence>
                {showModal && (
                    <ProfileModal
                        initial={editProfile}
                        onSave={handleSave}
                        onClose={() => { setShowModal(false); setEditProfile(null) }}
                    />
                )}
            </AnimatePresence>
        </div>
    )
}
