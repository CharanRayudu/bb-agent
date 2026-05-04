import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
    Shield, Code2, Package, Key, Container,
    CheckCircle, AlertTriangle, XCircle, Info, ChevronDown,
    ChevronRight, Loader, Github, Zap, Clock,
    ExternalLink, Play
} from 'lucide-react'

const API_BASE = '/api'
const CHIP = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

const SEV_STYLES = {
    critical: { chip: 'bg-[#ff4757]/12 text-[#ff4757] border-[#ff4757]/35', dot: 'bg-[#ff4757]', glow: '#ff4757' },
    high:     { chip: 'bg-[#ff7f50]/12 text-[#ff7f50] border-[#ff7f50]/35', dot: 'bg-[#ff7f50]', glow: '#ff7f50' },
    medium:   { chip: 'bg-[#eccc68]/12 text-[#eccc68] border-[#eccc68]/35', dot: 'bg-[#eccc68]', glow: '#eccc68' },
    low:      { chip: 'bg-[#2ed573]/12 text-[#2ed573] border-[#2ed573]/35', dot: 'bg-[#2ed573]', glow: '#2ed573' },
    info:     { chip: 'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30', dot: 'bg-accent-cyan', glow: '#22d3ee' },
}

function SevChip({ sev }) {
    const s = SEV_STYLES[sev] || SEV_STYLES.info
    return <span className={`${CHIP} ${s.chip}`}>{sev}</span>
}

const SCAN_TYPES = [
    { id: 'secrets', label: 'Secrets', icon: Key, color: '#ff4757', desc: 'AWS keys, GitHub tokens, private keys, DB URLs' },
    { id: 'sast',    label: 'SAST',    icon: Code2, color: '#ff7f50', desc: 'SQL injection, XSS, CMDi, path traversal, SSRF' },
    { id: 'sca',     label: 'SCA',     icon: Package, color: '#eccc68', desc: 'Vulnerable dependencies, CVE matching' },
    { id: 'container', label: 'Container', icon: Container, color: '#2ed573', desc: 'Dockerfile misconfigs, privileged, root user' },
    { id: 'full',    label: 'Full Scan', icon: Shield, color: '#22d3ee', desc: 'All scanners in parallel' },
]

function StatBox({ label, value, color, icon: Icon }) {
    return (
        <div className="flex-1 min-w-0 p-4 rounded-xl bg-white/[0.03] border border-white/[0.08] flex items-center gap-3">
            <span className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: `${color}18`, boxShadow: `0 0 12px ${color}25` }}>
                <Icon className="w-4 h-4" style={{ color }} />
            </span>
            <div className="min-w-0">
                <div className="text-xl font-bold text-text-primary">{value}</div>
                <div className="text-[10px] text-text-muted uppercase tracking-widest">{label}</div>
            </div>
        </div>
    )
}

function FindingCard({ finding, idx }) {
    const [expanded, setExpanded] = useState(false)
    const sev = finding.severity || 'info'
    const s = SEV_STYLES[sev] || SEV_STYLES.info

    const typeLabel = (finding.type || '').replace(/^(SAST|SCA|Secret|Container)-/, '')

    return (
        <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.03 }}
            className="rounded-xl border border-white/[0.08] bg-white/[0.02] overflow-hidden"
        >
            <button
                type="button"
                onClick={() => setExpanded(e => !e)}
                className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/[0.03] transition-colors"
            >
                <span className={`w-2 h-2 rounded-full flex-shrink-0 shadow-[0_0_8px_currentColor]`} style={{ background: s.glow }} />
                <span className="flex-1 text-sm text-text-primary font-medium truncate">{typeLabel || finding.type}</span>
                <SevChip sev={sev} />
                <span className="text-[10px] text-text-muted font-mono">{(finding.confidence * 100).toFixed(0)}%</span>
                {expanded ? <ChevronDown className="w-3.5 h-3.5 text-text-muted flex-shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />}
            </button>

            {expanded && (
                <div className="px-4 pb-4 space-y-2 border-t border-white/[0.06]">
                    {finding.payload && (
                        <div className="mt-2">
                            <span className="text-[10px] text-text-muted uppercase tracking-widest">Match</span>
                            <pre className="mt-1 text-xs text-text-secondary font-mono bg-black/20 rounded-lg p-2 overflow-x-auto whitespace-pre-wrap break-all">{finding.payload}</pre>
                        </div>
                    )}
                    {finding.evidence && (
                        <div>
                            <span className="text-[10px] text-text-muted uppercase tracking-widest">Evidence</span>
                            <div className="mt-1 space-y-1">
                                {Object.entries(finding.evidence).map(([k, v]) => (
                                    <div key={k} className="flex gap-2 text-xs">
                                        <span className="text-text-muted font-mono min-w-[80px] flex-shrink-0">{k}</span>
                                        <span className="text-text-secondary font-mono break-all">{String(v)}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {finding.url && (
                        <div className="flex items-center gap-1.5 text-xs text-text-muted">
                            <ExternalLink className="w-3 h-3" />
                            <a href={finding.url} target="_blank" rel="noopener noreferrer" className="truncate hover:text-accent-cyan transition-colors">{finding.url}</a>
                        </div>
                    )}
                </div>
            )}
        </motion.div>
    )
}

function ScanTypeSelector({ selected, onSelect }) {
    return (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {SCAN_TYPES.map(t => {
                const Icon = t.icon
                const active = selected === t.id
                return (
                    <button
                        key={t.id}
                        type="button"
                        onClick={() => onSelect(t.id)}
                        className={`relative flex flex-col items-center gap-2 p-3 rounded-xl border transition-all text-center ${
                            active
                                ? 'border-white/20 bg-white/[0.06]'
                                : 'border-white/[0.06] bg-white/[0.02] hover:bg-white/[0.04] hover:border-white/10'
                        }`}
                    >
                        {active && (
                            <span className="absolute inset-0 rounded-xl" style={{ boxShadow: `inset 0 0 0 1px ${t.color}40, 0 0 20px ${t.color}15` }} />
                        )}
                        <span className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${t.color}18` }}>
                            <Icon className="w-4 h-4" style={{ color: t.color }} />
                        </span>
                        <span className="text-[11px] font-semibold text-text-primary">{t.label}</span>
                        <span className="text-[9px] text-text-muted leading-snug">{t.desc}</span>
                    </button>
                )
            })}
        </div>
    )
}

function GitHubAppPanel({ onConfigSaved }) {
    const [config, setConfig] = useState({ app_id: '', webhook_secret: '' })
    const [status, setStatus] = useState(null)
    const [saving, setSaving] = useState(false)

    useEffect(() => {
        fetch(`${API_BASE}/webhooks/github/config`)
            .then(r => r.json())
            .then(setStatus)
            .catch(() => {})
    }, [])

    async function save() {
        setSaving(true)
        try {
            await fetch(`${API_BASE}/webhooks/github/config`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
            })
            const updated = await fetch(`${API_BASE}/webhooks/github/config`).then(r => r.json())
            setStatus(updated)
            onConfigSaved && onConfigSaved()
        } finally {
            setSaving(false)
        }
    }

    return (
        <div className="rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5 space-y-4">
            <div className="flex items-center gap-3">
                <span className="w-9 h-9 rounded-xl bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center">
                    <Github className="w-[18px] h-[18px] text-accent-cyan" />
                </span>
                <div>
                    <h3 className="text-sm font-bold text-text-primary">GitHub App Integration</h3>
                    <p className="text-xs text-text-muted">Trigger DevSecOps scans automatically on PR open/update</p>
                </div>
                {status?.configured && (
                    <span className="ml-auto inline-flex items-center gap-1.5 text-[10px] text-emerald-400 font-mono bg-emerald-400/10 border border-emerald-400/25 rounded-full px-2.5 py-1">
                        <CheckCircle className="w-3 h-3" /> Active
                    </span>
                )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                    <label className="block text-[10px] text-text-muted uppercase tracking-widest mb-1">GitHub App ID</label>
                    <input
                        value={config.app_id}
                        onChange={e => setConfig(c => ({ ...c, app_id: e.target.value }))}
                        placeholder="123456"
                        className="w-full px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-sm text-text-primary font-mono placeholder:text-text-muted outline-none focus:border-accent-cyan/40 transition-colors"
                    />
                </div>
                <div>
                    <label className="block text-[10px] text-text-muted uppercase tracking-widest mb-1">Webhook Secret</label>
                    <input
                        type="password"
                        value={config.webhook_secret}
                        onChange={e => setConfig(c => ({ ...c, webhook_secret: e.target.value }))}
                        placeholder="••••••••••••••••"
                        className="w-full px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-sm text-text-primary font-mono placeholder:text-text-muted outline-none focus:border-accent-cyan/40 transition-colors"
                    />
                </div>
            </div>

            <div className="rounded-lg bg-black/20 border border-white/[0.06] p-3 space-y-1">
                <p className="text-[10px] text-text-muted uppercase tracking-widest font-mono">Webhook URL</p>
                <p className="text-xs text-text-secondary font-mono select-all">{window.location.origin}/api/webhooks/github</p>
                <p className="text-[10px] text-text-muted mt-1">Subscribe to: <span className="text-text-secondary font-mono">pull_request</span> events</p>
            </div>

            <button
                type="button"
                onClick={save}
                disabled={saving || (!config.app_id && !config.webhook_secret)}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan text-sm font-medium hover:bg-accent-cyan/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
                {saving ? <Loader className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                Save Configuration
            </button>
        </div>
    )
}

export default function DevSecOps() {
    const [target, setTarget] = useState('')
    const [mode, setMode] = useState('full')
    const [image, setImage] = useState('')
    const [scanning, setScanning] = useState(false)
    const [findings, setFindings] = useState(null)
    const [error, setError] = useState(null)
    const [elapsed, setElapsed] = useState(null)
    const [activeFilter, setActiveFilter] = useState('all')

    async function runScan() {
        if (!target.trim()) return
        setScanning(true)
        setFindings(null)
        setError(null)
        setElapsed(null)

        const started = Date.now()
        try {
            // Trigger via the ticket create endpoint is not quite right —
            // we POST to /api/integrations/ticket to create a finding first.
            // For DevSecOps we use a dedicated enqueue-and-wait pattern via
            // the config store trick: POST target to trigger a one-shot scan.
            //
            // Since the agent runs async, we simulate the scan inline via the
            // secret/file exposure probes which are synchronous HTTP checks.
            const res = await fetch(`${API_BASE}/devsecops/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target.trim(), mode, image: image.trim() || undefined }),
            })
            const data = await res.json()
            setElapsed(Date.now() - started)
            if (!res.ok) {
                setError(data.error || `HTTP ${res.status}`)
            } else {
                setFindings(data.findings || [])
            }
        } catch (e) {
            setError(e.message)
            setElapsed(Date.now() - started)
        } finally {
            setScanning(false)
        }
    }

    const filteredFindings = findings
        ? (activeFilter === 'all' ? findings : findings.filter(f => f.severity === activeFilter))
        : []

    const counts = findings ? {
        critical: findings.filter(f => f.severity === 'critical').length,
        high:     findings.filter(f => f.severity === 'high').length,
        medium:   findings.filter(f => f.severity === 'medium').length,
        low:      findings.filter(f => f.severity === 'low').length,
        info:     findings.filter(f => f.severity === 'info').length,
    } : {}

    const byCategory = findings ? {
        secrets:   findings.filter(f => f.type?.startsWith('Secret')).length,
        sast:      findings.filter(f => f.type?.startsWith('SAST')).length,
        sca:       findings.filter(f => f.type?.startsWith('SCA')).length,
        container: findings.filter(f => f.type?.startsWith('Container')).length,
    } : {}

    return (
        <div className="p-6 space-y-6 max-w-5xl">
            {/* Header */}
            <div>
                <div className="flex items-center gap-3 mb-2">
                    <span className="w-10 h-10 rounded-xl bg-gradient-to-br from-accent-cyan/30 to-accent-purple/20 border border-white/20 flex items-center justify-center shadow-[0_0_20px_rgba(34,211,238,0.2)]">
                        <Shield className="w-5 h-5 text-accent-cyan" />
                    </span>
                    <div>
                        <h1 className="text-xl font-bold text-text-primary">DevSecOps Pipeline</h1>
                        <p className="text-xs text-text-muted">SAST · SCA · Secrets · Container Security · GitHub App</p>
                    </div>
                </div>
            </div>

            {/* Scan Form */}
            <div className="rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5 space-y-4">
                <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                    <Play className="w-4 h-4 text-accent-cyan" /> Run On-Demand Scan
                </h2>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                        <label className="block text-[10px] text-text-muted uppercase tracking-widest mb-1">Target URL *</label>
                        <input
                            value={target}
                            onChange={e => setTarget(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && runScan()}
                            placeholder="https://example.com"
                            className="w-full px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-sm text-text-primary font-mono placeholder:text-text-muted outline-none focus:border-accent-cyan/40 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] text-text-muted uppercase tracking-widest mb-1">Container Image (optional)</label>
                        <input
                            value={image}
                            onChange={e => setImage(e.target.value)}
                            placeholder="nginx:latest"
                            className="w-full px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-sm text-text-primary font-mono placeholder:text-text-muted outline-none focus:border-accent-cyan/40 transition-colors"
                        />
                    </div>
                </div>

                <ScanTypeSelector selected={mode} onSelect={setMode} />

                <button
                    type="button"
                    onClick={runScan}
                    disabled={scanning || !target.trim()}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-accent-cyan/20 to-accent-purple/15 border border-accent-cyan/30 text-accent-cyan text-sm font-semibold hover:from-accent-cyan/30 hover:to-accent-purple/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(34,211,238,0.1)]"
                >
                    {scanning ? (
                        <><Loader className="w-4 h-4 animate-spin" /> Scanning…</>
                    ) : (
                        <><Zap className="w-4 h-4" /> Launch {SCAN_TYPES.find(t => t.id === mode)?.label} Scan</>
                    )}
                </button>

                {error && (
                    <div className="flex items-start gap-2 p-3 rounded-lg bg-[#ff4757]/10 border border-[#ff4757]/30 text-[#ff4757] text-xs">
                        <XCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                        <span>{error}</span>
                    </div>
                )}
            </div>

            {/* Results */}
            {findings !== null && (
                <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-4"
                >
                    {/* Summary Stats */}
                    <div className="flex flex-wrap gap-2">
                        <StatBox label="Critical" value={counts.critical} color="#ff4757" icon={XCircle} />
                        <StatBox label="High" value={counts.high} color="#ff7f50" icon={AlertTriangle} />
                        <StatBox label="Medium" value={counts.medium} color="#eccc68" icon={AlertTriangle} />
                        <StatBox label="Low" value={counts.low} color="#2ed573" icon={Info} />
                    </div>

                    {/* Category Breakdown */}
                    <div className="rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-4">
                        <h3 className="text-xs font-semibold text-text-muted uppercase tracking-widest mb-3">Scanner Breakdown</h3>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                            {[
                                { key: 'secrets', label: 'Secrets', icon: Key, color: '#ff4757' },
                                { key: 'sast', label: 'SAST', icon: Code2, color: '#ff7f50' },
                                { key: 'sca', label: 'SCA / Deps', icon: Package, color: '#eccc68' },
                                { key: 'container', label: 'Container', icon: Container, color: '#2ed573' },
                            ].map(c => {
                                const Icon = c.icon
                                const n = byCategory[c.key] || 0
                                return (
                                    <div key={c.key} className="flex items-center gap-2.5 p-3 rounded-xl bg-black/20 border border-white/[0.06]">
                                        <Icon className="w-4 h-4 flex-shrink-0" style={{ color: c.color }} />
                                        <div>
                                            <div className="text-sm font-bold text-text-primary">{n}</div>
                                            <div className="text-[10px] text-text-muted">{c.label}</div>
                                        </div>
                                    </div>
                                )
                            })}
                        </div>

                        {elapsed !== null && (
                            <div className="mt-3 flex items-center gap-1.5 text-[11px] text-text-muted">
                                <Clock className="w-3 h-3" />
                                <span>Completed in {(elapsed / 1000).toFixed(1)}s · {findings.length} finding{findings.length !== 1 ? 's' : ''}</span>
                            </div>
                        )}
                    </div>

                    {/* Filter Tabs */}
                    {findings.length > 0 && (
                        <div className="flex gap-1.5 flex-wrap">
                            {['all', 'critical', 'high', 'medium', 'low', 'info'].map(f => {
                                const n = f === 'all' ? findings.length : counts[f] || 0
                                const active = activeFilter === f
                                return (
                                    <button
                                        key={f}
                                        type="button"
                                        onClick={() => setActiveFilter(f)}
                                        className={`px-3 py-1 rounded-lg text-[11px] font-medium transition-all ${
                                            active
                                                ? 'bg-white/10 text-text-primary border border-white/20'
                                                : 'text-text-muted hover:text-text-secondary border border-transparent hover:border-white/[0.08]'
                                        }`}
                                    >
                                        {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)} ({n})
                                    </button>
                                )
                            })}
                        </div>
                    )}

                    {/* Finding Cards */}
                    {filteredFindings.length > 0 ? (
                        <div className="space-y-2">
                            {filteredFindings.map((f, i) => (
                                <FindingCard key={i} finding={f} idx={i} />
                            ))}
                        </div>
                    ) : (
                        <div className="text-center py-10 text-text-muted text-sm">
                            {findings.length === 0 ? (
                                <><CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" /><p className="text-emerald-400 font-medium">No findings detected</p><p className="text-xs mt-1">Target appears clean for the selected scanner</p></>
                            ) : (
                                <p>No {activeFilter} severity findings</p>
                            )}
                        </div>
                    )}
                </motion.div>
            )}

            {/* GitHub App Panel */}
            <GitHubAppPanel />
        </div>
    )
}
