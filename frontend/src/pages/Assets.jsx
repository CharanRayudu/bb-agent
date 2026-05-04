import React, { useState, useEffect, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
    Globe, Server, AlertTriangle, CheckCircle, Clock, ArrowRight,
    Shield, Target, ChevronDown, ChevronRight, Activity, Zap,
    Lock, Layers, Search, X
} from 'lucide-react'
import EmptyState from '../components/EmptyState'
import Pagination from '../components/Pagination'

const API_BASE = '/api'

const CHIP = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

function severityColor(sev) {
    switch (sev) {
        case 'critical': return { text: '#ff4757', bg: 'rgba(255,71,87,0.12)', border: 'rgba(255,71,87,0.35)', glow: 'rgba(255,71,87,0.25)' }
        case 'high':     return { text: '#ff7f50', bg: 'rgba(255,127,80,0.12)', border: 'rgba(255,127,80,0.35)', glow: 'rgba(255,127,80,0.20)' }
        case 'medium':   return { text: '#eccc68', bg: 'rgba(236,204,104,0.12)', border: 'rgba(236,204,104,0.35)', glow: 'rgba(236,204,104,0.15)' }
        case 'low':      return { text: '#2ed573', bg: 'rgba(46,213,115,0.12)', border: 'rgba(46,213,115,0.35)', glow: 'rgba(46,213,115,0.15)' }
        default:         return { text: '#67e8f9', bg: 'rgba(34,211,238,0.08)', border: 'rgba(34,211,238,0.25)', glow: 'rgba(34,211,238,0.12)' }
    }
}

function riskScore(findings) {
    if (!findings.length) return 100
    const weights = { critical: 40, high: 20, medium: 8, low: 2, info: 0 }
    const penalty = findings.reduce((s, f) => s + (weights[f.severity] || 0), 0)
    return Math.max(0, 100 - Math.min(penalty, 100))
}

function riskLabel(score) {
    if (score >= 80) return { label: 'Secure', color: '#2ed573' }
    if (score >= 60) return { label: 'Low Risk', color: '#eccc68' }
    if (score >= 40) return { label: 'Medium Risk', color: '#ff7f50' }
    if (score >= 20) return { label: 'High Risk', color: '#ff4757' }
    return { label: 'Critical', color: '#ff2d3b' }
}

function AssetCard({ asset, findings }) {
    const [expanded, setExpanded] = useState(false)
    const score = riskScore(findings)
    const risk = riskLabel(score)
    const critical = findings.filter(f => f.severity === 'critical').length
    const high = findings.filter(f => f.severity === 'high').length
    const medium = findings.filter(f => f.severity === 'medium').length

    const severities = ['critical', 'high', 'medium', 'low', 'info']
    const totalFindings = findings.length

    return (
        <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl shadow-[0_14px_50px_rgba(15,23,42,0.9)]"
        >
            {/* Top bar */}
            <div className="p-5 flex items-start gap-4">
                {/* Risk Score Ring */}
                <div className="flex-shrink-0 relative w-14 h-14">
                    <svg className="w-full h-full -rotate-90" viewBox="0 0 44 44">
                        <circle cx="22" cy="22" r="18" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="4" />
                        <circle
                            cx="22" cy="22" r="18" fill="none"
                            stroke={risk.color}
                            strokeWidth="4"
                            strokeLinecap="round"
                            strokeDasharray={`${(score / 100) * 113.1} 113.1`}
                            style={{ filter: `drop-shadow(0 0 4px ${risk.color})` }}
                        />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-[13px] font-bold font-mono" style={{ color: risk.color }}>{score}</span>
                    </div>
                </div>

                <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                            <h3 className="text-base font-bold text-text-primary truncate font-mono">{asset.host}</h3>
                            <div className="flex items-center gap-2 mt-1">
                                <span className={`${CHIP}`} style={{ color: risk.color, background: `rgba(${risk.color.match(/\d+/g)?.join(',')},0.1)`, borderColor: risk.color + '40' }}>
                                    {risk.label}
                                </span>
                                {asset.lastScan && (
                                    <span className="text-[10px] text-text-muted font-mono flex items-center gap-1">
                                        <Clock className="w-3 h-3" />
                                        {new Date(asset.lastScan).toLocaleDateString()}
                                    </span>
                                )}
                            </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                            <Link
                                to={`/flow/${asset.flowId}`}
                                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-accent-cyan/10 border border-accent-cyan/25 text-accent-cyan text-xs font-medium hover:bg-accent-cyan/20 transition-colors"
                            >
                                View Scan <ArrowRight className="w-3 h-3" />
                            </Link>
                        </div>
                    </div>

                    {/* Severity mini-bar */}
                    {totalFindings > 0 && (
                        <div className="mt-3 flex gap-1 h-1.5 rounded-full overflow-hidden">
                            {severities.map(sev => {
                                const count = findings.filter(f => f.severity === sev).length
                                if (!count) return null
                                const c = severityColor(sev)
                                return (
                                    <div
                                        key={sev}
                                        title={`${count} ${sev}`}
                                        style={{ flex: count, background: c.text, boxShadow: `0 0 6px ${c.glow}` }}
                                        className="rounded-full"
                                    />
                                )
                            })}
                        </div>
                    )}

                    {/* Quick stats row */}
                    <div className="mt-3 flex items-center gap-4 text-[11px] font-mono">
                        {critical > 0 && <span style={{ color: '#ff4757' }}>{critical} critical</span>}
                        {high > 0 && <span style={{ color: '#ff7f50' }}>{high} high</span>}
                        {medium > 0 && <span style={{ color: '#eccc68' }}>{medium} medium</span>}
                        {!totalFindings && <span className="text-accent-green">No findings</span>}
                        <button
                            type="button"
                            onClick={() => setExpanded(e => !e)}
                            className="ml-auto flex items-center gap-1 text-text-muted hover:text-text-primary transition-colors"
                        >
                            {expanded ? 'Hide' : 'Show'} {totalFindings} finding{totalFindings !== 1 ? 's' : ''}
                            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                        </button>
                    </div>
                </div>
            </div>

            {/* Expanded finding list */}
            {expanded && totalFindings > 0 && (
                <div className="border-t border-white/[0.06] px-5 py-3 space-y-2">
                    {findings.slice(0, 8).map((f, i) => {
                        const c = severityColor(f.severity)
                        return (
                            <div key={i} className="flex items-center gap-3 text-sm">
                                <span className={`${CHIP} flex-shrink-0`} style={{ color: c.text, background: c.bg, borderColor: c.border }}>
                                    {f.severity}
                                </span>
                                <span className="text-text-secondary truncate">{f.type || f.title}</span>
                                {f.url && <span className="text-text-muted font-mono text-[10px] truncate max-w-[160px]">{f.url}</span>}
                            </div>
                        )
                    })}
                    {findings.length > 8 && (
                        <p className="text-[11px] text-text-muted text-center pt-1">
                            +{findings.length - 8} more — <Link to={`/flow/${asset.flowId}`} className="text-accent-cyan hover:underline">view in flow</Link>
                        </p>
                    )}
                </div>
            )}
        </motion.div>
    )
}

function SeverityBreakdown({ findings }) {
    const severities = [
        { key: 'critical', label: 'Critical', color: '#ff4757' },
        { key: 'high',     label: 'High',     color: '#ff7f50' },
        { key: 'medium',   label: 'Medium',   color: '#eccc68' },
        { key: 'low',      label: 'Low',      color: '#2ed573' },
        { key: 'info',     label: 'Info',     color: '#67e8f9' },
    ]
    const total = findings.length || 1
    return (
        <div className="space-y-2.5">
            {severities.map(({ key, label, color }) => {
                const count = findings.filter(f => f.severity === key).length
                const pct = Math.round((count / total) * 100)
                return (
                    <div key={key} className="flex items-center gap-3">
                        <span className="w-14 text-[11px] font-mono text-right flex-shrink-0" style={{ color }}>{label}</span>
                        <div className="flex-1 h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
                            <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${pct}%` }}
                                transition={{ duration: 0.7, ease: 'easeOut' }}
                                className="h-full rounded-full"
                                style={{ background: color, boxShadow: `0 0 6px ${color}60` }}
                            />
                        </div>
                        <span className="w-8 text-[11px] font-mono text-text-muted text-right flex-shrink-0">{count}</span>
                    </div>
                )
            })}
        </div>
    )
}

const _NET_FINDING_TYPES = {
    NET_OPEN_PORT:                    { label: 'Open Port',               color: '#eccc68', icon: '🔌' },
    NET_REDIS_UNAUTHENTICATED:        { label: 'Redis No Auth',           color: '#ff4757', icon: '🚨' },
    NET_MONGODB_UNAUTHENTICATED:      { label: 'MongoDB No Auth',         color: '#ff4757', icon: '🚨' },
    NET_ELASTICSEARCH_UNAUTHENTICATED:{ label: 'Elasticsearch No Auth',   color: '#ff4757', icon: '🚨' },
    NET_DOCKER_API_EXPOSED:           { label: 'Docker API Exposed',      color: '#ff4757', icon: '🐳' },
    NET_FTP_ANONYMOUS:                { label: 'FTP Anonymous Login',     color: '#ffa502', icon: '📂' },
    NET_DEFAULT_CREDENTIALS:          { label: 'Default Credentials',     color: '#ff4757', icon: '🔑' },
    NET_SUBDOMAIN_TAKEOVER:           { label: 'Subdomain Takeover',      color: '#ff6b81', icon: '💀' },
    NET_SUBDOMAIN_TAKEOVER_CANDIDATE: { label: 'Takeover Candidate',      color: '#ffa502', icon: '⚠️' },
    NET_CT_SUBDOMAIN_ENUM:            { label: 'CT Subdomains Found',     color: '#2ed573', icon: '📜' },
    NET_SUBDOMAIN_BRUTE:              { label: 'Active Subdomains Found', color: '#2ed573', icon: '🌐' },
    NET_WILDCARD_CERT:                { label: 'Wildcard Certificate',    color: '#eccc68', icon: '🔒' },
}

function NetworkReconPanel({ findings }) {
    const netFindings = findings.filter(f => f.type && f.type.startsWith('NET_'))
    const criticalNet = netFindings.filter(f => f.severity === 'critical')
    const highNet = netFindings.filter(f => f.severity === 'high')
    const openPorts = netFindings.filter(f => f.type === 'NET_OPEN_PORT')
    const takeovers = netFindings.filter(f => f.type === 'NET_SUBDOMAIN_TAKEOVER' || f.type === 'NET_SUBDOMAIN_TAKEOVER_CANDIDATE')
    const subdomains = netFindings.find(f => f.type === 'NET_CT_SUBDOMAIN_ENUM' || f.type === 'NET_SUBDOMAIN_BRUTE')

    return (
        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5">
            <h3 className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-4 flex items-center gap-2">
                <Server className="w-3.5 h-3.5 text-accent-purple" />
                Network Recon
                {criticalNet.length > 0 && (
                    <span className="ml-auto text-[10px] px-2 py-0.5 rounded-full bg-accent-red/20 border border-accent-red/30 text-accent-red font-bold">
                        {criticalNet.length} CRITICAL
                    </span>
                )}
            </h3>

            {netFindings.length === 0 ? (
                <div className="text-center py-4 space-y-1">
                    <p className="text-[11px] text-text-muted">No network findings</p>
                    <p className="text-[10px] text-text-muted/60">Run a scan to probe ports, services & subdomains</p>
                </div>
            ) : (
                <div className="space-y-2">
                    {[
                        { label: 'Open Ports', value: openPorts.length, color: '#eccc68' },
                        { label: 'Critical Services', value: criticalNet.length, color: '#ff4757' },
                        { label: 'High Severity', value: highNet.length, color: '#ffa502' },
                        { label: 'Takeover Risks', value: takeovers.length, color: '#ff6b81' },
                    ].map(s => (
                        <div key={s.label} className="flex items-center justify-between text-[11px]">
                            <span className="text-text-muted">{s.label}</span>
                            <span className="font-mono font-bold" style={{ color: s.value > 0 ? s.color : '#666' }}>{s.value}</span>
                        </div>
                    ))}

                    {subdomains && (
                        <div className="mt-3 pt-3 border-t border-white/[0.06]">
                            <p className="text-[10px] text-text-muted">
                                {subdomains.type === 'NET_CT_SUBDOMAIN_ENUM' ? '📜' : '🌐'} {subdomains.evidence?.subdomains_found || 0} subdomains via {subdomains.type === 'NET_CT_SUBDOMAIN_ENUM' ? 'CT logs' : 'DNS brute-force'}
                            </p>
                        </div>
                    )}

                    {takeovers.length > 0 && (
                        <div className="mt-2 space-y-1">
                            {takeovers.slice(0, 3).map((f, i) => (
                                <div key={i} className="flex items-center gap-2 rounded-lg bg-accent-red/5 border border-accent-red/20 px-2 py-1">
                                    <span className="text-[10px]">💀</span>
                                    <span className="text-[10px] text-accent-red truncate">{f.evidence?.subdomain || f.url}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}

const CLOUD_FINDING_TYPES = {
    CLOUD_AWS_IMDS_EXPOSED:        { label: 'AWS IMDS Exposed',        provider: 'AWS',   color: '#ff4757' },
    CLOUD_AWS_IAM_CREDENTIALS_EXPOSED: { label: 'IAM Credentials Leaked', provider: 'AWS', color: '#ff4757' },
    CLOUD_AWS_CREDENTIAL_EXPOSURE: { label: 'AWS Credential File',     provider: 'AWS',   color: '#ff6b81' },
    CLOUD_S3_PUBLIC_BUCKET:        { label: 'S3 Public Bucket',        provider: 'AWS',   color: '#ffa502' },
    CLOUD_S3_BUCKET_EXISTS:        { label: 'S3 Bucket Enumerated',    provider: 'AWS',   color: '#eccc68' },
    CLOUD_AZURE_IMDS_EXPOSED:      { label: 'Azure IMDS Exposed',      provider: 'Azure', color: '#ff4757' },
    CLOUD_AZURE_AD_ENUM:           { label: 'Azure AD Enumeration',    provider: 'Azure', color: '#eccc68' },
    CLOUD_AZURE_BLOB_PUBLIC:       { label: 'Azure Blob Public',       provider: 'Azure', color: '#ffa502' },
    CLOUD_GCP_METADATA_EXPOSED:    { label: 'GCP Metadata Exposed',    provider: 'GCP',   color: '#ff4757' },
    CLOUD_GCS_PUBLIC_BUCKET:       { label: 'GCS Public Bucket',       provider: 'GCP',   color: '#ffa502' },
    CLOUD_K8S_UNAUTHENTICATED:     { label: 'K8s Unauthenticated API', provider: 'K8s',   color: '#ff4757' },
    CLOUD_CREDENTIAL_LEAK:         { label: 'Cloud Credential Leak',   provider: 'Multi', color: '#ff4757' },
}

const PROVIDER_COLORS = { AWS: '#ff9500', Azure: '#0078d4', GCP: '#4285f4', K8s: '#326ce5', Multi: '#a855f7' }

function CloudSecurityPanel({ findings }) {
    const cloudFindings = findings.filter(f => f.type && f.type.startsWith('CLOUD_'))
    const byProvider = {}
    cloudFindings.forEach(f => {
        const meta = CLOUD_FINDING_TYPES[f.type] || { label: f.type, provider: 'Cloud', color: '#888' }
        const p = meta.provider
        if (!byProvider[p]) byProvider[p] = []
        byProvider[p].push({ ...f, meta })
    })

    const providers = Object.keys(byProvider)

    return (
        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5">
            <h3 className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-4 flex items-center gap-2">
                <Lock className="w-3.5 h-3.5 text-accent-cyan" />
                Cloud Security
                {cloudFindings.length > 0 && (
                    <span className="ml-auto text-[10px] px-2 py-0.5 rounded-full bg-accent-red/20 border border-accent-red/30 text-accent-red font-bold">
                        {cloudFindings.length} FOUND
                    </span>
                )}
            </h3>

            {cloudFindings.length === 0 ? (
                <div className="text-center py-4 space-y-1">
                    <p className="text-[11px] text-text-muted">No cloud findings</p>
                    <p className="text-[10px] text-text-muted/60">Run a scan to probe AWS/Azure/GCP</p>
                </div>
            ) : (
                <div className="space-y-3">
                    {providers.map(provider => (
                        <div key={provider}>
                            <div className="flex items-center gap-2 mb-1.5">
                                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border"
                                    style={{ color: PROVIDER_COLORS[provider] || '#888', borderColor: (PROVIDER_COLORS[provider] || '#888') + '44', background: (PROVIDER_COLORS[provider] || '#888') + '11' }}>
                                    {provider}
                                </span>
                                <span className="text-[10px] text-text-muted">{byProvider[provider].length} finding{byProvider[provider].length !== 1 ? 's' : ''}</span>
                            </div>
                            <div className="space-y-1 pl-2">
                                {byProvider[provider].slice(0, 4).map((f, i) => (
                                    <div key={i} className="flex items-center gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: f.meta.color }} />
                                        <span className="text-[10px] text-text-secondary truncate">{f.meta.label}</span>
                                        <span className="ml-auto text-[9px] font-mono text-text-muted">{f.severity || 'info'}</span>
                                    </div>
                                ))}
                                {byProvider[provider].length > 4 && (
                                    <p className="text-[10px] text-text-muted pl-3.5">+{byProvider[provider].length - 4} more</p>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    )
}

const PAGE_SIZE = 10

export default function Assets() {
    const [flows, setFlows] = useState([])
    const [findings, setFindings] = useState([])
    const [loading, setLoading] = useState(true)
    const [search, setSearch] = useState('')
    const [page, setPage] = useState(1)

    useEffect(() => {
        Promise.all([
            fetch(`${API_BASE}/flows`).then(r => r.json()).catch(() => []),
            fetch(`${API_BASE}/findings`).then(r => r.json()).catch(() => []),
        ]).then(([f, fi]) => {
            setFlows(f || [])
            setFindings(fi || [])
            setLoading(false)
        })
    }, [])

    // Group findings by target host, cross-referenced with flows
    const assetMap = useMemo(() => {
        const map = {}
        flows.forEach(flow => {
            let host = flow.target
            try { host = new URL(flow.target).hostname } catch {}
            if (!map[host]) {
                map[host] = { host, flowId: flow.id, lastScan: flow.created_at, findings: [] }
            }
            if (new Date(flow.created_at) > new Date(map[host].lastScan)) {
                map[host].lastScan = flow.created_at
                map[host].flowId = flow.id
            }
        })
        findings.forEach(f => {
            let host = f.url || ''
            try { host = new URL(f.url).hostname } catch {}
            if (map[host]) map[host].findings.push(f)
            else {
                const target = f.target || f.flowName || host
                if (!map[target]) map[target] = { host: target, flowId: f.flowId, lastScan: f.timestamp, findings: [] }
                map[target].findings.push(f)
            }
        })
        return map
    }, [flows, findings])

    const allAssets = useMemo(() =>
        Object.values(assetMap).sort((a, b) => riskScore(a.findings) - riskScore(b.findings)),
        [assetMap]
    )

    const filteredAssets = useMemo(() => {
        if (!search.trim()) return allAssets
        const q = search.toLowerCase()
        return allAssets.filter(a => a.host.toLowerCase().includes(q))
    }, [allAssets, search])

    // Reset page when search changes
    useEffect(() => { setPage(1) }, [search])

    const totalPages = Math.max(1, Math.ceil(filteredAssets.length / PAGE_SIZE))
    const pagedAssets = filteredAssets.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

    const assets = allAssets
    const allFindings = findings
    const overallScore = riskScore(allFindings)
    const overallRisk = riskLabel(overallScore)

    const containerVariants = { hidden: { opacity: 0 }, visible: { opacity: 1, transition: { staggerChildren: 0.07 } } }

    return (
        <div className="relative pb-12">
            {/* Ambient */}
            <div className="pointer-events-none absolute inset-0 -z-10">
                <div className="absolute -top-40 -left-32 w-[40rem] h-[40rem] bg-accent-cyan/15 rounded-full blur-3xl" />
                <div className="absolute top-24 -right-40 w-[36rem] h-[36rem] bg-accent-purple/15 rounded-full blur-3xl" />
            </div>

            {/* Hero */}
            <div className="mb-8 relative z-10">
                <div className="lg-surface-hero px-7 py-8 md:px-10 md:py-10">
                    <div className="absolute -right-28 -top-28 h-72 w-72 bg-accent-purple/20 blur-3xl opacity-60 pointer-events-none" />
                    <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
                            <div className="inline-flex items-center gap-2 lg-pill mb-4 text-[10px] uppercase tracking-[0.22em] font-semibold">
                                <span className="w-1.5 h-1.5 rounded-full bg-accent-purple animate-pulse" />
                                Attack Surface
                            </div>
                            <h1 className="text-4xl md:text-5xl font-display font-semibold mb-3 tracking-[-0.02em] lg-gradient-text">
                                Asset Inventory
                            </h1>
                            <p className="text-sm md:text-base text-text-secondary flex items-center gap-2">
                                <Globe className="w-4 h-4 text-accent-purple" />
                                {assets.length} target{assets.length !== 1 ? 's' : ''} across {flows.length} scan{flows.length !== 1 ? 's' : ''}
                            </p>
                        </motion.div>

                        {/* Overall risk score widget */}
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ delay: 0.1, duration: 0.3 }}
                            className="flex-shrink-0 relative overflow-hidden rounded-2xl border border-white/[0.15] bg-white/[0.04] backdrop-blur-xl px-8 py-5 text-center shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
                        >
                            <div className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-2">Overall Security Score</div>
                            <div className="text-5xl font-bold font-mono" style={{ color: overallRisk.color, textShadow: `0 0 24px ${overallRisk.color}60` }}>
                                {overallScore}
                            </div>
                            <div className="text-xs font-semibold mt-1" style={{ color: overallRisk.color }}>{overallRisk.label}</div>
                        </motion.div>
                    </div>
                </div>
            </div>

            {loading ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {[1,2,3,4].map(i => (
                        <div key={i} className="h-32 rounded-2xl border border-white/10 bg-white/[0.03] animate-pulse" />
                    ))}
                </div>
            ) : (
                <div className="relative z-10 grid grid-cols-1 xl:grid-cols-3 gap-6">
                    {/* Asset list — 2/3 width */}
                    <div className="xl:col-span-2 space-y-4">
                        {/* Search bar */}
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
                            <input
                                type="text"
                                value={search}
                                onChange={e => setSearch(e.target.value)}
                                placeholder="Filter by hostname…"
                                className="w-full pl-10 pr-9 py-2.5 bg-white/[0.04] border border-white/[0.09] rounded-xl text-[13px] text-text-primary placeholder:text-text-muted outline-none focus:border-accent-cyan/40 transition-colors font-mono"
                            />
                            {search && (
                                <button type="button" onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary transition-colors">
                                    <X className="w-3.5 h-3.5" />
                                </button>
                            )}
                        </div>

                        {assets.length === 0 ? (
                            <EmptyState
                                icon={Globe}
                                title="No assets discovered yet"
                                message="Run a scan to start building your asset inventory."
                                action={{ label: 'Launch Scan', onClick: () => window.location.href = '/new' }}
                            />
                        ) : filteredAssets.length === 0 ? (
                            <EmptyState
                                icon={Search}
                                title="No matching assets"
                                message={`No assets match "${search}". Try a different hostname.`}
                                action={{ label: 'Clear search', onClick: () => setSearch('') }}
                            />
                        ) : (
                            <>
                                <motion.div variants={containerVariants} initial="hidden" animate="visible" className="space-y-4">
                                    {pagedAssets.map(asset => (
                                        <AssetCard key={asset.host} asset={asset} findings={asset.findings} />
                                    ))}
                                </motion.div>
                                <Pagination
                                    page={page}
                                    totalPages={totalPages}
                                    onChange={setPage}
                                    pageSize={PAGE_SIZE}
                                    totalItems={filteredAssets.length}
                                />
                            </>
                        )}
                    </div>

                    {/* Sidebar stats — 1/3 width */}
                    <div className="space-y-4">
                        {/* Severity Breakdown */}
                        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5 shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                            <h3 className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-4 flex items-center gap-2">
                                <AlertTriangle className="w-3.5 h-3.5 text-accent-red" />
                                Findings by Severity
                            </h3>
                            {allFindings.length === 0 ? (
                                <p className="text-text-muted text-sm text-center py-4">No findings yet</p>
                            ) : (
                                <SeverityBreakdown findings={allFindings} />
                            )}
                            <div className="mt-4 pt-4 border-t border-white/[0.06] flex items-center justify-between text-[11px] font-mono">
                                <span className="text-text-muted">Total findings</span>
                                <span className="text-text-primary font-bold">{allFindings.length}</span>
                            </div>
                        </div>

                        {/* Risk Summary */}
                        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5">
                            <h3 className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-4 flex items-center gap-2">
                                <Shield className="w-3.5 h-3.5 text-accent-cyan" />
                                Risk Summary
                            </h3>
                            <div className="space-y-3 text-sm">
                                {[
                                    { label: 'Assets Scanned', value: assets.length, icon: Target },
                                    { label: 'Critical Targets', value: assets.filter(a => riskScore(a.findings) < 20).length, icon: AlertTriangle, warn: true },
                                    { label: 'Clean Assets', value: assets.filter(a => a.findings.length === 0).length, icon: CheckCircle },
                                    { label: 'Scans Run', value: flows.length, icon: Activity },
                                ].map(({ label, value, icon: Icon, warn }) => (
                                    <div key={label} className="flex items-center justify-between">
                                        <div className="flex items-center gap-2 text-text-secondary">
                                            <Icon className={`w-3.5 h-3.5 ${warn ? 'text-accent-red' : 'text-text-muted'}`} />
                                            {label}
                                        </div>
                                        <span className={`font-mono font-bold ${warn && value > 0 ? 'text-accent-red' : 'text-text-primary'}`}>{value}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Network Recon Findings */}
                        <NetworkReconPanel findings={allFindings} />

                        {/* Cloud Security Findings */}
                        <CloudSecurityPanel findings={allFindings} />

                        {/* Quick Actions */}
                        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5">
                            <h3 className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-4 flex items-center gap-2">
                                <Zap className="w-3.5 h-3.5 text-accent-green" />
                                Quick Actions
                            </h3>
                            <div className="space-y-2">
                                <Link to="/new" className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-white/[0.04] border border-white/[0.08] hover:bg-white/[0.08] transition-colors text-sm text-text-secondary hover:text-text-primary">
                                    <Zap className="w-4 h-4 text-accent-cyan" />
                                    Launch New Scan
                                </Link>
                                <Link to="/reports" className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-white/[0.04] border border-white/[0.08] hover:bg-white/[0.08] transition-colors text-sm text-text-secondary hover:text-text-primary">
                                    <Layers className="w-4 h-4 text-accent-purple" />
                                    Generate Report
                                </Link>
                                <Link to="/" className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-white/[0.04] border border-white/[0.08] hover:bg-white/[0.08] transition-colors text-sm text-text-secondary hover:text-text-primary">
                                    <Activity className="w-4 h-4 text-accent-green" />
                                    View All Findings
                                </Link>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}
