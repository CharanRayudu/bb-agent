import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
    FileText, Download, CheckCircle, AlertTriangle, Clock,
    Zap, Activity, Shield, Globe, ArrowRight, ExternalLink,
    FileCode, Bug, Layers
} from 'lucide-react'

const API_BASE = '/api'

const CHIP = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

function severityChip(sev) {
    const styles = {
        critical: 'bg-[#ff4757]/12 text-[#ff4757] border-[#ff4757]/35',
        high:     'bg-[#ff7f50]/12 text-[#ff7f50] border-[#ff7f50]/35',
        medium:   'bg-[#eccc68]/12 text-[#eccc68] border-[#eccc68]/35',
        low:      'bg-[#2ed573]/12 text-[#2ed573] border-[#2ed573]/35',
        info:     'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30',
    }
    return `${CHIP} ${styles[sev] || styles.info}`
}

function ExportCard({ icon: Icon, title, description, badge, color, onExport, loading }) {
    return (
        <motion.div
            whileHover={{ y: -2 }}
            className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5 shadow-[0_8px_32px_rgba(0,0,0,0.4)] group cursor-pointer"
            onClick={onExport}
        >
            <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full blur-3xl opacity-40 transition-opacity group-hover:opacity-70" style={{ background: `radial-gradient(circle, ${color}60, transparent 70%)` }} />
            <div className="relative z-10 flex items-start gap-4">
                <div className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0 border" style={{ background: `${color}18`, borderColor: `${color}40`, boxShadow: `0 0 16px ${color}25` }}>
                    <Icon className="w-5 h-5" style={{ color }} />
                </div>
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                        <h3 className="text-sm font-bold text-text-primary">{title}</h3>
                        {badge && (
                            <span className="text-[9px] font-mono uppercase tracking-widest px-1.5 py-0.5 rounded-full border" style={{ color, background: `${color}15`, borderColor: `${color}40` }}>
                                {badge}
                            </span>
                        )}
                    </div>
                    <p className="text-xs text-text-muted leading-relaxed">{description}</p>
                </div>
                <div className="flex-shrink-0">
                    {loading ? (
                        <div className="w-7 h-7 rounded-full border border-white/20 flex items-center justify-center">
                            <div className="w-3 h-3 border-2 border-text-muted border-t-transparent rounded-full animate-spin" />
                        </div>
                    ) : (
                        <div className="w-7 h-7 rounded-full border border-white/20 bg-white/[0.04] flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity" style={{ borderColor: `${color}40`, background: `${color}10` }}>
                            <Download className="w-3.5 h-3.5" style={{ color }} />
                        </div>
                    )}
                </div>
            </div>
        </motion.div>
    )
}

function FlowReportRow({ flow, findings }) {
    const [downloading, setDownloading] = useState(null)
    const critical = findings.filter(f => f.severity === 'critical').length
    const high = findings.filter(f => f.severity === 'high').length

    async function download(format) {
        setDownloading(format)
        try {
            const url = `${API_BASE}/flows/${flow.id}/report/${format}`
            const resp = await fetch(url)
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
            const blob = await resp.blob()
            const a = document.createElement('a')
            a.href = URL.createObjectURL(blob)
            const ext = format === 'html' ? 'html' : format === 'burp' ? 'xml' : 'txt'
            a.download = `mirage-${flow.name.replace(/[^a-zA-Z0-9]/g, '_')}-${format}.${ext}`
            a.click()
            URL.revokeObjectURL(a.href)
        } catch (err) {
            console.error('Export failed:', err)
        } finally {
            setDownloading(null)
        }
    }

    return (
        <div className="flex items-center gap-4 px-5 py-4 hover:bg-white/[0.02] transition-colors border-b border-white/[0.05] last:border-0">
            <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-medium text-text-primary truncate">{flow.name}</span>
                    <span className={`${CHIP} ${
                        flow.status === 'completed' ? 'bg-accent-green/10 text-accent-green border-accent-green/30'
                        : flow.status === 'active' ? 'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30'
                        : 'bg-white/5 text-text-muted border-white/10'
                    }`}>{flow.status}</span>
                </div>
                <div className="flex items-center gap-3 text-[11px] font-mono text-text-muted">
                    <span className="flex items-center gap-1"><Globe className="w-3 h-3" />{flow.target}</span>
                    <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{new Date(flow.created_at).toLocaleDateString()}</span>
                    {critical > 0 && <span className="text-[#ff4757]">{critical} critical</span>}
                    {high > 0 && <span className="text-[#ff7f50]">{high} high</span>}
                    {!findings.length && <span className="text-accent-green">Clean</span>}
                </div>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
                {[
                    { fmt: 'html',  label: 'HTML',  color: '#67e8f9', icon: FileText },
                    { fmt: 'burp',  label: 'Burp',  color: '#c4b5fd', icon: Bug },
                    { fmt: 'nuclei',label: 'Nuclei', color: '#6ee7b7', icon: FileCode },
                ].map(({ fmt, label, color, icon: Ico }) => (
                    <button
                        key={fmt}
                        onClick={() => download(fmt)}
                        disabled={downloading === fmt}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all hover:opacity-80 disabled:opacity-50"
                        style={{ color, borderColor: `${color}35`, background: `${color}10` }}
                        title={`Export as ${label}`}
                    >
                        {downloading === fmt
                            ? <div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin" />
                            : <Ico className="w-3 h-3" />
                        }
                        {label}
                    </button>
                ))}
            </div>
        </div>
    )
}

export default function Reports() {
    const [flows, setFlows] = useState([])
    const [findings, setFindings] = useState([])
    const [loading, setLoading] = useState(true)
    const [downloading, setDownloading] = useState(null)

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

    const completedFlows = flows.filter(f => f.status === 'completed')
    const critical = findings.filter(f => f.severity === 'critical').length
    const high = findings.filter(f => f.severity === 'high').length

    async function downloadAllHTML() {
        setDownloading('all-html')
        try {
            if (completedFlows.length === 0) return
            for (const flow of completedFlows.slice(0, 3)) {
                const resp = await fetch(`${API_BASE}/flows/${flow.id}/report/html`)
                if (!resp.ok) continue
                const blob = await resp.blob()
                const a = document.createElement('a')
                a.href = URL.createObjectURL(blob)
                a.download = `mirage-${flow.name.replace(/[^a-zA-Z0-9]/g, '_')}.html`
                a.click()
                URL.revokeObjectURL(a.href)
            }
        } finally {
            setDownloading(null)
        }
    }

    const findingsPerFlow = {}
    findings.forEach(f => {
        if (!findingsPerFlow[f.flowId]) findingsPerFlow[f.flowId] = []
        findingsPerFlow[f.flowId].push(f)
    })

    return (
        <div className="relative pb-12">
            {/* Ambient */}
            <div className="pointer-events-none absolute inset-0 -z-10">
                <div className="absolute -top-40 -left-32 w-[40rem] h-[40rem] bg-accent-purple/15 rounded-full blur-3xl" />
                <div className="absolute top-24 -right-40 w-[36rem] h-[36rem] bg-accent-green/10 rounded-full blur-3xl" />
            </div>

            {/* Hero */}
            <div className="mb-8 relative z-10">
                <div className="lg-surface-hero px-7 py-8 md:px-10 md:py-10">
                    <div className="absolute -right-28 -top-28 h-72 w-72 bg-accent-green/20 blur-3xl opacity-60 pointer-events-none" />
                    <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
                            <div className="inline-flex items-center gap-2 lg-pill mb-4 text-[10px] uppercase tracking-[0.22em] font-semibold">
                                <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
                                Reporting
                            </div>
                            <h1 className="text-4xl md:text-5xl font-display font-semibold mb-3 tracking-[-0.02em] lg-gradient-text">
                                Reports & Exports
                            </h1>
                            <p className="text-sm md:text-base text-text-secondary flex items-center gap-2">
                                <FileText className="w-4 h-4 text-accent-green" />
                                {flows.length} scan{flows.length !== 1 ? 's' : ''} · {findings.length} findings · {critical} critical
                            </p>
                        </motion.div>

                        <motion.div
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ delay: 0.1 }}
                            className="flex-shrink-0"
                        >
                            <button
                                onClick={downloadAllHTML}
                                disabled={downloading === 'all-html' || completedFlows.length === 0}
                                className="lg-btn text-[15px] px-6 py-3.5 disabled:opacity-50"
                            >
                                {downloading === 'all-html'
                                    ? <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                                    : <Download className="w-4 h-4 relative z-10" />
                                }
                                <span className="relative z-10 font-semibold">Export All Reports</span>
                            </button>
                        </motion.div>
                    </div>
                </div>
            </div>

            {/* Summary Stats */}
            <div className="relative z-10 grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
                {[
                    { label: 'Total Scans', value: flows.length, color: '#67e8f9', icon: Activity },
                    { label: 'Completed', value: completedFlows.length, color: '#6ee7b7', icon: CheckCircle },
                    { label: 'Critical Findings', value: critical, color: '#ff4757', icon: AlertTriangle },
                    { label: 'High Findings', value: high, color: '#ff7f50', icon: Shield },
                ].map(({ label, value, color, icon: Icon }) => (
                    <motion.div
                        key={label}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-4 shadow-[0_8px_24px_rgba(0,0,0,0.4)]"
                    >
                        <div className="absolute -top-8 -right-8 w-24 h-24 rounded-full blur-3xl opacity-30" style={{ background: `radial-gradient(circle, ${color}, transparent 70%)` }} />
                        <div className="relative z-10 flex items-center gap-3">
                            <div className="w-9 h-9 rounded-xl flex items-center justify-center border" style={{ background: `${color}15`, borderColor: `${color}35` }}>
                                <Icon className="w-4 h-4" style={{ color }} />
                            </div>
                            <div>
                                <div className="text-2xl font-bold font-mono" style={{ color }}>{value}</div>
                                <div className="text-[10px] text-text-muted">{label}</div>
                            </div>
                        </div>
                    </motion.div>
                ))}
            </div>

            <div className="relative z-10 grid grid-cols-1 xl:grid-cols-3 gap-6">
                {/* Per-flow exports — left 2/3 */}
                <div className="xl:col-span-2">
                    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                        <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
                            <h2 className="text-[11px] font-mono uppercase tracking-widest text-text-muted flex items-center gap-2">
                                <Layers className="w-3.5 h-3.5 text-accent-cyan" />
                                Scan Reports
                            </h2>
                            <span className="text-[11px] font-mono text-text-muted">{flows.length} scans</span>
                        </div>

                        {loading ? (
                            <div className="p-5 space-y-3">
                                {[1,2,3].map(i => <div key={i} className="h-16 rounded-xl bg-white/[0.04] animate-pulse" />)}
                            </div>
                        ) : flows.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-16 text-center px-8">
                                <FileText className="w-10 h-10 text-text-muted mb-3" />
                                <p className="text-text-muted text-sm">No scans completed yet.</p>
                            </div>
                        ) : (
                            <div>
                                {flows.map(flow => (
                                    <FlowReportRow
                                        key={flow.id}
                                        flow={flow}
                                        findings={findingsPerFlow[flow.id] || []}
                                    />
                                ))}
                            </div>
                        )}
                    </div>
                </div>

                {/* Export formats info — right 1/3 */}
                <div className="space-y-4">
                    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5">
                        <h3 className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-4 flex items-center gap-2">
                            <Download className="w-3.5 h-3.5 text-accent-green" />
                            Export Formats
                        </h3>
                        <div className="space-y-3">
                            {[
                                { fmt: 'HTML Report', color: '#67e8f9', icon: FileText, desc: 'Full pentest report with executive summary, CVSS scores, and evidence' },
                                { fmt: 'Burp Suite XML', color: '#c4b5fd', icon: Bug, desc: 'Import findings directly into Burp Suite for manual verification' },
                                { fmt: 'Nuclei YAML', color: '#6ee7b7', icon: FileCode, desc: 'Re-run confirmed findings with Nuclei templates for CI/CD integration' },
                            ].map(({ fmt, color, icon: Icon, desc }) => (
                                <div key={fmt} className="flex gap-3 p-3 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                                    <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 border" style={{ background: `${color}15`, borderColor: `${color}35` }}>
                                        <Icon className="w-4 h-4" style={{ color }} />
                                    </div>
                                    <div>
                                        <div className="text-xs font-semibold text-text-primary mb-0.5">{fmt}</div>
                                        <div className="text-[10px] text-text-muted leading-relaxed">{desc}</div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5">
                        <h3 className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-3 flex items-center gap-2">
                            <Shield className="w-3.5 h-3.5 text-accent-purple" />
                            APTS Compliance
                        </h3>
                        <div className="space-y-2 text-xs text-text-muted">
                            <div className="flex items-center gap-2">
                                <CheckCircle className="w-3.5 h-3.5 text-accent-green flex-shrink-0" />
                                <span>OWASP APTS Tier 1 compliant</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <CheckCircle className="w-3.5 h-3.5 text-accent-green flex-shrink-0" />
                                <span>SHA-256 evidence integrity hashing</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <CheckCircle className="w-3.5 h-3.5 text-accent-green flex-shrink-0" />
                                <span>RP-003 confidence scoring (0-100)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <CheckCircle className="w-3.5 h-3.5 text-accent-green flex-shrink-0" />
                                <span>Confirmed/Unconfirmed classification</span>
                            </div>
                        </div>
                        <a
                            href="/api/apts/status"
                            target="_blank"
                            rel="noreferrer"
                            className="mt-4 flex items-center gap-2 text-xs text-accent-purple hover:text-accent-purple/80 transition-colors"
                        >
                            View APTS compliance status <ExternalLink className="w-3 h-3" />
                        </a>
                    </div>
                </div>
            </div>
        </div>
    )
}
