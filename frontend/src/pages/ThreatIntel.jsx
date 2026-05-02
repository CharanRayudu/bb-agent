import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Target, Shield, Link2, AlertTriangle, CheckCircle,
    XCircle, ChevronRight, RefreshCw, Loader, ExternalLink,
    Info, Zap, TrendingUp, Activity, ArrowRight, Lock,
    Globe, Code2, Package, Key, Database, Network, Cloud
} from 'lucide-react'

const API_BASE = '/api'

// ── Tactic colours (MITRE colour scheme approximation) ──────────────────────
const TACTIC_COLORS = {
    'Initial Access':       '#ff4757',
    'Execution':            '#ff6b81',
    'Persistence':          '#ff7f50',
    'Privilege Escalation': '#ffa502',
    'Defense Evasion':      '#eccc68',
    'Credential Access':    '#7bed9f',
    'Discovery':            '#70a1ff',
    'Lateral Movement':     '#5352ed',
    'Collection':           '#a29bfe',
    'Command and Control':  '#fd79a8',
    'Exfiltration':         '#e84393',
    'Impact':               '#d63031',
    'Resource Development': '#b2bec3',
}

const CHIP = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

const RISK_STYLES = {
    critical: { chip: 'bg-[#ff4757]/12 text-[#ff4757] border-[#ff4757]/35', glow: '#ff4757' },
    high:     { chip: 'bg-[#ff7f50]/12 text-[#ff7f50] border-[#ff7f50]/35', glow: '#ff7f50' },
    medium:   { chip: 'bg-[#eccc68]/12 text-[#eccc68] border-[#eccc68]/35', glow: '#eccc68' },
    low:      { chip: 'bg-[#2ed573]/12 text-[#2ed573] border-[#2ed573]/35', glow: '#2ed573' },
}

function RiskChip({ label }) {
    const s = RISK_STYLES[label] || RISK_STYLES.low
    return <span className={`${CHIP} ${s.chip}`}>{label}</span>
}

function RiskBar({ score }) {
    const color = score >= 75 ? '#ff4757' : score >= 50 ? '#ff7f50' : score >= 25 ? '#eccc68' : '#2ed573'
    return (
        <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 rounded-full bg-white/[0.06]">
                <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${score}%`, background: color, boxShadow: `0 0 6px ${color}80` }}
                />
            </div>
            <span className="text-[10px] font-mono text-text-muted w-8 text-right">{score}</span>
        </div>
    )
}

// ── ATT&CK Tactic Matrix ─────────────────────────────────────────────────────
function ATTCKMatrix({ tacticMatrix }) {
    const tactics = Object.keys(tacticMatrix)
    if (tactics.length === 0) {
        return (
            <div className="text-center py-8 text-text-muted text-sm">
                No ATT&CK mappings found for current findings
            </div>
        )
    }

    return (
        <div className="space-y-3">
            {tactics.map(tactic => {
                const color = TACTIC_COLORS[tactic] || '#888'
                const techs = tacticMatrix[tactic] || []
                return (
                    <div key={tactic} className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-3">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
                            <span className="text-xs font-semibold text-text-primary">{tactic}</span>
                            <span className="ml-auto text-[10px] text-text-muted font-mono">{techs.length} technique{techs.length !== 1 ? 's' : ''}</span>
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                            {techs.map(tech => (
                                <a
                                    key={tech.id}
                                    href={tech.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="group flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-mono border transition-all hover:border-white/20"
                                    style={{ background: `${color}12`, borderColor: `${color}30`, color }}
                                    title={tech.name}
                                >
                                    <span>{tech.id}</span>
                                    <ExternalLink className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                                </a>
                            ))}
                        </div>
                    </div>
                )
            })}
        </div>
    )
}

// ── Attack Chain Visualizer ──────────────────────────────────────────────────
function ChainCard({ chain, idx }) {
    const scoreColor = chain.score >= 75 ? '#ff4757' : chain.score >= 50 ? '#ff7f50' : chain.score >= 25 ? '#eccc68' : '#2ed573'

    return (
        <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.04 }}
            className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-4"
        >
            <div className="flex items-start justify-between gap-3 mb-3">
                <div className="flex-1 min-w-0">
                    <p className="text-xs text-text-secondary leading-relaxed">{chain.impact}</p>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                    <div className="text-right">
                        <div className="text-sm font-bold" style={{ color: scoreColor }}>{chain.score.toFixed(0)}</div>
                        <div className="text-[9px] text-text-muted uppercase tracking-widest">score</div>
                    </div>
                    <div className="w-1 h-8 rounded-full" style={{ background: scoreColor, boxShadow: `0 0 8px ${scoreColor}80` }} />
                </div>
            </div>

            {/* Step flow */}
            <div className="flex items-center gap-1.5 flex-wrap">
                {chain.steps.map((step, i) => (
                    <React.Fragment key={i}>
                        <span className="px-2 py-0.5 rounded-md bg-white/[0.05] border border-white/[0.08] text-[10px] font-mono text-text-primary">
                            {step.finding_type}
                        </span>
                        {i < chain.steps.length - 1 && (
                            <ArrowRight className="w-3 h-3 text-text-muted flex-shrink-0" />
                        )}
                    </React.Fragment>
                ))}
            </div>

            {chain.steps.length > 1 && (
                <div className="mt-2 flex items-center gap-1.5 text-[10px] text-text-muted">
                    <span className="font-mono">{chain.length} steps</span>
                    <span className="text-white/20">·</span>
                    <span>
                        {chain.steps[chain.steps.length - 1]?.relation === 'enables'
                            ? 'direct exploitation path'
                            : chain.steps[chain.steps.length - 1]?.relation}
                    </span>
                </div>
            )}
        </motion.div>
    )
}

// ── Risk-Ranked Finding Row ──────────────────────────────────────────────────
function RankedFindingRow({ finding, idx }) {
    const [expanded, setExpanded] = useState(false)
    const riskStyle = RISK_STYLES[finding.risk_label] || RISK_STYLES.low

    return (
        <motion.div
            initial={{ opacity: 0, x: -4 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.025 }}
            className="rounded-xl border border-white/[0.06] overflow-hidden"
        >
            <button
                type="button"
                onClick={() => setExpanded(e => !e)}
                className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/[0.02] transition-colors"
            >
                <div className="w-6 h-6 rounded-md flex items-center justify-center flex-shrink-0 text-[10px] font-bold text-text-muted bg-white/[0.04]">
                    {idx + 1}
                </div>
                <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-text-primary truncate">{finding.title || finding.finding_type}</div>
                    <div className="text-[11px] text-text-muted font-mono truncate">{finding.finding_type}</div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                    {finding.in_kev && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-[#ff4757] bg-[#ff4757]/10 border border-[#ff4757]/25">KEV</span>
                    )}
                    {finding.epss_score > 0 && (
                        <span className="text-[10px] font-mono text-[#7bed9f]">{(finding.epss_score * 100).toFixed(1)}%</span>
                    )}
                    <RiskChip label={finding.risk_label} />
                    <div className="w-16">
                        <RiskBar score={finding.risk_score} />
                    </div>
                </div>
            </button>

            {expanded && (
                <div className="px-4 pb-4 space-y-3 border-t border-white/[0.06] bg-black/10">
                    <div className="pt-3 grid grid-cols-2 sm:grid-cols-4 gap-2">
                        <div className="p-2 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                            <div className="text-[9px] text-text-muted uppercase tracking-widest">Severity</div>
                            <div className="text-xs text-text-primary mt-0.5 capitalize">{finding.severity}</div>
                        </div>
                        <div className="p-2 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                            <div className="text-[9px] text-text-muted uppercase tracking-widest">Risk Score</div>
                            <div className="text-xs font-bold mt-0.5" style={{ color: RISK_STYLES[finding.risk_label]?.glow }}>{finding.risk_score}</div>
                        </div>
                        {finding.cvss > 0 && (
                            <div className="p-2 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                                <div className="text-[9px] text-text-muted uppercase tracking-widest">CVSS v3</div>
                                <div className="text-xs text-text-primary mt-0.5">{finding.cvss.toFixed(1)}</div>
                            </div>
                        )}
                        {finding.epss_score > 0 && (
                            <div className="p-2 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                                <div className="text-[9px] text-text-muted uppercase tracking-widest">EPSS</div>
                                <div className="text-xs text-[#7bed9f] mt-0.5">{(finding.epss_score * 100).toFixed(2)}% · p{(finding.epss_percentile * 100).toFixed(0)}</div>
                            </div>
                        )}
                    </div>

                    {finding.cve_ids?.length > 0 && (
                        <div className="flex items-center gap-1.5 flex-wrap">
                            {finding.cve_ids.map(cve => (
                                <a
                                    key={cve}
                                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-blue-500/10 border border-blue-500/25 text-[10px] font-mono text-blue-300 hover:text-blue-200 transition-colors"
                                >
                                    {cve} <ExternalLink className="w-2.5 h-2.5" />
                                </a>
                            ))}
                        </div>
                    )}

                    {finding.chain_impact && (
                        <div className="flex items-start gap-2 p-2 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                            <Link2 className="w-3.5 h-3.5 text-accent-cyan flex-shrink-0 mt-0.5" />
                            <div>
                                <span className="text-[9px] text-text-muted uppercase tracking-widest">Chain Impact</span>
                                <p className="text-xs text-text-secondary mt-0.5">{finding.chain_impact}</p>
                            </div>
                        </div>
                    )}

                    {finding.target && (
                        <div className="text-[10px] text-text-muted font-mono truncate">{finding.target}</div>
                    )}
                </div>
            )}
        </motion.div>
    )
}

// ── CVE Enrichment Panel ────────────────────────────────────────────────────
function EnrichPanel() {
    const [input, setInput] = useState('')
    const [loading, setLoading] = useState(false)
    const [results, setResults] = useState(null)
    const [error, setError] = useState(null)

    async function enrich() {
        const cves = input.split(/[\s,]+/).filter(s => s.match(/CVE-\d{4}-\d+/i))
        if (cves.length === 0) return
        setLoading(true)
        setError(null)
        try {
            const res = await fetch(`${API_BASE}/threatintel/enrich`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cves }),
            })
            const data = await res.json()
            if (!res.ok) setError(data.error || `HTTP ${res.status}`)
            else setResults(data.results || [])
        } catch (e) {
            setError(e.message)
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5 space-y-4">
            <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                <Zap className="w-4 h-4 text-accent-cyan" />
                CVE Enrichment — EPSS + CISA KEV
            </h3>
            <p className="text-xs text-text-muted">Enter CVE IDs to look up exploit probability and known-exploited status.</p>

            <div className="flex gap-2">
                <input
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && enrich()}
                    placeholder="CVE-2021-44228, CVE-2023-45857, …"
                    className="flex-1 px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-sm text-text-primary font-mono placeholder:text-text-muted outline-none focus:border-accent-cyan/40 transition-colors"
                />
                <button
                    type="button"
                    onClick={enrich}
                    disabled={loading}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan text-sm font-medium hover:bg-accent-cyan/20 transition-all disabled:opacity-40"
                >
                    {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                    Enrich
                </button>
            </div>

            {error && <p className="text-xs text-[#ff4757]">{error}</p>}

            {results && results.length > 0 && (
                <div className="space-y-2">
                    {results.map(r => (
                        <div key={r.cve} className="flex items-center gap-3 p-3 rounded-xl bg-black/20 border border-white/[0.06]">
                            <a
                                href={`https://nvd.nist.gov/vuln/detail/${r.cve}`}
                                target="_blank" rel="noopener noreferrer"
                                className="text-xs font-mono text-blue-300 hover:text-blue-200 transition-colors min-w-[160px]"
                            >
                                {r.cve} <ExternalLink className="w-2.5 h-2.5 inline" />
                            </a>
                            <div className="flex-1">
                                {r.epss ? (
                                    <div className="flex items-center gap-3">
                                        <div>
                                            <span className="text-[9px] text-text-muted uppercase">EPSS</span>
                                            <span className="ml-1.5 text-xs font-mono text-[#7bed9f]">{(r.epss.epss * 100).toFixed(2)}%</span>
                                        </div>
                                        <div>
                                            <span className="text-[9px] text-text-muted uppercase">Percentile</span>
                                            <span className="ml-1.5 text-xs font-mono text-text-secondary">p{(r.epss.percentile * 100).toFixed(0)}</span>
                                        </div>
                                    </div>
                                ) : (
                                    <span className="text-[10px] text-text-muted italic">No EPSS data</span>
                                )}
                            </div>
                            {r.in_kev && (
                                <span className="px-2 py-0.5 rounded-md text-[9px] font-bold font-mono uppercase text-[#ff4757] bg-[#ff4757]/12 border border-[#ff4757]/30">
                                    CISA KEV
                                </span>
                            )}
                            <RiskChip label={r.risk_label} />
                        </div>
                    ))}
                </div>
            )}
        </div>
    )
}

// ── Main Page ────────────────────────────────────────────────────────────────
const TABS = [
    { id: 'risk',    label: 'Risk Prioritization', icon: TrendingUp },
    { id: 'attck',   label: 'ATT&CK Coverage',      icon: Target },
    { id: 'chains',  label: 'Attack Chains',         icon: Link2 },
    { id: 'enrich',  label: 'CVE Enrichment',        icon: Zap },
]

export default function ThreatIntel() {
    const [tab, setTab] = useState('risk')
    const [flowID, setFlowID] = useState('')
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState(null)
    const [attck, setATTCK] = useState(null)
    const [chains, setChains] = useState(null)
    const [risk, setRisk] = useState(null)

    const fetchAll = useCallback(async () => {
        setLoading(true)
        setError(null)
        const qs = flowID ? `?flow_id=${flowID}` : ''
        try {
            const [attckRes, chainsRes, riskRes] = await Promise.all([
                fetch(`${API_BASE}/threatintel/attck${qs}`),
                fetch(`${API_BASE}/threatintel/chains${qs}`),
                fetch(`${API_BASE}/threatintel/risk${qs}`),
            ])
            const [a, c, r] = await Promise.all([attckRes.json(), chainsRes.json(), riskRes.json()])
            setATTCK(a)
            setChains(c)
            setRisk(r)
        } catch (e) {
            setError(e.message)
        } finally {
            setLoading(false)
        }
    }, [flowID])

    useEffect(() => { fetchAll() }, [fetchAll])

    const [riskFilter, setRiskFilter] = useState('all')
    const filteredRanked = risk?.ranked_findings
        ? (riskFilter === 'all' ? risk.ranked_findings : risk.ranked_findings.filter(f => f.risk_label === riskFilter))
        : []

    return (
        <div className="p-6 space-y-6 max-w-5xl">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <div className="flex items-center gap-3 mb-1">
                        <span className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#ff4757]/20 to-accent-purple/15 border border-white/20 flex items-center justify-center">
                            <Target className="w-5 h-5 text-[#ff4757]" />
                        </span>
                        <div>
                            <h1 className="text-xl font-bold text-text-primary">Threat Intelligence</h1>
                            <p className="text-xs text-text-muted">MITRE ATT&CK · Kill Chains · EPSS · CISA KEV · Risk Scoring</p>
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <input
                        value={flowID}
                        onChange={e => setFlowID(e.target.value)}
                        placeholder="Filter by Flow ID (optional)"
                        className="w-56 px-3 py-2 rounded-lg bg-black/20 border border-white/10 text-xs text-text-primary font-mono placeholder:text-text-muted outline-none focus:border-accent-cyan/40 transition-colors"
                    />
                    <button
                        type="button"
                        onClick={fetchAll}
                        disabled={loading}
                        className="p-2 rounded-lg bg-white/[0.04] border border-white/10 text-text-muted hover:text-text-primary hover:border-white/20 transition-all disabled:opacity-40"
                    >
                        {loading ? <Loader className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                    </button>
                </div>
            </div>

            {/* Summary Cards */}
            {risk && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {[
                        { label: 'Avg Risk Score', value: risk.avg_risk_score?.toFixed(0) || '—', color: '#ff7f50', icon: Activity },
                        { label: 'Top Risk Score', value: risk.top_risk_score?.toFixed(0) || '—', color: '#ff4757', icon: TrendingUp },
                        { label: 'CISA KEV', value: risk.kev_count || 0, color: '#ff4757', icon: AlertTriangle },
                        { label: 'Attack Chains', value: chains?.chains?.length || 0, color: '#a29bfe', icon: Link2 },
                    ].map(item => {
                        const Icon = item.icon
                        return (
                            <div key={item.label} className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.08] flex items-center gap-3">
                                <span className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: `${item.color}18` }}>
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
            )}

            {error && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-[#ff4757]/10 border border-[#ff4757]/30 text-[#ff4757] text-xs">
                    <XCircle className="w-4 h-4 flex-shrink-0" />
                    <span>{error}</span>
                </div>
            )}

            {/* Tabs */}
            <div className="flex gap-1 border-b border-white/[0.08] overflow-x-auto">
                {TABS.map(t => {
                    const Icon = t.icon
                    const active = tab === t.id
                    return (
                        <button
                            key={t.id}
                            type="button"
                            onClick={() => setTab(t.id)}
                            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-all whitespace-nowrap border-b-2 -mb-px ${
                                active
                                    ? 'text-accent-cyan border-accent-cyan'
                                    : 'text-text-muted border-transparent hover:text-text-secondary hover:border-white/20'
                            }`}
                        >
                            <Icon className="w-3.5 h-3.5" />
                            {t.label}
                        </button>
                    )
                })}
            </div>

            {/* Tab Content */}
            <AnimatePresence mode="wait">
                <motion.div
                    key={tab}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -4 }}
                    transition={{ duration: 0.15 }}
                >
                    {/* ── Risk Prioritization ─────────────────────────────── */}
                    {tab === 'risk' && (
                        <div className="space-y-4">
                            <div className="flex items-center justify-between gap-3">
                                <p className="text-xs text-text-muted">
                                    Composite risk = CVSS(30%) + EPSS(25%) + KEV(15%) + Chain depth(20%) + Severity(10%)
                                </p>
                                <div className="flex gap-1.5 flex-wrap justify-end">
                                    {['all', 'critical', 'high', 'medium', 'low'].map(f => {
                                        const n = f === 'all' ? (risk?.total_findings || 0) : (risk?.[`${f}_count`] || 0)
                                        const active = riskFilter === f
                                        return (
                                            <button
                                                key={f}
                                                type="button"
                                                onClick={() => setRiskFilter(f)}
                                                className={`px-2.5 py-1 rounded-lg text-[10px] font-medium transition-all ${
                                                    active ? 'bg-white/10 text-text-primary border border-white/20' : 'text-text-muted hover:text-text-secondary border border-transparent'
                                                }`}
                                            >
                                                {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)} ({n})
                                            </button>
                                        )
                                    })}
                                </div>
                            </div>

                            {loading ? (
                                <div className="flex items-center justify-center py-12">
                                    <Loader className="w-6 h-6 text-text-muted animate-spin" />
                                </div>
                            ) : filteredRanked.length > 0 ? (
                                <div className="space-y-2">
                                    {filteredRanked.map((f, i) => (
                                        <RankedFindingRow key={i} finding={f} idx={i} />
                                    ))}
                                </div>
                            ) : (
                                <div className="text-center py-12 text-text-muted">
                                    <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
                                    <p className="text-sm">No findings to rank yet</p>
                                    <p className="text-xs mt-1">Run a scan to populate the risk matrix</p>
                                </div>
                            )}
                        </div>
                    )}

                    {/* ── ATT&CK Coverage ─────────────────────────────────── */}
                    {tab === 'attck' && (
                        <div className="space-y-4">
                            {attck && (
                                <>
                                    <div className="flex gap-4 text-sm">
                                        <div>
                                            <span className="text-text-muted">Techniques detected: </span>
                                            <span className="font-semibold text-text-primary">{attck.technique_count}</span>
                                        </div>
                                        <div>
                                            <span className="text-text-muted">Tactics covered: </span>
                                            <span className="font-semibold text-text-primary">{attck.tactic_count}</span>
                                        </div>
                                        <div>
                                            <span className="text-text-muted">Findings mapped: </span>
                                            <span className="font-semibold text-text-primary">{attck.finding_count}</span>
                                        </div>
                                    </div>
                                    {loading ? (
                                        <div className="flex items-center justify-center py-12">
                                            <Loader className="w-6 h-6 text-text-muted animate-spin" />
                                        </div>
                                    ) : (
                                        <ATTCKMatrix tacticMatrix={attck.tactic_matrix || {}} />
                                    )}
                                </>
                            )}
                        </div>
                    )}

                    {/* ── Attack Chains ────────────────────────────────────── */}
                    {tab === 'chains' && (
                        <div className="space-y-4">
                            {chains && (
                                <>
                                    <div className="flex items-center gap-3 text-sm">
                                        <span className="text-text-muted">Kill paths found:</span>
                                        <span className="font-semibold text-text-primary">{chains.chains?.length || 0}</span>
                                        {chains.top_chain && (
                                            <>
                                                <span className="text-text-muted">· Top chain score:</span>
                                                <span className="font-semibold text-[#ff4757]">{chains.top_chain.score.toFixed(0)}</span>
                                            </>
                                        )}
                                    </div>
                                    {loading ? (
                                        <div className="flex items-center justify-center py-12">
                                            <Loader className="w-6 h-6 text-text-muted animate-spin" />
                                        </div>
                                    ) : chains.chains?.length > 0 ? (
                                        <div className="space-y-3">
                                            {chains.chains.slice(0, 20).map((chain, i) => (
                                                <ChainCard key={i} chain={chain} idx={i} />
                                            ))}
                                            {chains.chains.length > 20 && (
                                                <p className="text-xs text-text-muted text-center py-2">
                                                    + {chains.chains.length - 20} more chains not shown
                                                </p>
                                            )}
                                        </div>
                                    ) : (
                                        <div className="text-center py-12 text-text-muted">
                                            <Link2 className="w-8 h-8 mx-auto mb-2 opacity-30" />
                                            <p className="text-sm">No attack chains found</p>
                                            <p className="text-xs mt-1">Chains require multiple related findings across different categories</p>
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    )}

                    {/* ── CVE Enrichment ──────────────────────────────────── */}
                    {tab === 'enrich' && <EnrichPanel />}
                </motion.div>
            </AnimatePresence>
        </div>
    )
}
