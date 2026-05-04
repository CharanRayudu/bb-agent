import React, { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    FileText, Download, CheckCircle, AlertTriangle, Clock,
    Zap, Activity, Shield, Globe, ExternalLink,
    FileCode, Bug, Layers, Sparkles, Copy, RefreshCw,
    ChevronDown, BarChart2, BookOpen, Briefcase
} from 'lucide-react'

const API_BASE = '/api'

const CHIP = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

const TEMPLATES = [
    {
        id: 'executive',
        label: 'Executive',
        icon: Briefcase,
        color: '#c4b5fd',
        desc: 'Business risk, financial impact, strategic recommendations — no jargon',
    },
    {
        id: 'technical',
        label: 'Technical',
        icon: FileCode,
        color: '#67e8f9',
        desc: 'Detailed findings, attack vectors, ATT&CK coverage, code-level fixes',
    },
    {
        id: 'compliance',
        label: 'Compliance',
        icon: BookOpen,
        color: '#6ee7b7',
        desc: 'OWASP Top 10, PCI-DSS, SOC2 mapping with audit-ready tables',
    },
    {
        id: 'full',
        label: 'Full Report',
        icon: BarChart2,
        color: '#fbbf24',
        desc: 'Comprehensive — executive + technical + compliance in one document',
    },
]

// ── Minimal streaming markdown renderer ──────────────────────────────────────

function renderInline(text) {
    const parts = []
    let i = 0
    let key = 0
    while (i < text.length) {
        if (text[i] === '*' && text[i + 1] === '*') {
            const end = text.indexOf('**', i + 2)
            if (end !== -1) {
                parts.push(<strong key={key++} className="text-text-primary font-semibold">{text.slice(i + 2, end)}</strong>)
                i = end + 2
                continue
            }
        }
        if (text[i] === '`') {
            const end = text.indexOf('`', i + 1)
            if (end !== -1) {
                parts.push(<code key={key++} className="px-1.5 py-0.5 rounded bg-white/[0.08] text-accent-cyan text-[0.85em] font-mono">{text.slice(i + 1, end)}</code>)
                i = end + 1
                continue
            }
        }
        // collect plain chars
        let j = i + 1
        while (j < text.length && text[j] !== '*' && text[j] !== '`') j++
        parts.push(<React.Fragment key={key++}>{text.slice(i, j)}</React.Fragment>)
        i = j
    }
    return parts
}

function MarkdownView({ content }) {
    const lines = content.split('\n')
    const nodes = []
    let tableRows = []
    let listItems = []
    let key = 0

    function flushList() {
        if (!listItems.length) return
        nodes.push(
            <ul key={key++} className="my-3 space-y-1 pl-4">
                {listItems.map((li, i) => (
                    <li key={i} className="text-text-secondary text-sm flex items-start gap-2">
                        <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-accent-cyan/60 flex-shrink-0" />
                        <span>{renderInline(li)}</span>
                    </li>
                ))}
            </ul>
        )
        listItems = []
    }

    function flushTable() {
        if (!tableRows.length) return
        nodes.push(
            <div key={key++} className="my-4 overflow-x-auto">
                <table className="w-full text-xs border-collapse">
                    <tbody>
                        {tableRows.map((row, ri) => {
                            const cells = row.split('|').filter((_, i, a) => i > 0 && i < a.length - 1)
                            const isHeader = ri === 0
                            return (
                                <tr key={ri} className={isHeader ? 'border-b border-white/20' : 'border-b border-white/[0.06] hover:bg-white/[0.02]'}>
                                    {cells.map((cell, ci) => (
                                        isHeader
                                            ? <th key={ci} className="px-3 py-2 text-left text-text-muted font-mono uppercase tracking-wider">{cell.trim()}</th>
                                            : <td key={ci} className="px-3 py-2 text-text-secondary">{renderInline(cell.trim())}</td>
                                    ))}
                                </tr>
                            )
                        })}
                    </tbody>
                </table>
            </div>
        )
        tableRows = []
    }

    for (const line of lines) {
        if (line.startsWith('| ') || line.match(/^\|[-: ]+\|/)) {
            if (!line.match(/^\|[-: ]+\|/)) {
                flushList()
                tableRows.push(line)
            }
            continue
        }
        if (tableRows.length) { flushTable() }

        if (line.startsWith('- ') || line.startsWith('* ')) {
            flushList()
            listItems.push(line.slice(2))
            continue
        }
        if (listItems.length) { flushList() }

        if (line.startsWith('## ')) {
            nodes.push(<h2 key={key++} className="text-lg font-bold text-text-primary mt-7 mb-3 pb-2 border-b border-white/10">{renderInline(line.slice(3))}</h2>)
        } else if (line.startsWith('### ')) {
            nodes.push(<h3 key={key++} className="text-base font-semibold text-text-primary mt-5 mb-2">{renderInline(line.slice(4))}</h3>)
        } else if (line.startsWith('# ')) {
            nodes.push(<h1 key={key++} className="text-xl font-bold text-text-primary mt-6 mb-4">{renderInline(line.slice(2))}</h1>)
        } else if (line === '---' || line === '***') {
            nodes.push(<hr key={key++} className="my-5 border-white/10" />)
        } else if (line.trim() === '') {
            nodes.push(<div key={key++} className="mb-3" />)
        } else {
            nodes.push(<p key={key++} className="text-sm text-text-secondary leading-relaxed mb-1">{renderInline(line)}</p>)
        }
    }
    flushList()
    flushTable()
    return <div className="prose-mirage">{nodes}</div>
}

// ── AI Generate tab ───────────────────────────────────────────────────────────

function GenerateTab({ flows }) {
    const [template, setTemplate] = useState('technical')
    const [flowID, setFlowID] = useState('')
    const [includeThreatIntel, setIncludeThreatIntel] = useState(true)
    const [includeMonitoring, setIncludeMonitoring] = useState(true)
    const [generating, setGenerating] = useState(false)
    const [content, setContent] = useState('')
    const [charCount, setCharCount] = useState(0)
    const [error, setError] = useState(null)
    const [aiAvailable, setAiAvailable] = useState(null)
    const readerRef = useRef(null)
    const previewRef = useRef(null)

    useEffect(() => {
        fetch(`${API_BASE}/reports/available`)
            .then(r => r.json())
            .then(d => setAiAvailable(d.available))
            .catch(() => setAiAvailable(false))
    }, [])

    // Auto-scroll preview to bottom while streaming
    useEffect(() => {
        if (generating && previewRef.current) {
            previewRef.current.scrollTop = previewRef.current.scrollHeight
        }
    }, [content, generating])

    const generate = useCallback(async () => {
        setGenerating(true)
        setContent('')
        setCharCount(0)
        setError(null)

        try {
            const resp = await fetch(`${API_BASE}/reports/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    template,
                    flow_id: flowID || undefined,
                    include_threat_intel: includeThreatIntel,
                    include_monitoring: includeMonitoring,
                }),
            })

            if (!resp.ok) {
                throw new Error(`HTTP ${resp.status}`)
            }

            const reader = resp.body.getReader()
            readerRef.current = reader
            const decoder = new TextDecoder()
            let buf = ''

            while (true) {
                const { done, value } = await reader.read()
                if (done) break
                buf += decoder.decode(value, { stream: true })

                const lines = buf.split('\n')
                buf = lines.pop()

                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue
                    try {
                        const ev = JSON.parse(line.slice(6))
                        if (ev.type === 'delta') {
                            setContent(prev => prev + ev.text)
                            setCharCount(prev => prev + ev.text.length)
                        } else if (ev.type === 'done') {
                            setGenerating(false)
                        } else if (ev.type === 'error') {
                            setError(ev.error)
                            setGenerating(false)
                        }
                    } catch {
                        // malformed SSE line
                    }
                }
            }
        } catch (err) {
            if (err.name !== 'AbortError') {
                setError(err.message)
            }
            setGenerating(false)
        }
    }, [template, flowID, includeThreatIntel, includeMonitoring])

    function stop() {
        readerRef.current?.cancel()
        setGenerating(false)
    }

    function copyToClipboard() {
        navigator.clipboard.writeText(content).catch(() => {})
    }

    function downloadMarkdown() {
        const blob = new Blob([content], { type: 'text/markdown' })
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `mirage-report-${template}-${new Date().toISOString().slice(0, 10)}.md`
        a.click()
        URL.revokeObjectURL(a.href)
    }

    const _selectedTmpl = TEMPLATES.find(t => t.id === template)

    return (
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
            {/* Config panel */}
            <div className="xl:col-span-2 space-y-5">
                {/* AI availability banner */}
                {aiAvailable === false && (
                    <div className="rounded-xl border border-[#fbbf24]/30 bg-[#fbbf24]/10 px-4 py-3 text-xs text-[#fbbf24]">
                        <strong>ANTHROPIC_API_KEY not configured.</strong> Set the environment variable to enable AI report generation.
                    </div>
                )}

                {/* Template selector */}
                <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5">
                    <h3 className="text-[11px] font-mono uppercase tracking-widest text-text-muted mb-4 flex items-center gap-2">
                        <Sparkles className="w-3.5 h-3.5 text-accent-cyan" />
                        Report Template
                    </h3>
                    <div className="space-y-2">
                        {TEMPLATES.map(tmpl => {
                            const Icon = tmpl.icon
                            const active = template === tmpl.id
                            return (
                                <button
                                    key={tmpl.id}
                                    type="button"
                                    onClick={() => setTemplate(tmpl.id)}
                                    className={`w-full flex items-start gap-3 p-3 rounded-xl border text-left transition-all ${
                                        active
                                            ? 'border-white/20 bg-white/[0.07] shadow-[inset_0_1px_0_rgba(255,255,255,0.1)]'
                                            : 'border-white/[0.06] bg-white/[0.02] hover:bg-white/[0.04]'
                                    }`}
                                >
                                    <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 border transition-all"
                                        style={{ background: active ? `${tmpl.color}18` : 'rgba(255,255,255,0.04)', borderColor: active ? `${tmpl.color}40` : 'rgba(255,255,255,0.08)' }}>
                                        <Icon className="w-4 h-4 transition-colors" style={{ color: active ? tmpl.color : '#6b7280' }} />
                                    </div>
                                    <div>
                                        <div className={`text-sm font-semibold transition-colors ${active ? 'text-text-primary' : 'text-text-secondary'}`}>{tmpl.label}</div>
                                        <div className="text-[10px] text-text-muted leading-relaxed mt-0.5">{tmpl.desc}</div>
                                    </div>
                                    {active && (
                                        <span className="ml-auto flex-shrink-0 w-4 h-4 rounded-full flex items-center justify-center" style={{ background: `${tmpl.color}25` }}>
                                            <CheckCircle className="w-3 h-3" style={{ color: tmpl.color }} />
                                        </span>
                                    )}
                                </button>
                            )
                        })}
                    </div>
                </div>

                {/* Options */}
                <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-5 space-y-4">
                    <h3 className="text-[11px] font-mono uppercase tracking-widest text-text-muted flex items-center gap-2">
                        <Layers className="w-3.5 h-3.5 text-accent-purple" />
                        Include Data
                    </h3>

                    {/* Scope filter */}
                    <div>
                        <label className="block text-xs text-text-muted mb-1.5">Scope to Flow (optional)</label>
                        <div className="relative">
                            <select
                                value={flowID}
                                onChange={e => setFlowID(e.target.value)}
                                className="w-full appearance-none bg-white/[0.04] border border-white/10 rounded-xl px-3 py-2 text-sm text-text-secondary outline-none focus:border-accent-cyan/40 pr-8"
                            >
                                <option value="">All flows</option>
                                {flows.map(f => (
                                    <option key={f.id} value={f.id}>{f.name}</option>
                                ))}
                            </select>
                            <ChevronDown className="absolute right-2.5 top-2.5 w-3.5 h-3.5 text-text-muted pointer-events-none" />
                        </div>
                    </div>

                    {/* Toggle checkboxes */}
                    {[
                        { key: 'threatIntel', label: 'Threat Intelligence', desc: 'ATT&CK mapping + attack chains', value: includeThreatIntel, onChange: setIncludeThreatIntel, color: '#f87171' },
                        { key: 'monitoring', label: 'Monitoring Delta', desc: 'New findings since baseline', value: includeMonitoring, onChange: setIncludeMonitoring, color: '#6ee7b7' },
                    ].map(({ key, label, desc, value, onChange, color }) => (
                        <label key={key} className="flex items-start gap-3 cursor-pointer group">
                            <div
                                onClick={() => onChange(!value)}
                                className={`mt-0.5 w-4 h-4 rounded flex items-center justify-center border transition-all flex-shrink-0 ${value ? 'border-transparent' : 'border-white/20 bg-white/[0.04]'}`}
                                style={value ? { background: color, borderColor: color } : {}}
                            >
                                {value && <CheckCircle className="w-3 h-3 text-black" />}
                            </div>
                            <div>
                                <div className="text-xs font-medium text-text-secondary group-hover:text-text-primary transition-colors">{label}</div>
                                <div className="text-[10px] text-text-muted">{desc}</div>
                            </div>
                        </label>
                    ))}
                </div>

                {/* Generate button */}
                <button
                    type="button"
                    onClick={generating ? stop : generate}
                    disabled={aiAvailable === false}
                    className="w-full lg-btn py-3.5 text-[15px] disabled:opacity-40 disabled:cursor-not-allowed"
                    style={generating ? { background: 'rgba(239,68,68,0.15)', borderColor: 'rgba(239,68,68,0.3)' } : {}}
                >
                    {generating ? (
                        <>
                            <div className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin relative z-10" />
                            <span className="relative z-10 font-semibold">Stop Generation</span>
                        </>
                    ) : (
                        <>
                            <Sparkles className="w-4 h-4 relative z-10" />
                            <span className="relative z-10 font-semibold">
                                Generate {TEMPLATES.find(t => t.id === template)?.label} Report
                            </span>
                        </>
                    )}
                </button>
            </div>

            {/* Preview panel */}
            <div className="xl:col-span-3">
                <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.02] backdrop-blur-xl shadow-[0_14px_50px_rgba(15,23,42,0.9)] flex flex-col" style={{ minHeight: '520px' }}>
                    {/* Preview header */}
                    <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/[0.06] flex-shrink-0">
                        <div className="flex items-center gap-2">
                            <FileText className="w-3.5 h-3.5 text-accent-cyan" />
                            <span className="text-[11px] font-mono uppercase tracking-widest text-text-muted">
                                Preview
                                {generating && <span className="ml-2 text-accent-cyan animate-pulse">● generating</span>}
                            </span>
                        </div>
                        {content && (
                            <div className="flex items-center gap-2">
                                <span className="text-[10px] font-mono text-text-muted">{charCount.toLocaleString()} chars</span>
                                <button
                                    type="button"
                                    onClick={copyToClipboard}
                                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-white/10 bg-white/[0.04] text-[11px] text-text-muted hover:text-text-primary transition-colors"
                                >
                                    <Copy className="w-3 h-3" /> Copy
                                </button>
                                <button
                                    type="button"
                                    onClick={downloadMarkdown}
                                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-accent-cyan/30 bg-accent-cyan/10 text-[11px] text-accent-cyan hover:bg-accent-cyan/15 transition-colors"
                                >
                                    <Download className="w-3 h-3" /> .md
                                </button>
                            </div>
                        )}
                    </div>

                    {/* Preview body */}
                    <div
                        ref={previewRef}
                        className="flex-1 overflow-y-auto px-6 py-5"
                        style={{ maxHeight: '640px' }}
                    >
                        <AnimatePresence mode="wait">
                            {error ? (
                                <motion.div key="error" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                                    className="flex flex-col items-center justify-center h-full py-20 text-center gap-3">
                                    <AlertTriangle className="w-8 h-8 text-[#ff4757]" />
                                    <p className="text-sm text-[#ff4757]">{error}</p>
                                    <button onClick={() => setError(null)} className="text-xs text-text-muted hover:text-text-primary transition-colors flex items-center gap-1">
                                        <RefreshCw className="w-3 h-3" /> Dismiss
                                    </button>
                                </motion.div>
                            ) : content ? (
                                <motion.div key="content" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                                    <MarkdownView content={content} />
                                    {generating && (
                                        <span className="inline-block w-2 h-4 bg-accent-cyan animate-pulse rounded-sm ml-0.5 align-middle" />
                                    )}
                                </motion.div>
                            ) : (
                                <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                                    className="flex flex-col items-center justify-center h-full py-24 text-center gap-4">
                                    <div className="w-14 h-14 rounded-2xl bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center">
                                        <Sparkles className="w-6 h-6 text-accent-cyan" />
                                    </div>
                                    <div>
                                        <p className="text-sm font-medium text-text-secondary mb-1">AI Report Generator</p>
                                        <p className="text-xs text-text-muted max-w-xs">
                                            Select a template and click Generate to create a professional pentest report from your scan data.
                                        </p>
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                </div>
            </div>
        </div>
    )
}

// ── Export tab (original functionality) ──────────────────────────────────────

function FlowReportRow({ flow, findings }) {
    const [downloading, setDownloading] = useState(null)
    const critical = findings.filter(f => f.severity === 'critical').length
    const high = findings.filter(f => f.severity === 'high').length

    async function download(format) {
        setDownloading(format)
        try {
            const resp = await fetch(`${API_BASE}/flows/${flow.id}/report/${format}`)
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
                    { fmt: 'html',   label: 'HTML',   color: '#67e8f9', icon: FileText },
                    { fmt: 'burp',   label: 'Burp',   color: '#c4b5fd', icon: Bug },
                    { fmt: 'nuclei', label: 'Nuclei', color: '#6ee7b7', icon: FileCode },
                ].map(({ fmt, label, color, icon: Ico }) => (
                    <button
                        key={fmt}
                        onClick={() => download(fmt)}
                        disabled={downloading === fmt}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all hover:opacity-80 disabled:opacity-50"
                        style={{ color, borderColor: `${color}35`, background: `${color}10` }}
                    >
                        {downloading === fmt
                            ? <div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin" />
                            : <Ico className="w-3 h-3" />}
                        {label}
                    </button>
                ))}
            </div>
        </div>
    )
}

function ExportsTab({ flows, findings, loading }) {
    const [downloading, setDownloading] = useState(null)
    const completedFlows = flows.filter(f => f.status === 'completed')

    async function downloadAllHTML() {
        setDownloading('all-html')
        try {
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
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2">
                <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl shadow-[0_14px_50px_rgba(15,23,42,0.9)]">
                    <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
                        <h2 className="text-[11px] font-mono uppercase tracking-widest text-text-muted flex items-center gap-2">
                            <Layers className="w-3.5 h-3.5 text-accent-cyan" />
                            Scan Reports
                        </h2>
                        <div className="flex items-center gap-3">
                            <span className="text-[11px] font-mono text-text-muted">{flows.length} scans</span>
                            <button
                                onClick={downloadAllHTML}
                                disabled={downloading === 'all-html' || completedFlows.length === 0}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-cyan/10 border border-accent-cyan/25 text-accent-cyan text-xs font-mono hover:bg-accent-cyan/15 transition-colors disabled:opacity-40"
                            >
                                <Download className="w-3 h-3" />
                                Export All
                            </button>
                        </div>
                    </div>

                    {loading ? (
                        <div className="p-5 space-y-3">
                            {[1, 2, 3].map(i => <div key={i} className="h-16 rounded-xl bg-white/[0.04] animate-pulse" />)}
                        </div>
                    ) : flows.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-16 text-center px-8">
                            <FileText className="w-10 h-10 text-text-muted mb-3" />
                            <p className="text-text-muted text-sm">No scans completed yet.</p>
                        </div>
                    ) : (
                        <div>
                            {flows.map(flow => (
                                <FlowReportRow key={flow.id} flow={flow} findings={findingsPerFlow[flow.id] || []} />
                            ))}
                        </div>
                    )}
                </div>
            </div>

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
                        {[
                            'OWASP APTS Tier 1 compliant',
                            'SHA-256 evidence integrity hashing',
                            'RP-003 confidence scoring (0-100)',
                            'Confirmed/Unconfirmed classification',
                        ].map(item => (
                            <div key={item} className="flex items-center gap-2">
                                <CheckCircle className="w-3.5 h-3.5 text-accent-green flex-shrink-0" />
                                <span>{item}</span>
                            </div>
                        ))}
                    </div>
                    <a href="/api/apts/status" target="_blank" rel="noreferrer"
                        className="mt-4 flex items-center gap-2 text-xs text-accent-purple hover:text-accent-purple/80 transition-colors">
                        View APTS compliance status <ExternalLink className="w-3 h-3" />
                    </a>
                </div>
            </div>
        </div>
    )
}

// ── Page root ─────────────────────────────────────────────────────────────────

export default function Reports() {
    const [activeTab, setActiveTab] = useState('generate')
    const [flows, setFlows] = useState([])
    const [findings, setFindings] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        Promise.all([
            fetch(`${API_BASE}/flows`).then(r => r.json()).catch(() => []),
            fetch(`${API_BASE}/findings`).then(r => r.json()).catch(() => []),
        ]).then(([f, fi]) => {
            setFlows(Array.isArray(f) ? f : [])
            setFindings(Array.isArray(fi) ? fi : [])
            setLoading(false)
        })
    }, [])

    const critical = findings.filter(f => f.severity === 'critical').length
    const high = findings.filter(f => f.severity === 'high').length
    const completedFlows = flows.filter(f => f.status === 'completed')

    const TABS = [
        { id: 'generate', label: 'AI Generate', icon: Sparkles, color: '#67e8f9' },
        { id: 'exports',  label: 'Exports',     icon: Download,  color: '#6ee7b7' },
    ]

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
                                AI Reporting
                            </div>
                            <h1 className="text-4xl md:text-5xl font-display font-semibold mb-3 tracking-[-0.02em] lg-gradient-text">
                                Reports & Exports
                            </h1>
                            <p className="text-sm md:text-base text-text-secondary flex items-center gap-2">
                                <Sparkles className="w-4 h-4 text-accent-cyan" />
                                Claude-powered report generation · {findings.length} findings · {critical} critical
                            </p>
                        </motion.div>

                        {/* Stats */}
                        <div className="flex items-center gap-3 flex-shrink-0">
                            {[
                                { label: 'Scans', value: flows.length, color: '#67e8f9', icon: Activity },
                                { label: 'Done', value: completedFlows.length, color: '#6ee7b7', icon: CheckCircle },
                                { label: 'Critical', value: critical, color: '#ff4757', icon: AlertTriangle },
                                { label: 'High', value: high, color: '#ff7f50', icon: Zap },
                            ].map(({ label, value, color, icon: _Icon }) => (
                                <div key={label} className="text-center px-3 py-2 rounded-xl bg-white/[0.04] border border-white/[0.08]">
                                    <div className="text-lg font-bold font-mono" style={{ color }}>{value}</div>
                                    <div className="text-[9px] text-text-muted uppercase tracking-wider">{label}</div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* Tab bar */}
            <div className="relative z-10 flex items-center gap-1 mb-6 bg-white/[0.03] border border-white/[0.08] rounded-2xl p-1 w-fit">
                {TABS.map(tab => {
                    const Icon = tab.icon
                    const active = activeTab === tab.id
                    return (
                        <button
                            key={tab.id}
                            type="button"
                            onClick={() => setActiveTab(tab.id)}
                            className={`relative flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all ${
                                active ? 'text-text-primary' : 'text-text-muted hover:text-text-secondary'
                            }`}
                        >
                            {active && (
                                <motion.span
                                    layoutId="reports-tab"
                                    className="absolute inset-0 rounded-xl bg-white/[0.08] border border-white/10 shadow-[inset_0_1px_0_rgba(255,255,255,0.1)]"
                                    transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                                />
                            )}
                            <Icon className="relative z-10 w-4 h-4" style={{ color: active ? tab.color : undefined }} />
                            <span className="relative z-10">{tab.label}</span>
                        </button>
                    )
                })}
            </div>

            {/* Tab content */}
            <div className="relative z-10">
                <AnimatePresence mode="wait">
                    <motion.div
                        key={activeTab}
                        initial={{ opacity: 0, y: 6 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -4 }}
                        transition={{ duration: 0.18, ease: 'easeOut' }}
                    >
                        {activeTab === 'generate'
                            ? <GenerateTab flows={flows} />
                            : <ExportsTab flows={flows} findings={findings} loading={loading} />
                        }
                    </motion.div>
                </AnimatePresence>
            </div>
        </div>
    )
}
