import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Brain, ChevronDown, ChevronRight, Zap, Target, AlertTriangle, CheckCircle, Clock, XCircle } from 'lucide-react'

const VULN_COLORS = {
    SQLi: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/25' },
    XSS: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/25' },
    SSRF: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/25' },
    RCE: { bg: 'bg-red-600/15', text: 'text-red-300', border: 'border-red-600/40' },
    IDOR: { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/25' },
    AuthBypass: { bg: 'bg-pink-500/10', text: 'text-pink-400', border: 'border-pink-500/25' },
    BusinessLogic: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/25' },
    Deserialization: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/25' },
    default: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/25' },
}

function VulnBadge({ type }) {
    const colors = VULN_COLORS[type] || VULN_COLORS.default
    return (
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider border ${colors.bg} ${colors.text} ${colors.border}`}>
            {type}
        </span>
    )
}

function ConfidenceBar({ value }) {
    const pct = Math.round(value * 100)
    const color = pct >= 80 ? 'bg-red-500' : pct >= 60 ? 'bg-orange-500' : pct >= 40 ? 'bg-yellow-500' : 'bg-blue-500'
    return (
        <div className="flex items-center gap-2">
            <div className="flex-1 h-1 bg-[#1e2535] rounded-full overflow-hidden">
                <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.6, ease: 'easeOut' }}
                    className={`h-full rounded-full ${color}`}
                />
            </div>
            <span className="text-[10px] font-mono text-[#8b98b1] w-8 text-right">{pct}%</span>
        </div>
    )
}

function PriorityDots({ priority }) {
    return (
        <div className="flex items-center gap-0.5">
            {Array.from({ length: 10 }).map((_, i) => (
                <div
                    key={i}
                    className={`w-1.5 h-1.5 rounded-full transition-colors ${i < priority
                        ? priority >= 8 ? 'bg-red-500' : priority >= 5 ? 'bg-orange-400' : 'bg-blue-400'
                        : 'bg-[#1e2535]'
                        }`}
                />
            ))}
            <span className="ml-1 text-[10px] text-[#4b5675] font-mono">{priority}/10</span>
        </div>
    )
}

function HypothesisCard({ hyp, index }) {
    const [expanded, setExpanded] = useState(false)

    const statusIcon = hyp.zero_day_risk
        ? <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
        : hyp.confidence >= 0.8
            ? <Zap className="w-3.5 h-3.5 text-red-400" />
            : <Target className="w-3.5 h-3.5 text-[#4b5675]" />

    return (
        <motion.div
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.04 }}
            className="border border-[#1e2535] rounded-lg overflow-hidden bg-[#111318] hover:border-[#2d3a52] transition-colors"
        >
            <button
                type="button"
                onClick={() => setExpanded(!expanded)}
                className="w-full text-left px-4 py-3 flex items-start gap-3"
            >
                <div className="mt-0.5 flex-shrink-0">{statusIcon}</div>
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                        <span className="text-[13px] font-semibold text-[#e2e8f0] leading-tight">{hyp.title}</span>
                        <VulnBadge type={hyp.vuln_class} />
                        {hyp.zero_day_risk && (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider bg-amber-500/15 text-amber-400 border border-amber-500/30">
                                0-DAY
                            </span>
                        )}
                    </div>
                    <ConfidenceBar value={hyp.confidence} />
                    <div className="mt-1.5">
                        <PriorityDots priority={hyp.priority} />
                    </div>
                </div>
                <div className="flex-shrink-0 text-[#4b5675] mt-0.5">
                    {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                </div>
            </button>

            <AnimatePresence>
                {expanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                    >
                        <div className="px-4 pb-4 pt-1 border-t border-[#1e2535] space-y-3">
                            {/* Target */}
                            {hyp.target && (
                                <div>
                                    <div className="text-[10px] text-[#4b5675] uppercase tracking-wider mb-1 font-mono">Target</div>
                                    <code className="text-[11px] text-cyan-400 font-mono bg-cyan-500/5 px-2 py-0.5 rounded border border-cyan-500/15">
                                        {hyp.target}
                                    </code>
                                </div>
                            )}

                            {/* Premise */}
                            {hyp.premise && (
                                <div>
                                    <div className="text-[10px] text-[#4b5675] uppercase tracking-wider mb-1 font-mono">Hypothesis</div>
                                    <p className="text-[12px] text-[#8b98b1] leading-relaxed">{hyp.premise}</p>
                                </div>
                            )}

                            {/* Kill Chain */}
                            {hyp.kill_chain && hyp.kill_chain.length > 0 && (
                                <div>
                                    <div className="text-[10px] text-[#4b5675] uppercase tracking-wider mb-1.5 font-mono">Kill Chain</div>
                                    <div className="space-y-1">
                                        {hyp.kill_chain.map((step, i) => (
                                            <div key={i} className="flex items-start gap-2">
                                                <span className="text-[10px] font-mono text-[#4b5675] bg-[#161b24] border border-[#1e2535] rounded px-1.5 py-0.5 flex-shrink-0 mt-0.5">
                                                    {String(i + 1).padStart(2, '0')}
                                                </span>
                                                <span className="text-[12px] text-[#8b98b1]">{step}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Impact */}
                            {hyp.impact && (
                                <div className="p-2.5 rounded bg-red-500/5 border border-red-500/15">
                                    <div className="text-[10px] text-red-400/70 uppercase tracking-wider mb-1 font-mono">Impact</div>
                                    <p className="text-[12px] text-red-300/80">{hyp.impact}</p>
                                </div>
                            )}

                            {/* Evidence */}
                            {hyp.evidence && hyp.evidence.length > 0 && (
                                <div>
                                    <div className="text-[10px] text-[#4b5675] uppercase tracking-wider mb-1 font-mono">Evidence</div>
                                    <div className="flex flex-wrap gap-1">
                                        {hyp.evidence.map((e, i) => (
                                            <span key={i} className="text-[10px] text-[#8b98b1] bg-[#161b24] border border-[#1e2535] rounded px-2 py-0.5 font-mono">
                                                {e}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    )
}

export default function HypothesisTracker({ flowId, hypotheses: propHyps }) {
    const [hypotheses, setHypotheses] = useState(propHyps || [])
    const [loading, setLoading] = useState(!propHyps)
    const [fetchError, setFetchError] = useState(null)
    const [filter, setFilter] = useState('all')

    useEffect(() => {
        if (propHyps) {
            setHypotheses(propHyps)
            setLoading(false)
            return
        }
        if (!flowId) return

        async function load() {
            setFetchError(null)
            try {
                const res = await fetch(`/api/flows/${flowId}/hypotheses`)
                if (!res.ok) throw new Error(`HTTP ${res.status}`)
                const data = await res.json()
                setHypotheses(Array.isArray(data) ? data : [])
            } catch (e) {
                console.error('Failed to load hypotheses', e)
                setFetchError(e.message || 'Failed to load hypotheses')
            } finally {
                setLoading(false)
            }
        }
        load()
    }, [flowId, propHyps])

    const zeroDayCount = hypotheses.filter(h => h.zero_day_risk).length
    const highPriority = hypotheses.filter(h => h.priority >= 8).length

    const filtered = filter === 'zeroday'
        ? hypotheses.filter(h => h.zero_day_risk)
        : filter === 'high'
            ? hypotheses.filter(h => h.priority >= 7)
            : hypotheses

    if (loading) {
        return (
            <div className="space-y-2">
                {Array.from({ length: 3 }).map((_, i) => (
                    <div key={i} className="h-16 rounded-lg border border-[#1e2535] bg-[#111318] animate-pulse" />
                ))}
            </div>
        )
    }

    if (fetchError) {
        return (
            <div className="flex flex-col items-center justify-center py-10 text-center">
                <XCircle className="w-8 h-8 text-red-400/60 mb-3" />
                <p className="text-[13px] text-red-400">Failed to load hypotheses</p>
                <p className="text-[11px] text-[#4b5675] mt-1 font-mono">{fetchError}</p>
            </div>
        )
    }

    if (hypotheses.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-10 text-center">
                <Brain className="w-10 h-10 text-[#1e2535] mb-3" />
                <p className="text-[13px] text-[#4b5675]">Hypothesis engine initializing…</p>
                <p className="text-[11px] text-[#4b5675]/60 mt-1">Hypotheses generate after recon completes</p>
            </div>
        )
    }

    return (
        <div className="space-y-3">
            {/* Header stats */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4 text-[11px] font-mono text-[#4b5675]">
                    <span>{hypotheses.length} hypotheses</span>
                    {zeroDayCount > 0 && (
                        <span className="text-amber-400">{zeroDayCount} potential 0-days</span>
                    )}
                    {highPriority > 0 && (
                        <span className="text-red-400">{highPriority} high-priority</span>
                    )}
                </div>
                {/* Filter */}
                <div className="flex items-center gap-1 text-[10px] font-mono">
                    {['all', 'high', 'zeroday'].map(f => (
                        <button
                            key={f}
                            type="button"
                            onClick={() => setFilter(f)}
                            className={`px-2 py-1 rounded capitalize transition-colors ${filter === f
                                ? 'bg-cyan-500/15 text-cyan-400'
                                : 'text-[#4b5675] hover:text-[#8b98b1]'
                                }`}
                        >
                            {f}
                        </button>
                    ))}
                </div>
            </div>

            {/* Hypothesis list */}
            <div className="space-y-1.5">
                {filtered.map((hyp, i) => (
                    <HypothesisCard key={hyp.id || i} hyp={hyp} index={i} />
                ))}
            </div>
        </div>
    )
}
