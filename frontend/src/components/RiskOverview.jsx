import React from 'react'
import { motion } from 'framer-motion'
import { Shield, AlertTriangle, TrendingDown, TrendingUp, Minus } from 'lucide-react'

function riskScore(findings) {
    if (!findings.length) return 100
    const weights = { critical: 40, high: 20, medium: 8, low: 2, info: 0 }
    const penalty = findings.reduce((s, f) => s + (weights[f.severity] || 0), 0)
    return Math.max(0, 100 - Math.min(penalty, 100))
}

function riskMeta(score) {
    if (score >= 80) return { label: 'Secure',      color: '#2ed573', track: 'rgba(46,213,115,0.15)' }
    if (score >= 60) return { label: 'Low Risk',    color: '#eccc68', track: 'rgba(236,204,104,0.15)' }
    if (score >= 40) return { label: 'Medium Risk', color: '#ff7f50', track: 'rgba(255,127,80,0.15)' }
    if (score >= 20) return { label: 'High Risk',   color: '#ff4757', track: 'rgba(255,71,87,0.15)' }
    return              { label: 'Critical',        color: '#ff2d3b', track: 'rgba(255,45,59,0.20)' }
}

const SEVERITY_CONFIG = [
    { key: 'critical', label: 'Critical', color: '#ff4757', glow: 'rgba(255,71,87,0.35)' },
    { key: 'high',     label: 'High',     color: '#ff7f50', glow: 'rgba(255,127,80,0.25)' },
    { key: 'medium',   label: 'Medium',   color: '#eccc68', glow: 'rgba(236,204,104,0.20)' },
    { key: 'low',      label: 'Low',      color: '#2ed573', glow: 'rgba(46,213,115,0.18)' },
    { key: 'info',     label: 'Info',     color: '#67e8f9', glow: 'rgba(34,211,238,0.15)' },
]

export default function RiskOverview({ findings = [], flows = [] }) {
    const score = riskScore(findings)
    const meta = riskMeta(score)
    const total = findings.length || 1
    const circumference = 2 * Math.PI * 52 // r=52
    const dash = (score / 100) * circumference

    const targets = new Set(flows.map(f => {
        try { return new URL(f.target).hostname } catch { return f.target }
    })).size

    const criticalTargets = (() => {
        const hostsWithCrit = new Set(
            findings.filter(f => f.severity === 'critical').map(f => {
                try { return new URL(f.url || '').hostname } catch { return f.url }
            })
        )
        return hostsWithCrit.size
    })()

    return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
            {/* Risk Score Gauge */}
            <motion.div
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.4 }}
                className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6 shadow-[0_14px_50px_rgba(15,23,42,0.9)] flex flex-col items-center justify-center"
            >
                <div className="absolute inset-0 pointer-events-none" style={{ background: `radial-gradient(circle at 50% 60%, ${meta.track}, transparent 70%)` }} />
                <div className="relative z-10 text-[10px] font-mono uppercase tracking-widest text-text-muted mb-3">Security Score</div>
                <div className="relative z-10 relative w-36 h-36">
                    <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
                        {/* Track */}
                        <circle cx="60" cy="60" r="52" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
                        {/* Progress */}
                        <circle
                            cx="60" cy="60" r="52" fill="none"
                            stroke={meta.color}
                            strokeWidth="8"
                            strokeLinecap="round"
                            strokeDasharray={`${dash} ${circumference}`}
                            style={{ filter: `drop-shadow(0 0 8px ${meta.color})`, transition: 'stroke-dasharray 1s ease' }}
                        />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-4xl font-bold font-mono" style={{ color: meta.color, textShadow: `0 0 20px ${meta.color}60` }}>{score}</span>
                        <span className="text-[10px] font-semibold mt-0.5" style={{ color: meta.color }}>{meta.label}</span>
                    </div>
                </div>
                <div className="relative z-10 mt-3 flex items-center gap-4 text-[11px] font-mono text-text-muted">
                    <span>{targets} target{targets !== 1 ? 's' : ''}</span>
                    {criticalTargets > 0 && <span style={{ color: '#ff4757' }}>{criticalTargets} critical host{criticalTargets !== 1 ? 's' : ''}</span>}
                </div>
            </motion.div>

            {/* Severity Breakdown Bar Chart */}
            <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.05 }}
                className="lg:col-span-2 relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-6 shadow-[0_14px_50px_rgba(15,23,42,0.9)]"
            >
                <div className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-5 flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-accent-red" />
                    Findings by Severity
                    <span className="ml-auto text-text-muted">{findings.length} total</span>
                </div>

                {findings.length === 0 ? (
                    <div className="flex items-center justify-center h-24 text-text-muted text-sm">
                        No findings yet — run a scan to start
                    </div>
                ) : (
                    <div className="space-y-3">
                        {SEVERITY_CONFIG.map(({ key, label, color, glow }) => {
                            const count = findings.filter(f => f.severity === key).length
                            const pct = Math.round((count / (findings.length || 1)) * 100)
                            return (
                                <div key={key} className="flex items-center gap-3">
                                    <span className="w-14 text-right text-[11px] font-mono flex-shrink-0" style={{ color }}>{label}</span>
                                    <div className="flex-1 h-2 rounded-full bg-white/[0.06] overflow-hidden">
                                        <motion.div
                                            initial={{ width: 0 }}
                                            animate={{ width: `${pct}%` }}
                                            transition={{ duration: 0.8, ease: 'easeOut', delay: 0.1 }}
                                            className="h-full rounded-full"
                                            style={{ background: color, boxShadow: `0 0 8px ${glow}` }}
                                        />
                                    </div>
                                    <div className="flex items-center gap-2 flex-shrink-0 w-16 text-right">
                                        <span className="text-[11px] font-mono text-text-muted ml-auto">{count}</span>
                                        <span className="text-[10px] font-mono" style={{ color: count > 0 ? color : 'transparent' }}>
                                            {pct}%
                                        </span>
                                    </div>
                                </div>
                            )
                        })}
                    </div>
                )}

                {/* Mini heatmap strip at bottom */}
                {findings.length > 0 && (
                    <div className="mt-5 pt-4 border-t border-white/[0.06]">
                        <div className="flex gap-0.5 h-2 rounded-full overflow-hidden">
                            {SEVERITY_CONFIG.map(({ key, color }) => {
                                const count = findings.filter(f => f.severity === key).length
                                if (!count) return null
                                return <div key={key} style={{ flex: count, background: color }} className="rounded-full" />
                            })}
                        </div>
                    </div>
                )}
            </motion.div>
        </div>
    )
}
