import React from 'react'
import { Activity, AlertTriangle, CheckCircle, Clock3, FileText, Search, Shield, Target, XCircle } from 'lucide-react'

const CHIP_BASE = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono uppercase tracking-[0.16em]'

function humanize(value) {
    return (value || 'unknown')
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function statusClasses(value) {
    const normalized = (value || '').toLowerCase()
    if (normalized === 'confirmed' || normalized === 'completed') {
        return 'bg-accent-green/15 text-accent-green border-accent-green/30'
    }
    if (normalized === 'running') {
        return 'bg-accent-cyan/15 text-accent-cyan border-accent-cyan/30'
    }
    if (normalized === 'needs proof' || normalized === 'needs_proof' || normalized === 'pending') {
        return 'bg-accent-yellow/15 text-accent-yellow border-accent-yellow/30'
    }
    if (normalized.includes('blocked')) {
        return 'bg-accent-orange/15 text-accent-orange border-accent-orange/30'
    }
    if (normalized === 'rejected' || normalized === 'failed') {
        return 'bg-accent-red/15 text-accent-red border-accent-red/30'
    }
    return 'bg-white/10 text-text-muted border-white/10'
}

function summaryCard(label, value, Icon, accent) {
    return (
        <div className="rounded-xl border border-white/10 bg-white/5 p-3 shadow-[0_12px_36px_rgba(15,23,42,0.65)]">
            <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.18em] text-text-muted">
                <Icon className={`w-3.5 h-3.5 ${accent}`} />
                {label}
            </div>
            <div className="mt-2 text-2xl font-black text-text-primary">{value}</div>
        </div>
    )
}

export function FlowLedgerPanel({ ledger, formatTime }) {
    if (!ledger || !Array.isArray(ledger.tasks) || ledger.tasks.length === 0) {
        return (
            <div className="h-full flex items-center justify-center text-text-muted text-sm italic py-10">
                Execution ledger is still being initialized.
            </div>
        )
    }

    const summary = ledger.summary || {}

    return (
        <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
                {summaryCard('Execution Units', summary.total_subtasks || 0, Activity, 'text-accent-cyan')}
                {summaryCard('Confirmed Proof', summary.confirmed_evidence || 0, Shield, 'text-accent-green')}
                {summaryCard('Needs Proof', summary.needs_proof || 0, Search, 'text-accent-yellow')}
                {summaryCard('Rejected', summary.rejected_evidence || 0, XCircle, 'text-accent-red')}
            </div>

            <div className="space-y-3">
                {ledger.tasks.map((task) => (
                    <div key={task.id} className="rounded-2xl border border-white/12 bg-white/5 p-4 shadow-[0_12px_40px_rgba(15,23,42,0.75)]">
                        <div className="flex items-start justify-between gap-3">
                            <div>
                                <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-text-muted">Objective</div>
                                <div className="mt-1 text-sm font-bold text-text-primary">{task.name}</div>
                                {task.description && (
                                    <p className="mt-2 text-xs leading-relaxed text-text-muted">{task.description}</p>
                                )}
                                {task.result && (
                                    <p className="mt-3 text-xs leading-relaxed text-text-primary/90 bg-white/5 border border-white/10 rounded-xl p-3">
                                        {task.result}
                                    </p>
                                )}
                            </div>
                            <span className={`${CHIP_BASE} ${statusClasses(task.status)}`}>
                                {humanize(task.status)}
                            </span>
                        </div>

                        <div className="mt-4 space-y-3">
                            {(task.subtasks || []).map((subtask) => (
                                <div key={subtask.id} className="rounded-xl border border-white/10 bg-[#111827]/50 p-3">
                                    <div className="flex items-start justify-between gap-3">
                                        <div className="min-w-0">
                                            <div className="flex flex-wrap items-center gap-2">
                                                <span className="text-sm font-semibold text-text-primary">{subtask.name}</span>
                                                <span className={`${CHIP_BASE} ${statusClasses(subtask.kind)}`}>{humanize(subtask.kind)}</span>
                                                {subtask.priority && (
                                                    <span className={`${CHIP_BASE} bg-white/5 border-white/10 text-text-muted`}>
                                                        {subtask.priority}
                                                    </span>
                                                )}
                                            </div>
                                            {subtask.description && (
                                                <p className="mt-2 text-xs leading-relaxed text-text-muted">{subtask.description}</p>
                                            )}
                                        </div>
                                        <div className="flex flex-col items-end gap-1">
                                            <span className={`${CHIP_BASE} ${statusClasses(subtask.status)}`}>{humanize(subtask.status)}</span>
                                            {subtask.outcome && (
                                                <span className={`${CHIP_BASE} ${statusClasses(subtask.outcome)}`}>{humanize(subtask.outcome)}</span>
                                            )}
                                        </div>
                                    </div>

                                    <div className="mt-3 flex flex-wrap gap-2 text-[10px] font-mono uppercase tracking-[0.16em] text-text-muted">
                                        {subtask.target && (
                                            <span className={`${CHIP_BASE} bg-white/5 border-white/10 normal-case tracking-normal`}>
                                                <Target className="w-3 h-3 text-accent-cyan" />
                                                <span className="truncate max-w-[180px]">{subtask.target}</span>
                                            </span>
                                        )}
                                        {subtask.queue_name && (
                                            <span className={`${CHIP_BASE} bg-white/5 border-white/10`}>
                                                <FileText className="w-3 h-3 text-accent-purple" />
                                                {subtask.queue_name}
                                            </span>
                                        )}
                                        {subtask.updated_at && (
                                            <span className={`${CHIP_BASE} bg-white/5 border-white/10 normal-case tracking-normal`}>
                                                <Clock3 className="w-3 h-3 text-accent-yellow" />
                                                {formatTime(subtask.updated_at)}
                                            </span>
                                        )}
                                    </div>

                                    {subtask.result && (
                                        <div className="mt-3 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-xs leading-relaxed text-text-primary/85">
                                            {subtask.result}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    )
}

export function FlowEvidencePanel({ evidence, formatTime }) {
    if (!Array.isArray(evidence) || evidence.length === 0) {
        return (
            <div className="h-full flex items-center justify-center text-text-muted text-sm italic py-10">
                No evidence packs recorded yet.
            </div>
        )
    }

    return (
        <div className="space-y-3">
            {evidence.map((item) => {
                const proofKeys = Object.keys(item.proof || {}).filter((key) => key !== 'summary' && key !== 'payload')
                return (
                    <div key={item.id || item.fingerprint} className="rounded-2xl border border-white/12 bg-white/5 p-4 shadow-[0_12px_40px_rgba(15,23,42,0.75)]">
                        <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                                <div className="flex flex-wrap items-center gap-2">
                                    <span className="text-sm font-bold text-text-primary">{item.type || 'Hypothesis'}</span>
                                    <span className={`${CHIP_BASE} ${statusClasses(item.status)}`}>{humanize(item.status)}</span>
                                    {item.severity && (
                                        <span className={`${CHIP_BASE} ${statusClasses(item.severity)}`}>{item.severity}</span>
                                    )}
                                </div>
                                <div className="mt-2 text-xs text-text-muted break-all">{item.url || 'Target not captured'}</div>
                            </div>
                            <div className="text-right text-[10px] font-mono uppercase tracking-[0.18em] text-text-muted">
                                <div>{item.source_agent || 'unknown agent'}</div>
                                <div className="mt-1 normal-case tracking-normal">{formatTime(item.updated_at || item.created_at)}</div>
                            </div>
                        </div>

                        {item.summary && (
                            <p className="mt-3 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs leading-relaxed text-text-primary/90">
                                {item.summary}
                            </p>
                        )}

                        <div className="mt-3 flex flex-wrap gap-2 text-[10px] font-mono uppercase tracking-[0.16em] text-text-muted">
                            {item.parameter && (
                                <span className={`${CHIP_BASE} bg-white/5 border-white/10`}>
                                    <Target className="w-3 h-3 text-accent-cyan" />
                                    {item.parameter}
                                </span>
                            )}
                            {typeof item.confidence === 'number' && item.confidence > 0 && (
                                <span className={`${CHIP_BASE} bg-white/5 border-white/10`}>
                                    <CheckCircle className="w-3 h-3 text-accent-green" />
                                    {Math.round(item.confidence * 100)}%
                                </span>
                            )}
                            {proofKeys.length > 0 && (
                                <span className={`${CHIP_BASE} bg-white/5 border-white/10`}>
                                    <AlertTriangle className="w-3 h-3 text-accent-yellow" />
                                    {proofKeys.length} proof signals
                                </span>
                            )}
                        </div>

                        {proofKeys.length > 0 && (
                            <details className="mt-3 rounded-xl border border-white/10 bg-[#111827]/50 p-3">
                                <summary className="cursor-pointer text-xs font-semibold text-text-primary">Proof Details</summary>
                                <pre className="mt-3 whitespace-pre-wrap break-words text-[11px] text-text-muted">
                                    {JSON.stringify(item.proof, null, 2)}
                                </pre>
                            </details>
                        )}
                    </div>
                )
            })}
        </div>
    )
}
