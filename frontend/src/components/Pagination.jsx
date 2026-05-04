import React from 'react'
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react'

/**
 * Pagination controls.
 *
 * Props:
 *   page        — current page (1-based)
 *   totalPages  — total number of pages
 *   onChange    — (page: number) => void
 *   pageSize    — optional, for showing "X per page"
 *   totalItems  — optional total count shown as "1–20 of 138"
 */
export default function Pagination({ page, totalPages, onChange, pageSize, totalItems }) {
    if (totalPages <= 1) return null

    const canPrev = page > 1
    const canNext = page < totalPages

    // Sliding window of page numbers
    function getPages() {
        const delta = 2
        const range = []
        const left  = Math.max(2, page - delta)
        const right = Math.min(totalPages - 1, page + delta)

        range.push(1)
        if (left > 2) range.push('...')
        for (let i = left; i <= right; i++) range.push(i)
        if (right < totalPages - 1) range.push('...')
        if (totalPages > 1) range.push(totalPages)
        return range
    }

    const btnBase = 'w-8 h-8 flex items-center justify-center rounded-lg text-[12px] font-mono transition-all'
    const btnActive = 'bg-accent-cyan/20 border border-accent-cyan/40 text-accent-cyan shadow-[0_0_12px_rgba(34,211,238,0.2)]'
    const btnNormal = 'text-text-secondary hover:text-text-primary hover:bg-white/[0.06] border border-transparent hover:border-white/[0.10]'
    const btnDisabled = 'text-text-muted opacity-40 cursor-not-allowed border border-transparent'

    return (
        <div className="flex items-center justify-between gap-4 mt-4 flex-wrap">
            {/* Item count summary */}
            {totalItems != null && pageSize != null ? (
                <span className="text-[12px] text-text-muted font-mono">
                    {((page - 1) * pageSize) + 1}–{Math.min(page * pageSize, totalItems)} of {totalItems}
                </span>
            ) : (
                <span className="text-[12px] text-text-muted font-mono">
                    Page {page} of {totalPages}
                </span>
            )}

            {/* Controls */}
            <div className="flex items-center gap-1">
                {/* First page */}
                <button
                    type="button"
                    disabled={!canPrev}
                    onClick={() => onChange(1)}
                    className={`${btnBase} ${canPrev ? btnNormal : btnDisabled}`}
                    title="First page"
                >
                    <ChevronsLeft className="w-3.5 h-3.5" />
                </button>

                {/* Previous */}
                <button
                    type="button"
                    disabled={!canPrev}
                    onClick={() => onChange(page - 1)}
                    className={`${btnBase} ${canPrev ? btnNormal : btnDisabled}`}
                    title="Previous page"
                >
                    <ChevronLeft className="w-3.5 h-3.5" />
                </button>

                {/* Page numbers */}
                {getPages().map((p, idx) =>
                    p === '...'
                        ? <span key={`ellipsis-${idx}`} className="w-8 h-8 flex items-center justify-center text-[12px] text-text-muted">…</span>
                        : (
                            <button
                                key={p}
                                type="button"
                                onClick={() => onChange(p)}
                                className={`${btnBase} ${p === page ? btnActive : btnNormal}`}
                            >
                                {p}
                            </button>
                        )
                )}

                {/* Next */}
                <button
                    type="button"
                    disabled={!canNext}
                    onClick={() => onChange(page + 1)}
                    className={`${btnBase} ${canNext ? btnNormal : btnDisabled}`}
                    title="Next page"
                >
                    <ChevronRight className="w-3.5 h-3.5" />
                </button>

                {/* Last page */}
                <button
                    type="button"
                    disabled={!canNext}
                    onClick={() => onChange(totalPages)}
                    className={`${btnBase} ${canNext ? btnNormal : btnDisabled}`}
                    title="Last page"
                >
                    <ChevronsRight className="w-3.5 h-3.5" />
                </button>
            </div>
        </div>
    )
}
