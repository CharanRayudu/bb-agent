import React from 'react'
import { motion } from 'framer-motion'
import { Inbox } from 'lucide-react'

/**
 * Unified empty state for tables, lists, and grids.
 *
 * Props:
 *   icon       — lucide-react component (default: Inbox)
 *   title      — bold heading
 *   message    — supporting text
 *   action     — { label, onClick } optional CTA button
 *   compact    — reduce vertical padding
 */
export default function EmptyState({ icon: Icon = Inbox, title, message, action, compact = false }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
            className={`flex flex-col items-center justify-center text-center ${compact ? 'py-10 px-4' : 'py-20 px-6'}`}
        >
            <div className="relative mb-5">
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-white/[0.06] to-white/[0.02] border border-white/[0.10] flex items-center justify-center shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
                    <Icon className="w-7 h-7 text-text-muted" />
                </div>
                <span className="absolute -inset-2 rounded-2xl bg-accent-cyan/[0.04] blur-lg -z-10" />
            </div>

            {title && (
                <p className="text-[15px] font-semibold text-text-primary mb-1.5">{title}</p>
            )}
            {message && (
                <p className="text-[13px] text-text-muted max-w-xs leading-relaxed">{message}</p>
            )}
            {action && (
                <button
                    type="button"
                    onClick={action.onClick}
                    className="mt-5 lg-btn text-[13px] px-5 py-2"
                >
                    {action.label}
                </button>
            )}
        </motion.div>
    )
}
