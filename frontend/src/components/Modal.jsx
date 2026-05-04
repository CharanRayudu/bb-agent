import React, { useEffect, useRef } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { X } from 'lucide-react'

/**
 * Unified Modal/Dialog component.
 *
 * Props:
 *   open        — boolean
 *   onClose     — called when overlay clicked or Esc pressed
 *   title       — string, rendered in header
 *   subtitle    — optional string under title
 *   size        — 'sm' | 'md' (default) | 'lg' | 'xl' | 'full'
 *   children
 *   footer      — optional ReactNode rendered in sticky footer
 *   hideHeader  — omit title bar entirely
 */

const SIZE_CLASSES = {
    sm: 'max-w-sm',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
    full: 'max-w-[95vw]',
}

export default function Modal({ open, onClose, title, subtitle, size = 'md', children, footer, hideHeader = false }) {
    const overlayRef = useRef(null)

    // Close on Escape
    useEffect(() => {
        if (!open) return
        function handler(e) {
            if (e.key === 'Escape') onClose?.()
        }
        document.addEventListener('keydown', handler)
        return () => document.removeEventListener('keydown', handler)
    }, [open, onClose])

    // Lock body scroll
    useEffect(() => {
        if (open) {
            document.body.style.overflow = 'hidden'
        } else {
            document.body.style.overflow = ''
        }
        return () => { document.body.style.overflow = '' }
    }, [open])

    function handleOverlayClick(e) {
        if (e.target === overlayRef.current) onClose?.()
    }

    return (
        <AnimatePresence>
            {open && (
                <motion.div
                    ref={overlayRef}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.18 }}
                    onClick={handleOverlayClick}
                    className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/50 backdrop-blur-md"
                >
                    <motion.div
                        initial={{ opacity: 0, scale: 0.96, y: 10 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95, y: 8 }}
                        transition={{ duration: 0.22, ease: [0.2, 0.8, 0.2, 1] }}
                        className={`lg-surface-hero w-full ${SIZE_CLASSES[size] || SIZE_CLASSES.md} flex flex-col max-h-[90vh]`}
                        onClick={(e) => e.stopPropagation()}
                    >
                        {/* Header */}
                        {!hideHeader && (
                            <div className="relative z-10 flex items-start gap-4 px-6 py-5 border-b border-white/[0.08]">
                                <div className="flex-1 min-w-0">
                                    {title && (
                                        <h2 className="text-[15px] font-semibold text-text-primary leading-tight">{title}</h2>
                                    )}
                                    {subtitle && (
                                        <p className="text-[12px] text-text-muted mt-0.5">{subtitle}</p>
                                    )}
                                </div>
                                {onClose && (
                                    <button
                                        type="button"
                                        onClick={onClose}
                                        className="w-7 h-7 flex items-center justify-center rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.08] transition-colors flex-shrink-0"
                                    >
                                        <X className="w-4 h-4" />
                                    </button>
                                )}
                            </div>
                        )}

                        {/* Body */}
                        <div className="relative z-10 flex-1 overflow-y-auto px-6 py-5">
                            {children}
                        </div>

                        {/* Footer */}
                        {footer && (
                            <div className="relative z-10 border-t border-white/[0.08] px-6 py-4 flex items-center gap-3 justify-end">
                                {footer}
                            </div>
                        )}
                    </motion.div>
                </motion.div>
            )}
        </AnimatePresence>
    )
}
