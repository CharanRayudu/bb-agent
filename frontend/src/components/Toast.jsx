import React, { createContext, useContext, useCallback, useState, useRef } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { CheckCircle2, XCircle, AlertTriangle, Info, X } from 'lucide-react'

const ToastContext = createContext(null)

const ICONS = {
    success: CheckCircle2,
    error: XCircle,
    warning: AlertTriangle,
    info: Info,
}

const STYLES = {
    success: {
        icon: 'text-emerald-400',
        border: 'border-emerald-500/30',
        glow: 'shadow-[0_0_20px_rgba(16,185,129,0.15)]',
        bar: 'bg-emerald-400',
    },
    error: {
        icon: 'text-red-400',
        border: 'border-red-500/30',
        glow: 'shadow-[0_0_20px_rgba(239,68,68,0.15)]',
        bar: 'bg-red-400',
    },
    warning: {
        icon: 'text-amber-400',
        border: 'border-amber-500/30',
        glow: 'shadow-[0_0_20px_rgba(245,158,11,0.15)]',
        bar: 'bg-amber-400',
    },
    info: {
        icon: 'text-accent-cyan',
        border: 'border-accent-cyan/30',
        glow: 'shadow-[0_0_20px_rgba(34,211,238,0.15)]',
        bar: 'bg-accent-cyan',
    },
}

let _idCounter = 0

function ToastItem({ toast, onDismiss }) {
    const s = STYLES[toast.type] || STYLES.info
    const Icon = ICONS[toast.type] || Info
    const duration = toast.duration ?? 4000

    return (
        <motion.div
            layout
            initial={{ opacity: 0, y: 16, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.94 }}
            transition={{ duration: 0.22, ease: [0.2, 0.8, 0.2, 1] }}
            className={`relative flex items-start gap-3 min-w-[280px] max-w-sm w-full px-4 py-3.5 rounded-2xl bg-surface-2/90 backdrop-blur-xl border ${s.border} ${s.glow} overflow-hidden`}
        >
            {/* Progress bar */}
            {duration > 0 && (
                <motion.div
                    className={`absolute bottom-0 left-0 h-[2px] ${s.bar} opacity-60`}
                    initial={{ width: '100%' }}
                    animate={{ width: '0%' }}
                    transition={{ duration: duration / 1000, ease: 'linear' }}
                />
            )}

            <Icon className={`w-4.5 h-4.5 mt-0.5 flex-shrink-0 ${s.icon}`} style={{ width: 18, height: 18 }} />

            <div className="flex-1 min-w-0">
                {toast.title && (
                    <p className="text-[13px] font-semibold text-text-primary leading-tight">{toast.title}</p>
                )}
                {toast.message && (
                    <p className="text-[12px] text-text-secondary leading-snug mt-0.5">{toast.message}</p>
                )}
            </div>

            <button
                type="button"
                onClick={() => onDismiss(toast.id)}
                className="flex-shrink-0 mt-0.5 w-5 h-5 flex items-center justify-center rounded-md text-text-muted hover:text-text-primary hover:bg-white/[0.08] transition-colors"
            >
                <X className="w-3 h-3" />
            </button>
        </motion.div>
    )
}

export function ToastProvider({ children }) {
    const [toasts, setToasts] = useState([])
    const timersRef = useRef({})

    const dismiss = useCallback((id) => {
        clearTimeout(timersRef.current[id])
        delete timersRef.current[id]
        setToasts((prev) => prev.filter((t) => t.id !== id))
    }, [])

    const toast = useCallback((opts) => {
        const id = ++_idCounter
        const duration = opts.duration ?? 4000
        setToasts((prev) => [...prev.slice(-4), { ...opts, id }])
        if (duration > 0) {
            timersRef.current[id] = setTimeout(() => dismiss(id), duration)
        }
        return id
    }, [dismiss])

    // Convenience wrappers
    toast.success = (message, opts) => toast({ type: 'success', message, ...opts })
    toast.error   = (message, opts) => toast({ type: 'error',   message, ...opts })
    toast.warning = (message, opts) => toast({ type: 'warning', message, ...opts })
    toast.info    = (message, opts) => toast({ type: 'info',    message, ...opts })

    return (
        <ToastContext.Provider value={toast}>
            {children}
            <div className="fixed bottom-6 right-6 z-[100] flex flex-col gap-2 items-end pointer-events-none">
                <AnimatePresence mode="sync">
                    {toasts.map((t) => (
                        <div key={t.id} className="pointer-events-auto">
                            <ToastItem toast={t} onDismiss={dismiss} />
                        </div>
                    ))}
                </AnimatePresence>
            </div>
        </ToastContext.Provider>
    )
}

export function useToast() {
    const ctx = useContext(ToastContext)
    if (!ctx) throw new Error('useToast must be used within <ToastProvider>')
    return ctx
}
