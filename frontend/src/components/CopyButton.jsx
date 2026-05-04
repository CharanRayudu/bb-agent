import React, { useState, useCallback } from 'react'
import { Copy, Check } from 'lucide-react'

/**
 * Copy-to-clipboard button.
 *
 * Props:
 *   text      — string to copy
 *   className — extra classes on the button
 *   size      — 'sm' (default) | 'md'
 *   label     — optional text label beside icon
 */
export default function CopyButton({ text, className = '', size = 'sm', label }) {
    const [copied, setCopied] = useState(false)

    const handleCopy = useCallback(async () => {
        if (!text) return
        try {
            await navigator.clipboard.writeText(text)
        } catch {
            // Fallback for non-secure contexts
            const el = document.createElement('textarea')
            el.value = text
            el.style.position = 'fixed'
            el.style.opacity = '0'
            document.body.appendChild(el)
            el.select()
            document.execCommand('copy')
            document.body.removeChild(el)
        }
        setCopied(true)
        setTimeout(() => setCopied(false), 1800)
    }, [text])

    const iconSize = size === 'md' ? 'w-4 h-4' : 'w-3.5 h-3.5'
    const padding  = size === 'md' ? 'px-3 py-1.5' : 'px-2 py-1'

    return (
        <button
            type="button"
            onClick={handleCopy}
            title={copied ? 'Copied!' : 'Copy to clipboard'}
            className={`inline-flex items-center gap-1.5 rounded-lg border transition-all duration-200 font-mono text-[11px]
                ${copied
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                    : 'border-white/[0.10] bg-white/[0.04] text-text-muted hover:bg-white/[0.08] hover:text-text-primary hover:border-white/[0.16]'
                } ${padding} ${className}`}
        >
            {copied
                ? <Check className={iconSize} />
                : <Copy className={iconSize} />
            }
            {label && <span>{copied ? 'Copied' : label}</span>}
        </button>
    )
}
