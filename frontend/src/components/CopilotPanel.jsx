import React, { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Bot, X, Send, RefreshCw, ChevronDown, Sparkles,
    Copy, User, AlertTriangle
} from 'lucide-react'

const API_BASE = '/api'

// ── Inline markdown renderer (shared with Reports) ───────────────────────────

function renderInline(text, key = 0) {
    const parts = []
    let i = 0
    let k = key
    while (i < text.length) {
        if (text[i] === '*' && text[i + 1] === '*') {
            const end = text.indexOf('**', i + 2)
            if (end !== -1) {
                parts.push(<strong key={k++} className="text-text-primary font-semibold">{text.slice(i + 2, end)}</strong>)
                i = end + 2; continue
            }
        }
        if (text[i] === '`') {
            const end = text.indexOf('`', i + 1)
            if (end !== -1) {
                parts.push(<code key={k++} className="px-1 py-0.5 rounded bg-white/[0.10] text-accent-cyan text-[0.82em] font-mono">{text.slice(i + 1, end)}</code>)
                i = end + 1; continue
            }
        }
        let j = i + 1
        while (j < text.length && text[j] !== '*' && text[j] !== '`') j++
        parts.push(<React.Fragment key={k++}>{text.slice(i, j)}</React.Fragment>)
        i = j
    }
    return parts
}

function MiniMarkdown({ content }) {
    const lines = content.split('\n')
    const nodes = []
    let listItems = []
    let k = 0

    function flushList() {
        if (!listItems.length) return
        nodes.push(
            <ul key={k++} className="my-2 space-y-1 pl-3">
                {listItems.map((li, i) => (
                    <li key={i} className="text-[13px] text-text-secondary flex items-start gap-2">
                        <span className="mt-1.5 w-1 h-1 rounded-full bg-accent-cyan/60 flex-shrink-0" />
                        <span>{renderInline(li, i * 100)}</span>
                    </li>
                ))}
            </ul>
        )
        listItems = []
    }

    for (const line of lines) {
        if (line.startsWith('- ') || line.startsWith('* ')) {
            listItems.push(line.slice(2)); continue
        }
        if (listItems.length) flushList()

        if (line.startsWith('### ')) {
            nodes.push(<p key={k++} className="text-[13px] font-semibold text-text-primary mt-3 mb-1">{renderInline(line.slice(4), k)}</p>)
        } else if (line.startsWith('## ')) {
            nodes.push(<p key={k++} className="text-[13px] font-bold text-text-primary mt-3 mb-1 pb-1 border-b border-white/[0.08]">{renderInline(line.slice(3), k)}</p>)
        } else if (line.startsWith('# ')) {
            nodes.push(<p key={k++} className="text-sm font-bold text-text-primary mt-2 mb-1">{renderInline(line.slice(2), k)}</p>)
        } else if (line === '---') {
            nodes.push(<hr key={k++} className="my-3 border-white/[0.08]" />)
        } else if (line.trim() === '') {
            nodes.push(<div key={k++} className="mb-2" />)
        } else {
            nodes.push(<p key={k++} className="text-[13px] text-text-secondary leading-relaxed">{renderInline(line, k)}</p>)
        }
    }
    flushList()
    return <>{nodes}</>
}

// ── Message bubble ────────────────────────────────────────────────────────────

function MessageBubble({ msg, isStreaming }) {
    const isUser = msg.role === 'user'

    function copy() {
        navigator.clipboard.writeText(msg.content).catch(() => {})
    }

    return (
        <div className={`flex gap-2.5 group ${isUser ? 'flex-row-reverse' : ''}`}>
            {/* Avatar */}
            <div className={`w-7 h-7 rounded-xl flex items-center justify-center flex-shrink-0 mt-0.5 ${
                isUser
                    ? 'bg-accent-cyan/20 border border-accent-cyan/30'
                    : 'bg-accent-purple/20 border border-accent-purple/30'
            }`}>
                {isUser
                    ? <User className="w-3.5 h-3.5 text-accent-cyan" />
                    : <Bot className="w-3.5 h-3.5 text-accent-purple" />
                }
            </div>

            {/* Bubble */}
            <div className={`max-w-[82%] relative ${isUser ? 'items-end' : 'items-start'} flex flex-col`}>
                <div className={`rounded-2xl px-3.5 py-2.5 ${
                    isUser
                        ? 'bg-accent-cyan/15 border border-accent-cyan/25 text-text-primary rounded-tr-md'
                        : 'bg-white/[0.04] border border-white/[0.08] rounded-tl-md'
                }`}>
                    {isUser ? (
                        <p className="text-[13px] text-text-primary leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                    ) : (
                        <>
                            <MiniMarkdown content={msg.content} />
                            {isStreaming && (
                                <span className="inline-block w-1.5 h-3.5 bg-accent-purple animate-pulse rounded-sm ml-0.5 align-middle" />
                            )}
                        </>
                    )}
                </div>
                {!isUser && !isStreaming && msg.content && (
                    <button
                        onClick={copy}
                        className="mt-1 opacity-0 group-hover:opacity-100 transition-opacity self-start flex items-center gap-1 text-[10px] text-text-muted hover:text-text-secondary px-1"
                    >
                        <Copy className="w-2.5 h-2.5" /> copy
                    </button>
                )}
            </div>
        </div>
    )
}

// ── Copilot Panel ─────────────────────────────────────────────────────────────

export default function CopilotPanel() {
    const [open, setOpen] = useState(false)
    const [messages, setMessages] = useState([])
    const [input, setInput] = useState('')
    const [sending, setSending] = useState(false)
    const [sessionID, setSessionID] = useState(null)
    const [suggestions, setSuggestions] = useState([])
    const [available, setAvailable] = useState(null)
    const [streamingContent, setStreamingContent] = useState('')
    const readerRef = useRef(null)
    const bottomRef = useRef(null)
    const inputRef = useRef(null)

    // Keyboard shortcut ⌘/ or Ctrl+/
    useEffect(() => {
        function handler(e) {
            if ((e.metaKey || e.ctrlKey) && e.key === '/') {
                e.preventDefault()
                setOpen(prev => !prev)
            }
            if (e.key === 'Escape' && open) setOpen(false)
        }
        window.addEventListener('keydown', handler)
        return () => window.removeEventListener('keydown', handler)
    }, [open])

    // Focus input when opening
    useEffect(() => {
        if (open && inputRef.current) {
            setTimeout(() => inputRef.current?.focus(), 80)
        }
    }, [open])

    // Scroll to bottom on new messages
    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [messages, streamingContent])

    // Load suggestions and check availability
    useEffect(() => {
        fetch(`${API_BASE}/copilot/available`).then(r => r.json()).then(d => setAvailable(d.available)).catch(() => setAvailable(false))
        fetch(`${API_BASE}/copilot/suggestions`).then(r => r.json()).then(d => setSuggestions(d.suggestions || [])).catch(() => {})
    }, [])

    const send = useCallback(async (text) => {
        const msg = (text || input).trim()
        if (!msg || sending) return

        setInput('')
        setSending(true)
        setStreamingContent('')
        setMessages(prev => [...prev, { role: 'user', content: msg }])

        try {
            const resp = await fetch(`${API_BASE}/copilot/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sessionID, message: msg }),
            })

            if (!resp.ok) throw new Error(`HTTP ${resp.status}`)

            const reader = resp.body.getReader()
            readerRef.current = reader
            const decoder = new TextDecoder()
            let buf = ''
            let accumulated = ''

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
                        if (ev.type === 'session' && ev.session_id) {
                            setSessionID(ev.session_id)
                        } else if (ev.type === 'delta') {
                            accumulated += ev.text
                            setStreamingContent(accumulated)
                        } else if (ev.type === 'done') {
                            setMessages(prev => [...prev, { role: 'assistant', content: accumulated }])
                            setStreamingContent('')
                            setSending(false)
                        } else if (ev.type === 'error') {
                            setMessages(prev => [...prev, { role: 'assistant', content: `⚠️ ${ev.error}` }])
                            setStreamingContent('')
                            setSending(false)
                        }
                    } catch { /* malformed SSE */ }
                }
            }
        } catch (err) {
            if (err.name !== 'AbortError') {
                setMessages(prev => [...prev, { role: 'assistant', content: `⚠️ ${err.message}` }])
            }
            setStreamingContent('')
            setSending(false)
        }
    }, [input, sending, sessionID])

    function clearConversation() {
        if (sessionID) {
            fetch(`${API_BASE}/copilot/sessions/${sessionID}`, { method: 'DELETE' }).catch(() => {})
        }
        setMessages([])
        setStreamingContent('')
        setSessionID(null)
        setSending(false)
        readerRef.current?.cancel()
    }

    function handleKeyDown(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault()
            send()
        }
    }

    const allMessages = [...messages]
    if (streamingContent) {
        allMessages.push({ role: 'assistant', content: streamingContent, _streaming: true })
    }

    return (
        <>
            {/* Floating trigger button */}
            <AnimatePresence>
                {!open && (
                    <motion.button
                        key="trigger"
                        initial={{ scale: 0, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        exit={{ scale: 0, opacity: 0 }}
                        transition={{ type: 'spring', stiffness: 400, damping: 25 }}
                        type="button"
                        onClick={() => setOpen(true)}
                        className="fixed bottom-6 right-6 z-40 w-13 h-13 rounded-2xl flex items-center justify-center shadow-[0_8px_32px_rgba(0,0,0,0.5),0_0_0_1px_rgba(255,255,255,0.1),inset_0_1px_0_rgba(255,255,255,0.15)] bg-gradient-to-br from-accent-purple/40 to-accent-cyan/30 backdrop-blur-xl border border-white/15 hover:shadow-[0_8px_32px_rgba(139,92,246,0.35)] transition-shadow group"
                        title="AI Security Copilot (⌘/)"
                        style={{ width: 52, height: 52 }}
                    >
                        <Bot className="w-5 h-5 text-white drop-shadow-[0_0_8px_rgba(139,92,246,0.8)]" />
                        <span className="absolute -top-1.5 -right-1.5 w-3.5 h-3.5 rounded-full bg-accent-cyan border-2 border-[#0f1117] animate-pulse" />
                    </motion.button>
                )}
            </AnimatePresence>

            {/* Panel */}
            <AnimatePresence>
                {open && (
                    <>
                        {/* Backdrop (mobile) */}
                        <motion.div
                            key="backdrop"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm lg:hidden"
                            onClick={() => setOpen(false)}
                        />

                        {/* Panel itself */}
                        <motion.div
                            key="panel"
                            initial={{ opacity: 0, x: 40, scale: 0.96 }}
                            animate={{ opacity: 1, x: 0, scale: 1 }}
                            exit={{ opacity: 0, x: 40, scale: 0.96 }}
                            transition={{ type: 'spring', stiffness: 380, damping: 32 }}
                            className="fixed bottom-4 right-4 z-50 flex flex-col rounded-2xl border border-white/[0.12] bg-[#0d1117]/95 backdrop-blur-2xl shadow-[0_24px_64px_rgba(0,0,0,0.7),0_0_0_1px_rgba(255,255,255,0.06),inset_0_1px_0_rgba(255,255,255,0.08)]"
                            style={{ width: 400, height: 600 }}
                        >
                            {/* Header */}
                            <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.08] flex-shrink-0">
                                <div className="flex items-center gap-2.5">
                                    <div className="w-7 h-7 rounded-xl bg-gradient-to-br from-accent-purple/30 to-accent-cyan/20 border border-white/15 flex items-center justify-center">
                                        <Bot className="w-3.5 h-3.5 text-white" />
                                    </div>
                                    <div>
                                        <div className="text-[13px] font-semibold text-text-primary leading-none">Security Copilot</div>
                                        <div className="text-[10px] text-text-muted mt-0.5 flex items-center gap-1">
                                            <span className={`w-1.5 h-1.5 rounded-full ${available ? 'bg-accent-green' : 'bg-yellow-400'}`} />
                                            {available === false ? 'API key not set' : 'claude-sonnet-4-6'}
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-1">
                                    {messages.length > 0 && (
                                        <button
                                            onClick={clearConversation}
                                            className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.05] transition-colors"
                                            title="Clear conversation"
                                        >
                                            <RefreshCw className="w-3.5 h-3.5" />
                                        </button>
                                    )}
                                    <button
                                        onClick={() => setOpen(false)}
                                        className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.05] transition-colors"
                                    >
                                        <ChevronDown className="w-4 h-4" />
                                    </button>
                                    <button
                                        onClick={() => setOpen(false)}
                                        className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[0.05] transition-colors"
                                    >
                                        <X className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>

                            {/* Messages area */}
                            <div className="flex-1 overflow-y-auto px-4 py-4 space-y-4 min-h-0">
                                {allMessages.length === 0 ? (
                                    /* Empty state with suggestions */
                                    <div className="flex flex-col items-center pt-6 gap-4">
                                        <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-accent-purple/25 to-accent-cyan/15 border border-white/10 flex items-center justify-center">
                                            <Sparkles className="w-5 h-5 text-accent-purple" />
                                        </div>
                                        <div className="text-center">
                                            <p className="text-sm font-medium text-text-secondary mb-1">AI Security Analyst</p>
                                            <p className="text-xs text-text-muted max-w-[260px] leading-relaxed">
                                                Ask about findings, get remediation guidance, or explore attack chains — I have full context of your scan data.
                                            </p>
                                        </div>
                                        {available === false && (
                                            <div className="w-full rounded-xl border border-yellow-400/25 bg-yellow-400/10 px-3 py-2 flex items-start gap-2">
                                                <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 mt-0.5 flex-shrink-0" />
                                                <p className="text-[11px] text-yellow-300">Set <code className="font-mono">ANTHROPIC_API_KEY</code> to enable AI responses.</p>
                                            </div>
                                        )}
                                        {suggestions.length > 0 && (
                                            <div className="w-full space-y-1.5">
                                                <p className="text-[10px] font-mono uppercase tracking-widest text-text-muted px-0.5">Suggested prompts</p>
                                                {suggestions.slice(0, 4).map((s, i) => (
                                                    <button
                                                        key={i}
                                                        type="button"
                                                        onClick={() => send(s)}
                                                        disabled={sending}
                                                        className="w-full text-left text-[12px] text-text-muted px-3 py-2 rounded-xl border border-white/[0.07] bg-white/[0.02] hover:bg-white/[0.05] hover:text-text-secondary hover:border-white/[0.12] transition-all disabled:opacity-50"
                                                    >
                                                        {s}
                                                    </button>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    allMessages.map((msg, i) => (
                                        <MessageBubble
                                            key={i}
                                            msg={msg}
                                            isStreaming={!!msg._streaming}
                                        />
                                    ))
                                )}
                                <div ref={bottomRef} />
                            </div>

                            {/* Input area */}
                            <div className="flex-shrink-0 border-t border-white/[0.08] p-3">
                                <div className="flex items-end gap-2 bg-white/[0.04] border border-white/[0.10] rounded-xl px-3 py-2.5 focus-within:border-accent-purple/40 transition-colors">
                                    <textarea
                                        ref={inputRef}
                                        rows={1}
                                        value={input}
                                        onChange={e => {
                                            setInput(e.target.value)
                                            e.target.style.height = 'auto'
                                            e.target.style.height = Math.min(e.target.scrollHeight, 96) + 'px'
                                        }}
                                        onKeyDown={handleKeyDown}
                                        placeholder={available === false ? "Set ANTHROPIC_API_KEY first…" : "Ask about findings, risks, or remediations…"}
                                        disabled={sending}
                                        className="flex-1 bg-transparent text-[13px] text-text-primary placeholder:text-text-muted outline-none resize-none leading-relaxed disabled:opacity-50"
                                        style={{ minHeight: 20, maxHeight: 96 }}
                                    />
                                    <button
                                        type="button"
                                        onClick={() => send()}
                                        disabled={!input.trim() || sending || available === false}
                                        className="flex-shrink-0 w-7 h-7 rounded-lg flex items-center justify-center bg-accent-purple/70 border border-accent-purple/40 text-white hover:bg-accent-purple/90 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                                    >
                                        {sending
                                            ? <div className="w-3 h-3 border border-white/40 border-t-white rounded-full animate-spin" />
                                            : <Send className="w-3 h-3" />
                                        }
                                    </button>
                                </div>
                                <p className="text-[9px] text-text-muted text-center mt-1.5 opacity-60">
                                    ⌘/ to toggle · Enter to send · Shift+Enter for newline
                                </p>
                            </div>
                        </motion.div>
                    </>
                )}
            </AnimatePresence>
        </>
    )
}
