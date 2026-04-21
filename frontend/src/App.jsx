import React, { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, useLocation, useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { LayoutDashboard, Zap, Database, Settings, Search, Command } from 'lucide-react'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import NewTask from './pages/NewTask'
import FlowDetail from './pages/FlowDetail'
import KnowledgeGraph from './pages/KnowledgeGraph'
import SettingsPage from './pages/Settings'

// ============================================================
// Command Palette
// ============================================================
function CommandPalette() {
    const navigate = useNavigate()
    const [open, setOpen] = useState(false)
    const [query, setQuery] = useState('')
    const [activeIndex, setActiveIndex] = useState(0)

    const options = [
        { label: 'Go to Dashboard', action: () => navigate('/'), icon: LayoutDashboard },
        { label: 'Start New Scan', action: () => navigate('/new'), icon: Zap },
        { label: 'Knowledge Graph', action: () => navigate('/graph'), icon: Database },
        { label: 'Settings', action: () => navigate('/settings'), icon: Settings },
    ]

    const filtered = options.filter((opt) =>
        opt.label.toLowerCase().includes(query.toLowerCase())
    )

    useEffect(() => {
        function handler(e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault()
                setOpen((prev) => !prev)
                setActiveIndex(0)
                setQuery('')
            }
            if (!open) return
            if (e.key === 'Escape') {
                setOpen(false)
                setQuery('')
            }
            if (e.key === 'ArrowDown') {
                e.preventDefault()
                setActiveIndex((prev) => (prev + 1) % filtered.length)
            }
            if (e.key === 'ArrowUp') {
                e.preventDefault()
                setActiveIndex((prev) => (prev - 1 + filtered.length) % filtered.length)
            }
            if (e.key === 'Enter') {
                e.preventDefault()
                const opt = filtered[activeIndex]
                if (opt) {
                    opt.action()
                    setOpen(false)
                    setQuery('')
                }
            }
        }
        window.addEventListener('keydown', handler)
        return () => window.removeEventListener('keydown', handler)
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open, activeIndex, filtered])

    if (!open) return null

    return (
        <div
            className="fixed inset-0 z-[70] flex items-start justify-center pt-24 bg-black/40 backdrop-blur-md"
            onClick={() => { setOpen(false); setQuery('') }}
        >
            <motion.div
                initial={{ opacity: 0, scale: 0.96, y: -8 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.96, y: -8 }}
                transition={{ duration: 0.18, ease: [0.2, 0.8, 0.2, 1] }}
                className="lg-surface-hero w-full max-w-xl"
                onClick={(e) => e.stopPropagation()}
            >
                <div className="relative z-10 flex items-center gap-3 px-5 py-4 border-b border-white/10">
                    <Search className="w-4 h-4 text-text-muted" />
                    <input
                        autoFocus
                        value={query}
                        onChange={(e) => { setQuery(e.target.value); setActiveIndex(0) }}
                        placeholder="Search commands…"
                        className="flex-1 bg-transparent text-[15px] text-text-primary placeholder:text-text-muted outline-none"
                    />
                    <kbd className="text-[10px] text-text-muted font-mono bg-white/[0.06] border border-white/10 rounded-md px-1.5 py-0.5">ESC</kbd>
                </div>
                <div className="relative z-10 max-h-72 overflow-y-auto py-2 px-2">
                    {filtered.length === 0 ? (
                        <div className="px-4 py-10 text-sm text-text-muted text-center">No results found</div>
                    ) : (
                        filtered.map((opt, idx) => {
                            const Icon = opt.icon
                            const isActive = idx === activeIndex
                            return (
                                <button
                                    key={opt.label}
                                    type="button"
                                    onClick={() => {
                                        opt.action()
                                        setOpen(false)
                                        setQuery('')
                                    }}
                                    onMouseEnter={() => setActiveIndex(idx)}
                                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all ${
                                        isActive
                                            ? 'bg-white/[0.08] text-text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]'
                                            : 'text-text-secondary hover:bg-white/[0.04] hover:text-text-primary'
                                    }`}
                                >
                                    <span className={`w-7 h-7 rounded-lg flex items-center justify-center ${isActive ? 'bg-accent-cyan/15 text-accent-cyan' : 'bg-white/[0.04] text-text-muted'}`}>
                                        {Icon && <Icon className="w-4 h-4" />}
                                    </span>
                                    <span className="flex-1 text-left">{opt.label}</span>
                                    {isActive && <span className="text-[10px] font-mono text-text-muted">↵</span>}
                                </button>
                            )
                        })
                    )}
                </div>
                <div className="relative z-10 border-t border-white/10 px-5 py-2.5 flex items-center gap-4 text-[10px] text-text-muted font-mono">
                    <span className="flex items-center gap-1.5"><kbd className="bg-white/[0.06] border border-white/10 rounded px-1.5 py-0.5">↑↓</kbd> navigate</span>
                    <span className="flex items-center gap-1.5"><kbd className="bg-white/[0.06] border border-white/10 rounded px-1.5 py-0.5">↵</kbd> select</span>
                    <span className="flex items-center gap-1.5 ml-auto"><kbd className="bg-white/[0.06] border border-white/10 rounded px-1.5 py-0.5">⌘K</kbd> toggle</span>
                </div>
            </motion.div>
        </div>
    )
}

// ============================================================
// Floating Topbar — Liquid glass, shows command trigger
// ============================================================
function Topbar() {
    const [scrolled, setScrolled] = useState(false)
    useEffect(() => {
        const onScroll = () => setScrolled(window.scrollY > 12)
        onScroll()
        window.addEventListener('scroll', onScroll, { passive: true })
        return () => window.removeEventListener('scroll', onScroll)
    }, [])

    function openPalette() {
        const ev = new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, metaKey: true, bubbles: true })
        window.dispatchEvent(ev)
    }

    return (
        <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25, ease: [0.2, 0.8, 0.2, 1] }}
            className="pointer-events-none fixed top-4 right-4 z-30 flex items-center gap-2"
        >
            <button
                type="button"
                onClick={openPalette}
                className={`pointer-events-auto lg-pill group transition-all ${scrolled ? 'shadow-[0_10px_30px_rgba(0,0,0,0.35)]' : ''}`}
                title="Open command palette (⌘K)"
            >
                <Search className="w-3.5 h-3.5" />
                <span className="hidden sm:inline text-[12px] font-medium">Search commands</span>
                <span className="hidden sm:flex items-center gap-1 ml-2 pl-2 border-l border-white/10">
                    <Command className="w-3 h-3 opacity-60" />
                    <span className="text-[10px] font-mono">K</span>
                </span>
            </button>
        </motion.div>
    )
}

// ============================================================
// Page transition wrapper (respects prefers-reduced-motion)
// ============================================================
function PageWrapper({ children }) {
    const reducedMotion = typeof window !== 'undefined' &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches

    const variants = reducedMotion
        ? { initial: {}, animate: {}, exit: {} }
        : { initial: { opacity: 0, y: 6 }, animate: { opacity: 1, y: 0 }, exit: { opacity: 0, y: -6 } }
    const transition = reducedMotion ? { duration: 0 } : { duration: 0.2, ease: 'easeOut' }

    return (
        <motion.div
            variants={variants}
            initial="initial"
            animate="animate"
            exit="exit"
            transition={transition}
        >
            {children}
        </motion.div>
    )
}

// ============================================================
// App Shell — sidebar + main area
// ============================================================
function AppShell() {
    const location = useLocation()

    return (
        <div className="app-layout font-display text-text-primary">
            <Sidebar />
            <Topbar />
            <main className="main-area min-h-screen">
                <AnimatePresence mode="wait">
                    <Routes location={location} key={location.pathname}>
                        <Route
                            path="/"
                            element={
                                <PageWrapper><Dashboard /></PageWrapper>
                            }
                        />
                        <Route
                            path="/new"
                            element={
                                <PageWrapper><NewTask /></PageWrapper>
                            }
                        />
                        <Route
                            path="/flow/:id"
                            element={
                                <PageWrapper><FlowDetail /></PageWrapper>
                            }
                        />
                        {/* Legacy route */}
                        <Route
                            path="/flows/:id"
                            element={
                                <PageWrapper><FlowDetail /></PageWrapper>
                            }
                        />
                        <Route
                            path="/graph"
                            element={
                                <PageWrapper><KnowledgeGraph /></PageWrapper>
                            }
                        />
                        {/* Legacy route */}
                        <Route
                            path="/knowledge"
                            element={
                                <PageWrapper><KnowledgeGraph /></PageWrapper>
                            }
                        />
                        <Route
                            path="/settings"
                            element={
                                <PageWrapper><SettingsPage /></PageWrapper>
                            }
                        />
                    </Routes>
                </AnimatePresence>
            </main>
            <CommandPalette />
        </div>
    )
}

function App() {
    return (
        <BrowserRouter>
            <AppShell />
        </BrowserRouter>
    )
}

export default App
