import React, { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, useLocation, useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { LayoutDashboard, Zap, Database, Settings } from 'lucide-react'
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
            className="fixed inset-0 z-[70] flex items-start justify-center pt-24 bg-black/50 backdrop-blur-sm"
            onClick={() => { setOpen(false); setQuery('') }}
        >
            <motion.div
                initial={{ opacity: 0, scale: 0.96, y: -8 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.96, y: -8 }}
                transition={{ duration: 0.15 }}
                className="w-full max-w-lg rounded-xl border border-[#1e2535] bg-[#111318] shadow-[0_24px_80px_rgba(0,0,0,0.8)] overflow-hidden"
                onClick={(e) => e.stopPropagation()}
            >
                <div className="flex items-center gap-3 border-b border-[#1e2535] px-4 py-3">
                    <svg className="w-4 h-4 text-[#4b5675]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <input
                        autoFocus
                        value={query}
                        onChange={(e) => { setQuery(e.target.value); setActiveIndex(0) }}
                        placeholder="Search commands..."
                        className="flex-1 bg-transparent text-sm text-[#e2e8f0] placeholder:text-[#4b5675] outline-none"
                    />
                    <kbd className="text-[10px] text-[#4b5675] font-mono bg-[#161b24] border border-[#1e2535] rounded px-1.5 py-0.5">ESC</kbd>
                </div>
                <div className="max-h-64 overflow-y-auto py-1">
                    {filtered.length === 0 ? (
                        <div className="px-4 py-6 text-sm text-[#4b5675] text-center">No results found</div>
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
                                    className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-colors ${
                                        isActive
                                            ? 'bg-[#06b6d4]/10 text-[#06b6d4]'
                                            : 'text-[#e2e8f0] hover:bg-white/[0.03]'
                                    }`}
                                >
                                    {Icon && <Icon className="w-4 h-4 flex-shrink-0 opacity-70" />}
                                    <span>{opt.label}</span>
                                </button>
                            )
                        })
                    )}
                </div>
                <div className="border-t border-[#1e2535] px-4 py-2 flex items-center gap-4 text-[10px] text-[#4b5675] font-mono">
                    <span><kbd className="bg-[#161b24] border border-[#1e2535] rounded px-1">↑↓</kbd> navigate</span>
                    <span><kbd className="bg-[#161b24] border border-[#1e2535] rounded px-1">↵</kbd> select</span>
                    <span><kbd className="bg-[#161b24] border border-[#1e2535] rounded px-1">⌘K</kbd> toggle</span>
                </div>
            </motion.div>
        </div>
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
