import React, { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { Shield, LayoutDashboard, Zap, Activity } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import NewTask from './pages/NewTask'
import FlowDetail from './pages/FlowDetail'

function Navbar() {
    const location = useLocation()
    const onDashboard = location.pathname === '/'
    const onNew = location.pathname.startsWith('/new')
    const [scrolled, setScrolled] = useState(false)

    useEffect(() => {
        const onScroll = () => {
            setScrolled(window.scrollY > 8)
        }
        onScroll()
        window.addEventListener('scroll', onScroll)
        return () => window.removeEventListener('scroll', onScroll)
    }, [])

    return (
        <nav className="sticky top-0 z-50 w-full pointer-events-none">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-4">
                <div
                    className={`relative overflow-hidden rounded-3xl border backdrop-blur-2xl px-4 sm:px-6 h-14 flex items-center justify-between pointer-events-auto transition-all duration-300 ${
                        scrolled
                            ? 'bg-white/12 border-white/25 shadow-[0_12px_40px_rgba(0,0,0,0.9)]'
                            : 'bg-white/8 border-white/15 shadow-[0_18px_80px_rgba(15,23,42,0.95)]'
                    }`}
                >
                    {/* Glass light streak */}
                    <div className="pointer-events-none absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500">
                        <div className="absolute -inset-x-20 -top-10 h-20 bg-gradient-to-r from-white/40 via-white/5 to-transparent blur-2xl mix-blend-screen" />
                    </div>

                    {/* Brand */}
                    <Link to="/" className="flex items-center gap-3 group">
                        <div className="p-2 bg-white/5 rounded-xl border border-white/10 group-hover:bg-white/10 transition-colors duration-300">
                            <Shield className="w-6 h-6 text-accent-cyan" />
                        </div>
                        <div>
                            <div className="text-xl font-display font-bold text-text-primary tracking-tight">Mirage</div>
                            <div className="text-xs text-accent-cyan/80 font-mono tracking-widest uppercase">Agentic Security</div>
                        </div>
                    </Link>

                    {/* Navigation */}
                    <div className="flex items-center gap-4 sm:gap-6">
                        {/* Segmented control for desktop with sliding pill */}
                        <div className="hidden sm:flex items-center relative rounded-full bg-white/5 border border-white/10 p-0.5 overflow-hidden">
                            <div
                                className={`absolute inset-y-0 left-0 w-1/2 rounded-full bg-gradient-to-r from-accent-cyan to-accent-green shadow-[0_0_16px_rgba(0,212,255,0.45)] transition-transform duration-500 ease-out ${
                                    onNew ? 'translate-x-full' : 'translate-x-0'
                                }`}
                            />
                            <Link
                                to="/"
                                className={`relative z-10 flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-medium transition-colors duration-200 ${
                                    onDashboard ? 'text-primary-bg' : 'text-text-muted hover:text-text-primary'
                                }`}
                            >
                                <LayoutDashboard className="w-4 h-4" />
                                Dashboard
                            </Link>

                            <Link
                                to="/new"
                                className={`relative z-10 flex items-center gap-2 px-5 py-1.5 rounded-full text-xs font-medium transition-colors duration-200 ${
                                    onNew ? 'text-primary-bg' : 'text-text-muted hover:text-text-primary'
                                }`}
                            >
                                <Zap className="w-4 h-4" />
                                <span>Launch Scan</span>
                            </Link>
                        </div>

                        {/* Compact controls for small screens */}
                        <div className="flex sm:hidden items-center gap-2">
                            <Link
                                to="/"
                                className={`px-2 py-1 rounded-full text-xs font-medium transition-colors ${
                                    onDashboard ? 'text-accent-cyan bg-white/10' : 'text-text-muted hover:text-text-primary'
                                }`}
                            >
                                Dash
                            </Link>
                            <Link
                                to="/new"
                                className={`px-2 py-1 rounded-full text-xs font-medium transition-colors ${
                                    onNew ? 'text-accent-cyan bg-white/10' : 'text-text-muted hover:text-text-primary'
                                }`}
                            >
                                New
                            </Link>
                        </div>

                        <div className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[10px] font-mono uppercase tracking-[0.16em]">
                            <span className="relative flex h-2.5 w-2.5">
                                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-accent-green"></span>
                            </span>
                            <span className="text-accent-green">SYSTEM ONLINE</span>
                        </div>
                    </div>
                </div>
            </div>
        </nav>
    )
}

function CommandPalette() {
    const navigate = useNavigate()
    const [open, setOpen] = useState(false)
    const [query, setQuery] = useState('')
    const [activeIndex, setActiveIndex] = useState(0)

    useEffect(() => {
        function handler(e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault()
                setOpen((prev) => !prev)
                setActiveIndex(0)
            }
            if (!open) return
            if (e.key === 'ArrowDown') {
                e.preventDefault()
                setActiveIndex((prev) => (prev + 1) % options.length)
            }
            if (e.key === 'ArrowUp') {
                e.preventDefault()
                setActiveIndex((prev) => (prev - 1 + options.length) % options.length)
            }
            if (e.key === 'Enter') {
                e.preventDefault()
                const opt = options[activeIndex]
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
    }, [open, activeIndex])

    if (!open) return null

    const options = [
        { label: 'Go to Dashboard', action: () => navigate('/'), icon: LayoutDashboard },
        { label: 'Start New Scan', action: () => navigate('/new'), icon: Zap },
    ]

    const filtered = options.filter((opt) => opt.label.toLowerCase().includes(query.toLowerCase()))

    return (
        <div className="fixed inset-0 z-[70] flex items-start justify-center pt-24 bg-black/40 backdrop-blur-sm">
            <div className="w-full max-w-lg rounded-2xl border border-white/15 bg-white/10 backdrop-blur-2xl shadow-[0_24px_80px_rgba(15,23,42,0.95)] overflow-hidden">
                <div className="border-b border-white/10 px-4 py-3">
                    <input
                        autoFocus
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Jump to a screen… (Ctrl+K)"
                        className="w-full bg-transparent text-sm text-text-primary placeholder:text-text-muted/70 outline-none"
                    />
                </div>
                <div className="max-h-64 overflow-y-auto">
                    {filtered.length === 0 ? (
                        <div className="px-4 py-3 text-xs text-text-muted">No results.</div>
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
                                    className={`w-full flex items-center gap-3 px-4 py-2 text-sm transition-colors ${
                                        isActive ? 'bg-white/15 text-text-primary' : 'text-text-primary hover:bg-white/10'
                                    }`}
                                >
                                    {Icon && <Icon className="w-4 h-4 text-accent-cyan flex-shrink-0" />}
                                    <span>{opt.label}</span>
                                </button>
                            )
                        })
                    )}
                </div>
            </div>
        </div>
    )
}

function AppShell() {
    const location = useLocation()

    return (
        <div className="min-h-screen bg-primary-bg bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:60px_60px] animate-grid-move font-display text-text-primary">
            <Navbar />
            <CommandPalette />
            <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative">
                <AnimatePresence mode="wait">
                    <Routes location={location} key={location.pathname}>
                        <Route
                            path="/"
                            element={
                                <motion.div
                                    initial={{ opacity: 0, y: 8 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0, y: -8 }}
                                    transition={{ duration: 0.25, ease: 'easeOut' }}
                                >
                                    <Dashboard />
                                </motion.div>
                            }
                        />
                        <Route
                            path="/new"
                            element={
                                <motion.div
                                    initial={{ opacity: 0, y: 8 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0, y: -8 }}
                                    transition={{ duration: 0.25, ease: 'easeOut' }}
                                >
                                    <NewTask />
                                </motion.div>
                            }
                        />
                        <Route
                            path="/flow/:id"
                            element={
                                <motion.div
                                    initial={{ opacity: 0, y: 8 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0, y: -8 }}
                                    transition={{ duration: 0.25, ease: 'easeOut' }}
                                >
                                    <FlowDetail />
                                </motion.div>
                            }
                        />
                    </Routes>
                </AnimatePresence>
            </main>
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
