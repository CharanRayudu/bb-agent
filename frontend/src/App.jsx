import React from 'react'
import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, Zap, Activity } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import NewTask from './pages/NewTask'
import FlowDetail from './pages/FlowDetail'

function Navbar() {
    const location = useLocation()

    return (
        <nav className="sticky top-0 z-50 w-full backdrop-blur-md bg-[#0a0e1a]/80 border-b border-accent-cyan/20 shadow-glow">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex items-center justify-between h-16">
                    {/* Brand */}
                    <Link to="/" className="flex items-center gap-3 group">
                        <div className="p-2 bg-accent-cyan/10 rounded-xl group-hover:bg-accent-cyan/20 transition-colors duration-300">
                            <Shield className="w-6 h-6 text-accent-cyan animate-pulse-slow" />
                        </div>
                        <div>
                            <div className="text-xl font-display font-bold text-text-primary tracking-tight">Mirage</div>
                            <div className="text-xs text-accent-cyan/80 font-mono tracking-widest uppercase">Agentic Security</div>
                        </div>
                    </Link>

                    {/* Navigation */}
                    <div className="flex items-center gap-6">
                        <Link
                            to="/"
                            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300 ${location.pathname === '/'
                                    ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/30 shadow-[0_0_15px_rgba(0,212,255,0.15)]'
                                    : 'text-text-muted hover:text-text-primary hover:bg-[#111827]'
                                }`}
                        >
                            <LayoutDashboard className="w-4 h-4" />
                            Dashboard
                        </Link>

                        <Link
                            to="/new"
                            className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-medium bg-gradient-to-r from-accent-cyan to-accent-green text-primary-bg hover:opacity-90 hover:shadow-glow transition-all duration-300 transform hover:-translate-y-0.5"
                        >
                            <Zap className="w-4 h-4" />
                            Launch Scan
                        </Link>

                        <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#111827] border border-accent-green/20">
                            <span className="relative flex h-2.5 w-2.5">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent-green opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-accent-green"></span>
                            </span>
                            <span className="text-xs font-mono text-accent-green tracking-wide">SYSTEM ONLINE</span>
                        </div>
                    </div>
                </div>
            </div>
        </nav>
    )
}

function App() {
    return (
        <BrowserRouter>
            <div className="min-h-screen bg-primary-bg bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:60px_60px] animate-grid-move font-display text-text-primary">
                <Navbar />
                <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative">
                    <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/new" element={<NewTask />} />
                        <Route path="/flow/:id" element={<FlowDetail />} />
                    </Routes>
                </main>
            </div>
        </BrowserRouter>
    )
}

export default App
