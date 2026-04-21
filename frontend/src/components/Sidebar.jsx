import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, LayoutDashboard, Plus, Network, Settings, Wifi, WifiOff, Activity } from 'lucide-react'

const NAV_ITEMS = [
    { label: 'Dashboard',        icon: LayoutDashboard, to: '/',         hint: 'Overview' },
    { label: 'New Scan',         icon: Plus,            to: '/new',      hint: 'Launch' },
    { label: 'Knowledge Graph',  icon: Network,         to: '/graph',    hint: 'Graph' },
    { label: 'Settings',         icon: Settings,        to: '/settings', hint: 'Config' },
]

function NavItem({ item, isActive }) {
    const Icon = item.icon
    return (
        <Link
            to={item.to}
            className={[
                'group relative flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-colors duration-200',
                isActive
                    ? 'text-white'
                    : 'text-text-secondary hover:text-text-primary',
            ].join(' ')}
        >
            {isActive && (
                <motion.span
                    layoutId="sidebar-active"
                    transition={{ type: 'spring', stiffness: 420, damping: 32 }}
                    className="absolute inset-0 rounded-xl bg-gradient-to-br from-white/[0.10] to-white/[0.02] border border-white/[0.14] shadow-[inset_0_1px_0_rgba(255,255,255,0.14),inset_0_-1px_0_rgba(0,0,0,0.35),0_6px_20px_rgba(34,211,238,0.10)]"
                />
            )}
            <span
                className={`relative z-10 flex items-center justify-center w-7 h-7 rounded-lg transition-colors ${
                    isActive
                        ? 'bg-accent-cyan/20 text-accent-cyan shadow-[0_0_14px_rgba(34,211,238,0.35)]'
                        : 'bg-white/[0.04] text-text-muted group-hover:bg-white/[0.08] group-hover:text-text-primary'
                }`}
            >
                <Icon className="w-4 h-4" />
            </span>
            <span className="relative z-10 truncate">{item.label}</span>
        </Link>
    )
}

export default function Sidebar() {
    const location = useLocation()
    const [connected, setConnected] = useState(true)
    const [latency, setLatency] = useState(null)

    useEffect(() => {
        let cancelled = false
        async function check() {
            const t = performance.now()
            try {
                const res = await fetch('/api/flows', { signal: AbortSignal.timeout(3000) })
                if (!cancelled) {
                    setConnected(res.ok)
                    setLatency(Math.round(performance.now() - t))
                }
            } catch {
                if (!cancelled) {
                    setConnected(false)
                    setLatency(null)
                }
            }
        }
        check()
        const id = setInterval(check, 15000)
        return () => { cancelled = true; clearInterval(id) }
    }, [])

    function isActive(to) {
        if (to === '/') return location.pathname === '/'
        return location.pathname.startsWith(to)
    }

    return (
        <aside className="sidebar select-none">
            {/* Logo / brand */}
            <div className="relative z-10 flex items-center gap-3 px-4 pt-5 pb-4 border-b border-white/[0.08]">
                <div className="relative">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-accent-cyan/30 via-accent-purple/20 to-accent-green/20 border border-white/20 flex items-center justify-center flex-shrink-0 shadow-[inset_0_1px_0_rgba(255,255,255,0.2),0_4px_16px_rgba(34,211,238,0.25)]">
                        <Shield className="w-5 h-5 text-white drop-shadow-[0_0_6px_rgba(34,211,238,0.5)]" />
                    </div>
                    <span className="absolute -inset-1 rounded-xl bg-accent-cyan/20 blur-md -z-10 animate-pulse-slow" />
                </div>
                <div className="min-w-0">
                    <div className="text-[16px] font-semibold lg-gradient-text-cyan tracking-tight leading-none">
                        Mirage
                    </div>
                    <div className="text-[9px] text-text-muted font-mono tracking-[0.25em] uppercase mt-1">
                        Autonomous · Pentest
                    </div>
                </div>
            </div>

            {/* Navigation */}
            <nav className="relative z-10 flex-1 px-2.5 py-4 space-y-0.5 overflow-y-auto">
                <div className="text-[9px] font-semibold text-text-muted uppercase tracking-[0.22em] px-3 mb-2 flex items-center gap-2">
                    <span className="h-px flex-1 bg-gradient-to-r from-transparent via-white/[0.08] to-transparent" />
                    Navigate
                    <span className="h-px flex-1 bg-gradient-to-r from-transparent via-white/[0.08] to-transparent" />
                </div>
                {NAV_ITEMS.map((item) => (
                    <NavItem key={item.to} item={item} isActive={isActive(item.to)} />
                ))}
            </nav>

            {/* Bottom status panel */}
            <div className="relative z-10 border-t border-white/[0.08] px-3 py-3 space-y-2">
                {/* Connection chip */}
                <div className="flex items-center gap-2.5 px-3 py-2 rounded-xl bg-white/[0.03] border border-white/[0.06] backdrop-blur-md">
                    {connected ? (
                        <>
                            <span className="relative flex h-2 w-2 flex-shrink-0">
                                <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-70 animate-ping" />
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.7)]" />
                            </span>
                            <Wifi className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                            <span className="text-[11px] text-emerald-300 font-medium flex-1">Online</span>
                            {latency !== null && (
                                <span className="text-[10px] text-text-muted font-mono">{latency}ms</span>
                            )}
                        </>
                    ) : (
                        <>
                            <span className="w-2 h-2 rounded-full bg-red-400 flex-shrink-0 shadow-[0_0_8px_rgba(239,68,68,0.6)]" />
                            <WifiOff className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                            <span className="text-[11px] text-red-300 font-medium">Offline</span>
                        </>
                    )}
                </div>

                {/* Version / mode */}
                <div className="flex items-center justify-between px-3 pt-0.5">
                    <div className="flex items-center gap-1.5">
                        <Activity className="w-3 h-3 text-accent-cyan/60" />
                        <span className="text-[10px] text-text-muted font-mono">v2.0</span>
                    </div>
                    <span className="text-[10px] text-text-muted font-mono uppercase tracking-widest">agentic</span>
                </div>
            </div>
        </aside>
    )
}
