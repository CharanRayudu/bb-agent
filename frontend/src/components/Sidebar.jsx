import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, Plus, Network, Settings, Wifi, WifiOff } from 'lucide-react'

const NAV_ITEMS = [
    { label: 'Dashboard',      icon: LayoutDashboard, to: '/' },
    { label: 'New Scan',       icon: Plus,            to: '/new' },
    { label: 'Knowledge Graph',icon: Network,         to: '/graph' },
    { label: 'Settings',       icon: Settings,        to: '/settings' },
]

function NavItem({ item, isActive }) {
    const Icon = item.icon
    return (
        <Link
            to={item.to}
            className={[
                'relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150',
                isActive
                    ? 'bg-cyan-500/10 text-cyan-400'
                    : 'text-[#8b98b1] hover:bg-white/[0.04] hover:text-[#e2e8f0]',
            ].join(' ')}
        >
            {/* Active left border accent */}
            {isActive && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-cyan-400 rounded-r" />
            )}
            <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? 'text-cyan-400' : ''}`} />
            <span className="truncate">{item.label}</span>
        </Link>
    )
}

export default function Sidebar() {
    const location = useLocation()
    const [connected, setConnected] = useState(true)

    // Simple connectivity check — ping the API
    useEffect(() => {
        let cancelled = false
        async function check() {
            try {
                const res = await fetch('/api/flows', { signal: AbortSignal.timeout(3000) })
                if (!cancelled) setConnected(res.ok)
            } catch {
                if (!cancelled) setConnected(false)
            }
        }
        check()
        const id = setInterval(check, 15000)
        return () => { cancelled = true; clearInterval(id) }
    }, [])

    // Determine active route
    function isActive(to) {
        if (to === '/') return location.pathname === '/'
        return location.pathname.startsWith(to)
    }

    return (
        <aside className="sidebar select-none">
            {/* Logo */}
            <div className="flex items-center gap-3 px-4 py-5 border-b border-[#1e2535]">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/25 flex items-center justify-center flex-shrink-0">
                    <Shield className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="min-w-0">
                    <div className="text-[15px] font-semibold text-[#e2e8f0] tracking-tight leading-none">
                        Mirage
                    </div>
                    <div className="text-[10px] text-[#4b5675] font-mono tracking-widest uppercase mt-0.5">
                        Security
                    </div>
                </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
                <div className="text-[10px] font-semibold text-[#4b5675] uppercase tracking-wider px-3 mb-2">
                    Navigation
                </div>
                {NAV_ITEMS.map((item) => (
                    <NavItem key={item.to} item={item} isActive={isActive(item.to)} />
                ))}
            </nav>

            {/* Bottom status bar */}
            <div className="border-t border-[#1e2535] px-3 py-3 space-y-2">
                {/* Connection status */}
                <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.02]">
                    {connected ? (
                        <>
                            <span className="relative flex h-2 w-2 flex-shrink-0">
                                <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 animate-ping" />
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
                            </span>
                            <Wifi className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                            <span className="text-[11px] text-emerald-400 font-medium">Connected</span>
                        </>
                    ) : (
                        <>
                            <span className="w-2 h-2 rounded-full bg-red-400 flex-shrink-0" />
                            <WifiOff className="w-3 h-3 text-red-400 flex-shrink-0" />
                            <span className="text-[11px] text-red-400 font-medium">Offline</span>
                        </>
                    )}
                </div>

                {/* Version */}
                <div className="flex items-center justify-between px-3">
                    <span className="text-[10px] text-[#4b5675] font-mono">Mirage v2.0</span>
                    <span className="text-[10px] text-[#4b5675] font-mono">agentic</span>
                </div>
            </div>
        </aside>
    )
}
