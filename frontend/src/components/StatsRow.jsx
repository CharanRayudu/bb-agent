import React from 'react'
import { motion } from 'framer-motion'
import { Activity, AlertTriangle, CheckCircle, Crosshair, Cpu, Shield } from 'lucide-react'

function StatCard({ icon: Icon, label, value, accent, subvalue, delay }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay, duration: 0.3, ease: [0.2, 0.8, 0.2, 1] }}
            whileHover={{ y: -2 }}
            className="lg-surface lg-hover group relative p-4"
        >
            {/* colored halo behind icon */}
            <div
                className="pointer-events-none absolute -top-10 -left-10 w-32 h-32 rounded-full opacity-60 blur-3xl transition-opacity duration-500 group-hover:opacity-80"
                style={{ background: accent.halo }}
            />

            <div className="relative z-10 flex items-center gap-3">
                <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 border backdrop-blur-md shadow-[inset_0_1px_0_rgba(255,255,255,0.12)]"
                    style={{
                        background: accent.bg,
                        borderColor: accent.border,
                        boxShadow: `inset 0 1px 0 rgba(255,255,255,0.12), 0 0 16px ${accent.glow}`,
                    }}
                >
                    <Icon className="w-4.5 h-4.5" style={{ color: accent.icon }} />
                </div>

                <div className="min-w-0 flex-1">
                    <div
                        className="text-[22px] font-bold font-mono leading-none tracking-tight"
                        style={{ color: accent.text }}
                    >
                        {value}
                    </div>
                    <div className="text-[11px] text-text-secondary font-medium truncate mt-1">
                        {label}
                    </div>
                    {subvalue && (
                        <div className="text-[10px] text-text-muted font-mono mt-0.5">{subvalue}</div>
                    )}
                </div>
            </div>
        </motion.div>
    )
}

export default function StatsRow({ flows = [], findings = [] }) {
    const active = flows.filter(f => f.status === 'running' || f.status === 'active').length
    const completed = flows.filter(f => f.status === 'completed').length
    const critical = findings.filter(f => f.severity === 'critical').length
    const high = findings.filter(f => f.severity === 'high').length

    const targets = new Set(flows.map(f => {
        try { return new URL(f.target || f.name || '').hostname } catch { return f.target }
    })).size

    const coverage = completed > 0 ? Math.min(99, Math.round((completed / Math.max(flows.length, 1)) * 100)) : 0

    const neutral = {
        bg:     'rgba(255,255,255,0.04)',
        border: 'rgba(255,255,255,0.10)',
        halo:   'radial-gradient(circle, rgba(255,255,255,0.04), transparent 65%)',
        glow:   'rgba(255,255,255,0.06)',
        icon:   '#93a0bf',
        text:   '#cbd5e1',
    }
    const cyan = {
        bg:     'rgba(34,211,238,0.12)',
        border: 'rgba(34,211,238,0.35)',
        halo:   'radial-gradient(circle, rgba(34,211,238,0.35), transparent 65%)',
        glow:   'rgba(34,211,238,0.25)',
        icon:   '#67e8f9',
        text:   '#cffafe',
    }
    const red = {
        bg:     'rgba(239,68,68,0.12)',
        border: 'rgba(239,68,68,0.35)',
        halo:   'radial-gradient(circle, rgba(239,68,68,0.35), transparent 65%)',
        glow:   'rgba(239,68,68,0.25)',
        icon:   '#fca5a5',
        text:   '#fecaca',
    }
    const orange = {
        bg:     'rgba(249,115,22,0.12)',
        border: 'rgba(249,115,22,0.35)',
        halo:   'radial-gradient(circle, rgba(249,115,22,0.30), transparent 65%)',
        glow:   'rgba(249,115,22,0.25)',
        icon:   '#fdba74',
        text:   '#fed7aa',
    }
    const emerald = {
        bg:     'rgba(16,185,129,0.12)',
        border: 'rgba(16,185,129,0.35)',
        halo:   'radial-gradient(circle, rgba(16,185,129,0.30), transparent 65%)',
        glow:   'rgba(16,185,129,0.22)',
        icon:   '#6ee7b7',
        text:   '#a7f3d0',
    }
    const purple = {
        bg:     'rgba(167,139,250,0.14)',
        border: 'rgba(167,139,250,0.35)',
        halo:   'radial-gradient(circle, rgba(167,139,250,0.32), transparent 65%)',
        glow:   'rgba(167,139,250,0.22)',
        icon:   '#c4b5fd',
        text:   '#ddd6fe',
    }
    const blue = {
        bg:     'rgba(59,130,246,0.12)',
        border: 'rgba(59,130,246,0.35)',
        halo:   'radial-gradient(circle, rgba(59,130,246,0.30), transparent 65%)',
        glow:   'rgba(59,130,246,0.22)',
        icon:   '#93c5fd',
        text:   '#bfdbfe',
    }

    const stats = [
        {
            icon: Activity,
            label: 'Active Scans',
            value: active,
            accent: active > 0 ? cyan : neutral,
            subvalue: `${flows.length} total`,
            delay: 0,
        },
        {
            icon: AlertTriangle,
            label: 'Critical Findings',
            value: critical,
            accent: critical > 0 ? red : neutral,
            subvalue: `${high} high`,
            delay: 0.04,
        },
        {
            icon: Shield,
            label: 'Total Findings',
            value: findings.length,
            accent: findings.length > 0 ? orange : neutral,
            subvalue: findings.length > 0 ? `across ${targets} target${targets !== 1 ? 's' : ''}` : 'none yet',
            delay: 0.08,
        },
        {
            icon: CheckCircle,
            label: 'Completed',
            value: completed,
            accent: emerald,
            subvalue: `${coverage}% coverage`,
            delay: 0.12,
        },
        {
            icon: Crosshair,
            label: 'Targets',
            value: targets,
            accent: purple,
            subvalue: 'unique hosts',
            delay: 0.16,
        },
        {
            icon: Cpu,
            label: 'Agents Active',
            value: active * 8,
            accent: active > 0 ? blue : neutral,
            subvalue: 'parallel specialists',
            delay: 0.2,
        },
    ]

    return (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
            {stats.map((s) => (
                <StatCard key={s.label} {...s} />
            ))}
        </div>
    )
}
