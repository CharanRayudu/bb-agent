import React from 'react'
import { motion } from 'framer-motion'
import { Activity, AlertTriangle, CheckCircle, Crosshair, Cpu, Shield } from 'lucide-react'

function StatCard({ icon: Icon, label, value, color, subvalue, delay }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay, duration: 0.25 }}
            className="flex items-center gap-3 px-4 py-3.5 rounded-xl border border-[#1e2535] bg-[#111318] hover:border-[#2d3a52] transition-colors"
        >
            <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${color.bg}`}>
                <Icon className={`w-4.5 h-4.5 ${color.text}`} />
            </div>
            <div className="min-w-0">
                <div className={`text-xl font-bold font-mono leading-tight ${color.text}`}>{value}</div>
                <div className="text-[11px] text-[#4b5675] font-medium truncate">{label}</div>
                {subvalue && (
                    <div className="text-[10px] text-[#4b5675]/60 font-mono">{subvalue}</div>
                )}
            </div>
        </motion.div>
    )
}

export default function StatsRow({ flows = [], findings = [] }) {
    const active = flows.filter(f => f.status === 'running' || f.status === 'active').length
    const completed = flows.filter(f => f.status === 'completed').length
    const critical = findings.filter(f => f.severity === 'critical').length
    const high = findings.filter(f => f.severity === 'high').length

    // Unique targets scanned
    const targets = new Set(flows.map(f => {
        try { return new URL(f.target || f.name || '').hostname } catch { return f.target }
    })).size

    // Coverage score (rough estimate)
    const coverage = completed > 0 ? Math.min(99, Math.round((completed / Math.max(flows.length, 1)) * 100)) : 0

    const stats = [
        {
            icon: Activity,
            label: 'Active Scans',
            value: active,
            color: active > 0
                ? { bg: 'bg-cyan-500/10', text: 'text-cyan-400' }
                : { bg: 'bg-[#161b24]', text: 'text-[#8b98b1]' },
            subvalue: `${flows.length} total`,
            delay: 0,
        },
        {
            icon: AlertTriangle,
            label: 'Critical Findings',
            value: critical,
            color: critical > 0
                ? { bg: 'bg-red-500/10', text: 'text-red-400' }
                : { bg: 'bg-[#161b24]', text: 'text-[#8b98b1]' },
            subvalue: `${high} high`,
            delay: 0.04,
        },
        {
            icon: Shield,
            label: 'Total Findings',
            value: findings.length,
            color: findings.length > 0
                ? { bg: 'bg-orange-500/10', text: 'text-orange-400' }
                : { bg: 'bg-[#161b24]', text: 'text-[#8b98b1]' },
            subvalue: findings.length > 0 ? `across ${targets} target${targets !== 1 ? 's' : ''}` : 'none yet',
            delay: 0.08,
        },
        {
            icon: CheckCircle,
            label: 'Completed',
            value: completed,
            color: { bg: 'bg-emerald-500/10', text: 'text-emerald-400' },
            subvalue: `${coverage}% coverage`,
            delay: 0.12,
        },
        {
            icon: Crosshair,
            label: 'Targets',
            value: targets,
            color: { bg: 'bg-purple-500/10', text: 'text-purple-400' },
            subvalue: 'unique hosts',
            delay: 0.16,
        },
        {
            icon: Cpu,
            label: 'Agents Active',
            value: active * 8, // rough estimate of parallel specialists
            color: active > 0
                ? { bg: 'bg-blue-500/10', text: 'text-blue-400' }
                : { bg: 'bg-[#161b24]', text: 'text-[#8b98b1]' },
            subvalue: 'parallel specialists',
            delay: 0.2,
        },
    ]

    return (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
            {stats.map((s) => (
                <StatCard key={s.label} {...s} />
            ))}
        </div>
    )
}
