import React from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, Home, Search, ArrowLeft } from 'lucide-react'

export default function NotFound() {
    return (
        <div className="min-h-screen flex items-center justify-center px-6 py-20">
            {/* Ambient glow blobs */}
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-accent-cyan/[0.04] rounded-full blur-[120px]" />
                <div className="absolute top-2/3 left-1/3 w-[400px] h-[400px] bg-accent-purple/[0.04] rounded-full blur-[100px]" />
            </div>

            <motion.div
                initial={{ opacity: 0, y: 24 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, ease: [0.2, 0.8, 0.2, 1] }}
                className="relative z-10 flex flex-col items-center text-center max-w-lg"
            >
                {/* Glassy icon */}
                <div className="relative mb-8">
                    <div className="w-24 h-24 rounded-3xl bg-gradient-to-br from-white/[0.08] to-white/[0.02] border border-white/[0.12] flex items-center justify-center shadow-[inset_0_1px_0_rgba(255,255,255,0.12),0_20px_60px_rgba(0,0,0,0.4)]">
                        <Shield className="w-10 h-10 text-text-muted" />
                    </div>
                    <span className="absolute -inset-3 rounded-3xl bg-accent-cyan/[0.06] blur-xl -z-10" />
                </div>

                {/* 404 number */}
                <div className="relative mb-4">
                    <span className="text-[120px] font-extrabold leading-none tracking-tighter bg-gradient-to-b from-white/20 to-transparent bg-clip-text text-transparent select-none">
                        404
                    </span>
                    <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-[120px] font-extrabold leading-none tracking-tighter bg-gradient-to-b from-accent-cyan/40 to-accent-cyan/0 bg-clip-text text-transparent select-none blur-sm">
                            404
                        </span>
                    </div>
                </div>

                <h1 className="text-2xl font-bold text-text-primary mb-3 tracking-tight">
                    Page Not Found
                </h1>
                <p className="text-[14px] text-text-secondary mb-10 leading-relaxed max-w-sm">
                    The route you&apos;re looking for doesn&apos;t exist. It may have been moved, deleted,
                    or you may have followed a broken link.
                </p>

                <div className="flex flex-wrap gap-3 justify-center">
                    <Link
                        to="/"
                        className="lg-btn flex items-center gap-2 px-5 py-2.5"
                    >
                        <Home className="w-4 h-4" />
                        Back to Dashboard
                    </Link>
                    <button
                        type="button"
                        onClick={() => history.back()}
                        className="lg-btn flex items-center gap-2 px-5 py-2.5"
                    >
                        <ArrowLeft className="w-4 h-4" />
                        Go Back
                    </button>
                </div>

                {/* Quick links */}
                <div className="mt-12 w-full">
                    <p className="text-[11px] text-text-muted uppercase tracking-widest mb-4">Quick navigation</p>
                    <div className="grid grid-cols-2 gap-2">
                        {[
                            { label: 'New Scan', to: '/new', desc: 'Launch a pentest' },
                            { label: 'Asset Inventory', to: '/assets', desc: 'View all assets' },
                            { label: 'Reports', to: '/reports', desc: 'Export findings' },
                            { label: 'Settings', to: '/settings', desc: 'Configure platform' },
                        ].map((link) => (
                            <Link
                                key={link.to}
                                to={link.to}
                                className="group flex items-center gap-3 px-4 py-3 rounded-xl bg-white/[0.03] border border-white/[0.07] hover:bg-white/[0.06] hover:border-white/[0.12] transition-all"
                            >
                                <Search className="w-3.5 h-3.5 text-text-muted group-hover:text-accent-cyan transition-colors" />
                                <div className="text-left min-w-0">
                                    <div className="text-[12px] font-medium text-text-secondary group-hover:text-text-primary transition-colors truncate">{link.label}</div>
                                    <div className="text-[10px] text-text-muted truncate">{link.desc}</div>
                                </div>
                            </Link>
                        ))}
                    </div>
                </div>
            </motion.div>
        </div>
    )
}
