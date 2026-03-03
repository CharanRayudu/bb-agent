import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Search, Zap, Clock, Activity, Target, ArrowRight } from 'lucide-react'

const API_BASE = '/api'

function Dashboard() {
    const [flows, setFlows] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetchFlows()
        const interval = setInterval(fetchFlows, 5000)
        return () => clearInterval(interval)
    }, [])

    async function fetchFlows() {
        try {
            const res = await fetch(`${API_BASE}/flows`)
            if (res.ok) {
                const data = await res.json()
                setFlows(data || [])
            }
        } catch (err) {
            console.error('Failed to fetch flows:', err)
        } finally {
            setLoading(false)
        }
    }

    function getStatusBadge(status) {
        const baseClasses = 'px-3 py-1 rounded-full text-xs font-mono tracking-wider flex items-center gap-1.5 border backdrop-blur-sm shadow-sm'
        switch (status) {
            case 'active':
            case 'completed':
                return `${baseClasses} bg-accent-green/10 text-accent-green border-accent-green/30`
            case 'running':
                return `${baseClasses} bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30 animate-pulse`
            case 'failed':
                return `${baseClasses} bg-accent-red/10 text-accent-red border-accent-red/30`
            default:
                return `${baseClasses} bg-text-muted/10 text-text-muted border-text-muted/30`
        }
    }

    function formatDate(dateStr) {
        return new Date(dateStr).toLocaleString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
        })
    }

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
                <div className="w-12 h-12 border-4 border-accent-cyan/20 border-t-accent-cyan rounded-full animate-spin shadow-glow"></div>
                <div className="text-text-muted font-mono tracking-widest animate-pulse">Initializing Interface...</div>
            </div>
        )
    }

    // Framer Motion Variants
    const containerVariants = {
        hidden: { opacity: 0 },
        visible: { opacity: 1, transition: { staggerChildren: 0.1 } }
    }
    const itemVariants = {
        hidden: { opacity: 0, y: 20 },
        visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 300, damping: 24 } }
    }

    return (
        <div className="pb-12">
            {/* Header Area */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 gap-6">
                <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }}>
                    <h1 className="text-4xl font-display font-black text-transparent bg-clip-text bg-gradient-to-r from-text-primary to-text-muted mb-2 tracking-tight">Active Scans</h1>
                    <p className="text-text-muted flex items-center gap-2">
                        <Activity className="w-4 h-4 text-accent-cyan" />
                        Monitoring {flows.length} autonomous penetration tests
                    </p>
                </motion.div>
                <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}>
                    <Link to="/new" className="group relative inline-flex items-center justify-center gap-2 px-8 py-3.5 text-sm font-semibold text-primary-bg bg-text-primary rounded-xl overflow-hidden transition-all duration-300 hover:scale-105 hover:shadow-[0_0_20px_rgba(255,255,255,0.3)]">
                        <div className="absolute inset-0 w-full h-full bg-gradient-to-r from-accent-cyan via-accent-green to-accent-cyan opacity-0 group-hover:opacity-100 transition-opacity duration-500 bg-[length:200%_auto] animate-[shimmer_3s_linear_infinite]" />
                        <Zap className="w-4 h-4 relative z-10" />
                        <span className="relative z-10 font-bold tracking-wide">Initiate New Attack</span>
                    </Link>
                </motion.div>
            </div>

            {/* Grid Area */}
            {flows.length === 0 ? (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col items-center justify-center min-h-[40vh] p-12 text-center border border-border/50 rounded-2xl bg-card-bg/30 backdrop-blur-sm">
                    <div className="w-20 h-20 bg-[#111827] rounded-full flex items-center justify-center mb-6 shadow-[inset_0_2px_10px_rgba(0,0,0,0.5)] border border-border">
                        <Search className="w-8 h-8 text-text-muted" />
                    </div>
                    <h2 className="text-2xl font-bold text-text-primary mb-3">No active traces detected</h2>
                    <p className="text-text-muted max-w-md mb-8">Deploy your first autonomous agent. Let Mirage handle the complex enumeration, exploitation, and reporting automatically.</p>
                </motion.div>
            ) : (
                <motion.div
                    variants={containerVariants}
                    initial="hidden"
                    animate="visible"
                    className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 auto-rows-[1fr]"
                >
                    {flows.map((flow) => (
                        <motion.div key={flow.id} variants={itemVariants} className="h-full">
                            <Link to={`/flow/${flow.id}`} className="block h-full group">
                                <div className="h-full relative overflow-hidden bg-card-bg border border-border rounded-2xl p-6 transition-all duration-500 hover:border-accent-cyan/30 hover:bg-card-hover hover:shadow-[0_8px_30px_rgba(0,0,0,0.12)]">
                                    {/* Hover gradient overlay */}
                                    <div className="absolute inset-0 bg-gradient-to-br from-accent-cyan/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none" />

                                    <div className="relative z-10 flex flex-col h-full">
                                        <div className="flex justify-between items-start mb-4 gap-4">
                                            <h3 className="text-lg font-bold text-text-primary truncate" title={flow.name}>{flow.name}</h3>
                                            <div className="flex-shrink-0">
                                                <span className={getStatusBadge(flow.status)}>{flow.status}</span>
                                            </div>
                                        </div>

                                        {flow.description && (
                                            <p className="text-sm text-text-muted line-clamp-2 mb-6 flex-grow leading-relaxed">
                                                {flow.description}
                                            </p>
                                        )}

                                        <div className="flex items-center justify-between text-xs text-text-muted/80 mt-auto pt-4 border-t border-border/50">
                                            <div className="flex items-center gap-4">
                                                <div className="flex items-center gap-1.5" title="Target">
                                                    <Target className="w-3.5 h-3.5" />
                                                    <span className="truncate max-w-[100px]">{flow.target}</span>
                                                </div>
                                                <div className="flex items-center gap-1.5" title="Initiated">
                                                    <Clock className="w-3.5 h-3.5" />
                                                    <span>{formatDate(flow.created_at)}</span>
                                                </div>
                                            </div>

                                            <div className="w-8 h-8 rounded-full bg-[#111827] border border-border flex items-center justify-center opacity-0 group-hover:opacity-100 transform translate-x-4 group-hover:translate-x-0 transition-all duration-300">
                                                <ArrowRight className="w-4 h-4 text-accent-cyan" />
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </Link>
                        </motion.div>
                    ))}
                </motion.div>
            )}
        </div>
    )
}

export default Dashboard
