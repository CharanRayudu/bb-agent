import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Zap, Search, Globe, Network, Shield, Lightbulb, ChevronRight, Server, Database, Terminal, Ghost, Bug } from 'lucide-react'

const API_BASE = '/api'

function NewTask() {
    const navigate = useNavigate()
    const [form, setForm] = useState({
        name: '',
        target: '',
        description: '',
        model: '',
    })
    const [models, setModels] = useState([])
    const [modelsLoading, setModelsLoading] = useState(true)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')

    useEffect(() => {
        fetchModels()
    }, [])

    async function fetchModels() {
        try {
            const res = await fetch(`${API_BASE}/models`)
            if (res.ok) {
                const data = await res.json()
                setModels(data || [])
                const current = data.find((m) => m.current)
                if (current) {
                    setForm((prev) => ({ ...prev, model: current.id }))
                } else if (data.length > 0) {
                    setForm((prev) => ({ ...prev, model: data[0].id }))
                }
            }
        } catch (err) {
            console.error('Failed to fetch models:', err)
        } finally {
            setModelsLoading(false)
        }
    }

    function handleChange(e) {
        setForm({ ...form, [e.target.name]: e.target.value })
    }

    async function handleSubmit(e) {
        e.preventDefault()
        setError('')

        if (!form.name || !form.target) {
            setError('Scan name and target are required')
            return
        }

        setLoading(true)

        try {
            const res = await fetch(`${API_BASE}/flows/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: form.name,
                    target: form.target,
                    model: form.model,
                    description: form.description || `Perform a comprehensive penetration test against ${form.target}`,
                }),
            })

            if (!res.ok) {
                const text = await res.text()
                throw new Error(text || 'Failed to create scan')
            }

            const flow = await res.json()
            navigate(`/flow/${flow.id}`)
        } catch (err) {
            setError(err.message)
        } finally {
            setLoading(false)
        }
    }

    const presets = [
        {
            name: 'Stealth Reconnaissance',
            description: 'Perform quiet, passive OSINT and low-rate SYN scanning. Discover subdomains and open ports without triggering IDS/IPS alerts.',
            icon: Ghost,
        },
        {
            name: 'OWASP Web Exploitation',
            description: 'Run deep directory brute-force, test for SQLi, XSS, SSRF, and hunt for exposed admin panels using Nuclei templates.',
            icon: Globe,
        },
        {
            name: 'API Endpoint Fuzzing',
            description: 'Discover hidden API routes (v1/v2/graphql), test for Broken Object Level Authorization (BOLA), and JWT misconfigurations.',
            icon: Terminal,
        },
        {
            name: 'Database Extraction',
            description: 'Focus exclusively on DB ports (3306, 5432, 1433). Attempt weak credential brute-forcing and data extraction using SQLMap.',
            icon: Database,
        },
        {
            name: 'Internal Infrastructure',
            description: 'Identify internal services. Enumerate SMB/LDAP/Kerberos, check for anonymous logins, and map Active Directory attack paths.',
            icon: Server,
        },
        {
            name: 'Full Red Team Chain',
            description: 'Leave no stone unturned. Perform exhaustive port scanning, deep web enum, CVE hunting, and attempt authorized exploitation chains.',
            icon: Bug,
        },
    ]

    const modelsByCategory = models.reduce((acc, model) => {
        if (!acc[model.category]) acc[model.category] = []
        acc[model.category].push(model)
        return acc
    }, {})

    const selectedModel = models.find((m) => m.id === form.model)

    return (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="relative pb-12 max-w-6xl mx-auto">
            {/* Focused ambient halo behind form */}
            <div className="pointer-events-none absolute left-1/2 -translate-x-1/2 -top-6 w-[34rem] h-[34rem] bg-[radial-gradient(circle,_rgba(0,212,255,0.28),transparent_65%)] blur-3xl opacity-80" />

            <div className="mb-10 text-center relative z-10">
                <div className="inline-block px-8 py-5 rounded-3xl border border-white/12 bg-white/6 backdrop-blur-2xl shadow-[0_18px_80px_rgba(15,23,42,0.9)]">
                    <h1 className="text-4xl md:text-5xl font-display font-black text-transparent bg-clip-text bg-gradient-to-r from-text-primary to-text-muted mb-3 tracking-tight">
                        Initiate New Attack
                    </h1>
                    <p className="text-text-muted text-lg">Configure the autonomous agent&apos;s parameters and operational scope.</p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-8 relative z-10">
                {/* Form Column */}
                <div className="lg:col-span-3">
                    <div className="relative overflow-hidden rounded-3xl border border-white/12 bg-white/6 backdrop-blur-2xl p-8 shadow-[0_18px_80px_rgba(15,23,42,0.95)]">
                        {/* Glow effect */}
                        <div className="absolute top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-accent-cyan/16 rounded-full blur-[80px] pointer-events-none" />

                        <h3 className="text-lg md:text-xl font-semibold text-text-primary mb-8 flex items-center gap-2">
                            <span className="w-8 h-8 rounded-lg bg-accent-cyan/10 text-accent-cyan flex items-center justify-center">1</span>
                            Operational Configuration
                        </h3>

                        <form onSubmit={handleSubmit} className="space-y-6 relative z-10">
                            {/* Model */}
                            <div>
                                <label className="block text-sm font-semibold text-text-primary mb-2 flex items-center gap-2">
                                    Agent Brain Override
                                    {selectedModel?.current && (
                                        <span className="px-2 py-0.5 bg-accent-green/20 text-accent-green rounded text-[10px] font-bold uppercase tracking-wider border border-accent-green/30">Current</span>
                                    )}
                                </label>
                                {modelsLoading ? (
                                    <div className="w-full bg-[#0d1321] border border-border rounded-xl p-4 flex items-center gap-3 text-text-muted">
                                        <div className="w-4 h-4 border-2 border-accent-cyan/30 border-t-accent-cyan rounded-full animate-spin"></div>
                                        <span className="text-sm font-mono">Syncing models from Codex API...</span>
                                    </div>
                                ) : (
                                    <div className="relative group">
                                        <select
                                            name="model"
                                            value={form.model}
                                            onChange={handleChange}
                                            className="w-full bg-[#0d1321] text-text-primary border border-border rounded-xl p-4 appearance-none outline-none transition-all duration-300 focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan focus:shadow-[0_0_15px_rgba(0,212,255,0.15)] group-hover:border-border-focus"
                                        >
                                            {Object.entries(modelsByCategory).map(([category, catModels]) => (
                                                <optgroup key={category} label={category} className="bg-card-bg text-text-muted font-bold">
                                                    {catModels.map((m) => (
                                                        <option key={m.id} value={m.id} className="text-text-primary font-normal">
                                                            {m.name} {m.current ? '✓' : ''}
                                                        </option>
                                                    ))}
                                                </optgroup>
                                            ))}
                                        </select>
                                        <div className="absolute inset-y-0 right-4 flex items-center pointer-events-none text-text-muted">
                                            <ChevronRight className="w-5 h-5 rotate-90" />
                                        </div>
                                    </div>
                                )}
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div>
                                    <label className="block text-sm font-semibold text-text-primary mb-2">Operation Name</label>
                                    <input
                                        type="text"
                                        name="name"
                                        value={form.name}
                                        onChange={handleChange}
                                        className="w-full bg-[#0d1321] text-text-primary border border-border rounded-xl p-4 outline-none transition-all duration-300 focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan focus:shadow-[0_0_15px_rgba(0,212,255,0.15)] placeholder-text-muted/50"
                                        placeholder="e.g., Red Team Assessment"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-semibold text-text-primary mb-2">Target Scope</label>
                                    <input
                                        type="text"
                                        name="target"
                                        value={form.target}
                                        onChange={handleChange}
                                        className="w-full bg-[#0d1321] text-text-primary border border-border rounded-xl p-4 outline-none transition-all duration-300 focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan focus:shadow-[0_0_15px_rgba(0,212,255,0.15)] placeholder-text-muted/50"
                                        placeholder="IP, Domain, or CIDR"
                                    />
                                </div>
                            </div>

                            <div>
                                <label className="block text-sm font-semibold text-text-primary mb-2">Agent Instructions / Context</label>
                                <textarea
                                    name="description"
                                    value={form.description}
                                    onChange={handleChange}
                                    className="w-full bg-[#0d1321] text-text-primary border border-border rounded-xl p-4 outline-none transition-all duration-300 focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan focus:shadow-[0_0_15px_rgba(0,212,255,0.15)] placeholder-text-muted/50 resize-none font-mono text-sm leading-relaxed"
                                    placeholder="Provide explicit instructions. e.g., 'Discover subdomains, then run dirb on all discovered HTTP servers. Avoid DoS tools.' If left blank, default Recon & Scan occurs."
                                    rows={5}
                                />
                            </div>

                            {error && (
                                <div className="p-4 bg-accent-red/10 border border-accent-red/30 rounded-xl text-accent-red text-sm flex items-center gap-3">
                                    <span className="text-xl">⚠️</span> {error}
                                </div>
                            )}

                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full group relative flex items-center justify-center gap-3 px-8 py-4 bg-text-primary text-primary-bg rounded-xl font-bold text-lg overflow-hidden transition-all hover:scale-[1.02] disabled:opacity-70 disabled:hover:scale-100"
                            >
                                <div className="absolute inset-0 w-full h-full bg-gradient-to-r from-accent-cyan via-accent-green to-accent-cyan opacity-0 group-hover:opacity-100 transition-opacity duration-500 bg-[length:200%_auto] animate-[shimmer_3s_linear_infinite]" />
                                {loading ? (
                                    <>
                                        <div className="w-5 h-5 border-2 border-primary-bg border-t-transparent rounded-full animate-spin relative z-10"></div>
                                        <span className="relative z-10">Initializing Payload...</span>
                                    </>
                                ) : (
                                    <>
                                        <Zap className="w-5 h-5 relative z-10" />
                                        <span className="relative z-10">Deploy Agent</span>
                                    </>
                                )}
                            </button>
                        </form>
                    </div>
                </div>

                {/* Presets Column */}
                <div className="lg:col-span-2 space-y-6">
                    <h3 className="text-sm font-bold text-text-muted tracking-widest uppercase mb-2">Tactical Presets</h3>
                    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                        {presets.map((preset, idx) => {
                            const Icon = preset.icon
                            return (
                                <motion.div
                                    key={preset.name}
                                    initial={{ opacity: 0, scale: 0.95 }}
                                    animate={{ opacity: 1, scale: 1 }}
                                    transition={{ delay: idx * 0.05 }}
                                    onClick={() => setForm({ ...form, name: preset.name, description: preset.description })}
                                    className="group cursor-pointer relative overflow-hidden rounded-2xl border border-white/12 bg-white/5 backdrop-blur-xl p-4 hover:border-accent-cyan/50 hover:bg-white/10 transition-all duration-300 flex flex-col h-full shadow-[0_12px_40px_rgba(15,23,42,0.8)]"
                                >
                                    <div className="pointer-events-none absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500">
                                        <div className="absolute -inset-x-10 -top-10 h-20 bg-gradient-to-r from-white/35 via-transparent to-white/35 blur-2xl mix-blend-screen" />
                                    </div>
                                    <div className="flex items-center gap-3 mb-3 shrink-0">
                                        <div className="p-2.5 rounded-lg bg-[#111827] border border-border group-hover:border-accent-cyan/50 group-hover:text-accent-cyan group-hover:shadow-[0_0_15px_rgba(0,212,255,0.2)] transition-all">
                                            <Icon className="w-5 h-5" />
                                        </div>
                                        <h4 className="font-bold text-text-primary text-sm leading-tight">{preset.name}</h4>
                                    </div>
                                    <p className="text-xs text-text-muted/80 leading-relaxed grow">{preset.description}</p>
                                </motion.div>
                            )
                        })}
                    </div>

                    <div className="relative overflow-hidden rounded-2xl border border-white/12 bg-white/5 backdrop-blur-xl p-5 mt-8 shadow-[0_12px_40px_rgba(15,23,42,0.8)]">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-accent-purple/20 rounded-full blur-[40px] pointer-events-none" />
                        <div className="flex items-center gap-2 mb-2 relative z-10">
                            <Lightbulb className="w-4 h-4 text-accent-purple" />
                            <span className="font-bold text-sm text-accent-purple uppercase tracking-widest">Pro Tip</span>
                        </div>
                        <p className="text-xs text-text-muted leading-relaxed relative z-10">
                            The Sandboxed Agent parses your instructions natively using the selected LLM. Natural language scoping (e.g. "Ignore port 443" or "Run Nikto before Nmap") works perfectly.
                        </p>
                    </div>
                </div>
            </div>
        </motion.div>
    )
}

export default NewTask
