import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, Settings as SettingsIcon, Save, Server, Puzzle } from 'lucide-react'

const API_BASE = '/api'

function Settings() {
    const [activeTab, setActiveTab] = useState('providers')
    const [config, setConfig] = useState({
        providers: {
            openai: { enabled: true, model: 'gpt-4o', apiKey: '' },
        },
    })
    const [saving, setSaving] = useState(false)
    const [message, setMessage] = useState('')

    useEffect(() => {
        fetchConfig()
    }, [])

    async function fetchConfig() {
        try {
            const resp = await fetch(`${API_BASE}/config`)
            if (resp.ok) {
                const data = await resp.json()
                setConfig(prev => ({ ...prev, ...data }))
            }
        } catch (err) {
            console.error('Failed to fetch config:', err)
        }
    }

    async function saveConfig() {
        setSaving(true)
        setMessage('')
        try {
            const resp = await fetch(`${API_BASE}/config`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
            })
            if (resp.ok) {
                setMessage('Configuration saved successfully')
            } else {
                setMessage('Failed to save configuration')
            }
        } catch (err) {
            setMessage('Error saving configuration')
        }
        setSaving(false)
        setTimeout(() => setMessage(''), 3000)
    }

    const tabs = [
        { id: 'providers', label: 'LLM Provider', icon: Server },
        { id: 'plugins', label: 'Plugins', icon: Puzzle },
    ]

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <Link to="/" className="p-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 transition-colors">
                        <ArrowLeft className="w-4 h-4 text-text-muted" />
                    </Link>
                    <div>
                        <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-3">
                            <SettingsIcon className="w-6 h-6 text-accent-orange" />
                            Configuration
                        </h1>
                        <p className="text-xs text-text-muted mt-1">LLM provider and plugin settings</p>
                    </div>
                </div>
                <button
                    onClick={saveConfig}
                    disabled={saving}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-cyan/20 border border-accent-cyan/40 text-accent-cyan text-xs font-medium hover:bg-accent-cyan/30 transition-colors disabled:opacity-50"
                >
                    <Save className="w-3 h-3" />
                    {saving ? 'Saving...' : 'Save Changes'}
                </button>
            </div>

            {message && (
                <div className="rounded-xl bg-accent-green/10 border border-accent-green/30 px-4 py-2 text-xs text-accent-green">
                    {message}
                </div>
            )}

            {/* Tab Navigation */}
            <div className="flex items-center gap-2 overflow-x-auto pb-1">
                {tabs.map(tab => {
                    const Icon = tab.icon
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-medium transition-colors whitespace-nowrap ${
                                activeTab === tab.id
                                    ? 'bg-white/10 border border-white/20 text-text-primary'
                                    : 'bg-white/4 border border-white/10 text-text-muted hover:text-text-primary'
                            }`}
                        >
                            <Icon className="w-3 h-3" />
                            {tab.label}
                        </button>
                    )
                })}
            </div>

            {/* Tab Content */}
            <div className="rounded-xl bg-white/4 border border-white/10 p-6">
                {activeTab === 'providers' && (
                    <div className="space-y-4">
                        <h3 className="text-sm font-bold text-text-primary">LLM Provider Configuration</h3>
                        <p className="text-xs text-text-muted">Configure the OpenAI model and API key (or use Codex CLI OAuth).</p>
                        <div className="rounded-lg bg-white/4 border border-white/10 p-4 space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-xs font-bold text-text-primary uppercase">OpenAI</span>
                                <span className="text-[10px] text-accent-green px-2 py-0.5 rounded bg-accent-green/10 border border-accent-green/20">Active</span>
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="text-[10px] text-text-muted block mb-1">Model</label>
                                    <input
                                        type="text"
                                        value={config.providers.openai?.model || 'gpt-4o'}
                                        onChange={e => setConfig(prev => ({
                                            ...prev,
                                            providers: { ...prev.providers, openai: { ...prev.providers.openai, model: e.target.value } }
                                        }))}
                                        className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-text-primary outline-none"
                                    />
                                </div>
                                <div>
                                    <label className="text-[10px] text-text-muted block mb-1">API Key (optional if using Codex OAuth)</label>
                                    <input
                                        type="password"
                                        value={config.providers.openai?.apiKey || ''}
                                        onChange={e => setConfig(prev => ({
                                            ...prev,
                                            providers: { ...prev.providers, openai: { ...prev.providers.openai, apiKey: e.target.value } }
                                        }))}
                                        placeholder="sk-..."
                                        className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-text-primary outline-none"
                                    />
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'plugins' && (
                    <div className="space-y-4">
                        <h3 className="text-sm font-bold text-text-primary">Plugin Modules</h3>
                        <p className="text-xs text-text-muted">Manage community-extensible pentest operation profiles.</p>
                        <div className="text-center py-8 text-text-muted text-xs">
                            No plugins installed. Place plugin modules in the <code className="bg-white/10 px-1 rounded">plugins/</code> directory.
                        </div>
                    </div>
                )}
            </div>
        </div>
    )
}

export default Settings
