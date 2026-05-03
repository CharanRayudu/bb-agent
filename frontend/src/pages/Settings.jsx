import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, Settings as SettingsIcon, Save, Server, Puzzle, Bell, CheckCircle, AlertTriangle, Link2, Shield, Key } from 'lucide-react'

const API_BASE = '/api'

function Settings() {
    const [activeTab, setActiveTab] = useState('providers')
    const [config, setConfig] = useState({
        providers: {
            openai: { enabled: true, model: 'gpt-4o', apiKey: '' },
        },
        webhook_url: '',
        webhook_secret: '',
        notify_critical: true,
        notify_high: true,
        notify_complete: true,
    })
    const [saving, setSaving] = useState(false)
    const [message, setMessage] = useState('')
    const [testingWebhook, setTestingWebhook] = useState(false)
    const [testResult, setTestResult] = useState(null)

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

    async function testWebhook() {
        if (!config.webhook_url) return
        setTestingWebhook(true)
        setTestResult(null)
        try {
            const resp = await fetch(`${API_BASE}/notifications/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: config.webhook_url, secret: config.webhook_secret }),
            })
            setTestResult(resp.ok ? 'success' : 'failed')
        } catch {
            setTestResult('failed')
        }
        setTestingWebhook(false)
        setTimeout(() => setTestResult(null), 4000)
    }

    const [ticketProvider, setTicketProvider] = useState('jira')
    const [ticketTesting, setTicketTesting] = useState(false)
    const [ticketTestResult, setTicketTestResult] = useState(null)

    async function testTicketIntegration() {
        setTicketTesting(true)
        setTicketTestResult(null)
        try {
            const resp = await fetch(`${API_BASE}/integrations/ticket/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider: ticketProvider }),
            })
            const data = await resp.json()
            setTicketTestResult(resp.ok && data.status === 'ok' ? 'success' : { error: data.error || data.missing?.join(', ') })
        } catch {
            setTicketTestResult({ error: 'Connection failed' })
        }
        setTicketTesting(false)
        setTimeout(() => setTicketTestResult(null), 5000)
    }

    const tabs = [
        { id: 'providers', label: 'LLM Provider', icon: Server },
        { id: 'notifications', label: 'Notifications', icon: Bell },
        { id: 'integrations', label: 'Integrations', icon: Link2 },
        { id: 'sso', label: 'SSO / OIDC', icon: Key },
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

                {activeTab === 'notifications' && (
                    <div className="space-y-5">
                        {/* Banner pointing to the dedicated Notifications page */}
                        <div className="flex items-start gap-3 rounded-xl border border-accent-cyan/25 bg-accent-cyan/[0.07] p-4">
                            <Bell className="w-4 h-4 text-accent-cyan mt-0.5 flex-shrink-0" />
                            <div className="flex-1 min-w-0">
                                <p className="text-xs font-semibold text-text-primary">Full Notification Hub available</p>
                                <p className="text-[11px] text-text-muted mt-0.5">Manage Slack, webhook, and email channels with per-event rules, test pings, and delivery history in the dedicated Notifications page.</p>
                            </div>
                            <Link
                                to="/notifications"
                                className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-cyan/15 border border-accent-cyan/30 text-[11px] text-accent-cyan font-medium hover:bg-accent-cyan/25 transition-colors"
                            >
                                Go to Notifications →
                            </Link>
                        </div>
                        <div>
                            <h3 className="text-sm font-bold text-text-primary">Quick Webhook Test</h3>
                            <p className="text-xs text-text-muted mt-1">Send a one-off test ping to any HTTP endpoint. For persistent channel management use the Notifications page above.</p>
                        </div>

                        <div className="space-y-3">
                            <div>
                                <label className="text-[10px] text-text-muted block mb-1 uppercase tracking-widest">Webhook URL</label>
                                <input
                                    type="url"
                                    value={config.webhook_url || ''}
                                    onChange={e => setConfig(prev => ({ ...prev, webhook_url: e.target.value }))}
                                    placeholder="https://hooks.slack.com/services/... or any HTTPS endpoint"
                                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-text-primary outline-none focus:border-accent-cyan/40 font-mono"
                                />
                            </div>
                            <div>
                                <label className="text-[10px] text-text-muted block mb-1 uppercase tracking-widest">Signing Secret (optional)</label>
                                <input
                                    type="password"
                                    value={config.webhook_secret || ''}
                                    onChange={e => setConfig(prev => ({ ...prev, webhook_secret: e.target.value }))}
                                    placeholder="HMAC-SHA256 signing secret"
                                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-text-primary outline-none focus:border-accent-cyan/40 font-mono"
                                />
                                <p className="text-[10px] text-text-muted mt-1">If set, every request includes <code className="bg-white/10 px-1 rounded">X-Mirage-Signature: sha256=...</code></p>
                            </div>
                        </div>

                        <div className="rounded-lg bg-white/[0.03] border border-white/10 p-4 space-y-3">
                            <h4 className="text-[10px] font-mono uppercase tracking-widest text-text-muted">Trigger Events</h4>
                            {[
                                { key: 'notify_critical', label: 'Critical Findings', desc: 'Fire immediately when a critical vulnerability is confirmed', color: '#ff4757' },
                                { key: 'notify_high', label: 'High Findings', desc: 'Fire when a high severity vulnerability is confirmed', color: '#ff7f50' },
                                { key: 'notify_complete', label: 'Scan Complete', desc: 'Summary notification when a scan finishes', color: '#6ee7b7' },
                            ].map(({ key, label, desc, color }) => (
                                <label key={key} className="flex items-start gap-3 cursor-pointer group">
                                    <div className="relative mt-0.5 flex-shrink-0">
                                        <input
                                            type="checkbox"
                                            checked={config[key] !== false}
                                            onChange={e => setConfig(prev => ({ ...prev, [key]: e.target.checked }))}
                                            className="sr-only"
                                        />
                                        <div className={`w-4 h-4 rounded border flex items-center justify-center transition-all ${config[key] !== false ? 'border-transparent' : 'border-white/20 bg-white/5'}`} style={config[key] !== false ? { background: color, borderColor: color } : {}}>
                                            {config[key] !== false && <CheckCircle className="w-3 h-3 text-white" />}
                                        </div>
                                    </div>
                                    <div>
                                        <div className="text-xs font-medium text-text-primary group-hover:text-white transition-colors">{label}</div>
                                        <div className="text-[10px] text-text-muted mt-0.5">{desc}</div>
                                    </div>
                                </label>
                            ))}
                        </div>

                        <div className="flex items-center gap-3">
                            <button
                                onClick={testWebhook}
                                disabled={!config.webhook_url || testingWebhook}
                                className="flex items-center gap-2 px-4 py-2 rounded-xl border border-white/15 bg-white/5 text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-white/10 transition-colors disabled:opacity-50"
                            >
                                {testingWebhook ? <div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin" /> : <Bell className="w-3 h-3" />}
                                Send Test Ping
                            </button>
                            {testResult === 'success' && (
                                <span className="flex items-center gap-1.5 text-xs text-accent-green">
                                    <CheckCircle className="w-3.5 h-3.5" /> Webhook delivered successfully
                                </span>
                            )}
                            {testResult === 'failed' && (
                                <span className="flex items-center gap-1.5 text-xs text-accent-red">
                                    <AlertTriangle className="w-3.5 h-3.5" /> Delivery failed — check URL
                                </span>
                            )}
                        </div>

                        <div className="rounded-lg bg-white/[0.03] border border-white/[0.08] p-4">
                            <h4 className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-2">Slack Setup Guide</h4>
                            <ol className="text-[11px] text-text-muted space-y-1 list-decimal list-inside">
                                <li>Go to <span className="text-accent-cyan">api.slack.com/apps</span> → Create App → Incoming Webhooks</li>
                                <li>Enable Incoming Webhooks and click &quot;Add New Webhook to Workspace&quot;</li>
                                <li>Select a channel and copy the generated URL above</li>
                                <li>Save and run a test scan — alerts appear in your channel instantly</li>
                            </ol>
                        </div>
                    </div>
                )}

                {activeTab === 'integrations' && (
                    <div className="space-y-6">
                        <div>
                            <h3 className="text-sm font-bold text-text-primary">Issue Tracker Integration</h3>
                            <p className="text-xs text-text-muted mt-1">Auto-create tickets from findings in Jira, GitHub Issues, or Linear.</p>
                        </div>

                        {/* Provider selector */}
                        <div className="flex gap-2">
                            {['jira', 'github', 'linear'].map(p => (
                                <button key={p} onClick={() => setTicketProvider(p)}
                                    className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition-colors ${ticketProvider === p ? 'bg-accent-cyan/20 border-accent-cyan/40 text-accent-cyan' : 'bg-white/5 border-white/10 text-text-muted hover:text-text-primary'}`}>
                                    {p.charAt(0).toUpperCase() + p.slice(1)}
                                </button>
                            ))}
                        </div>

                        {ticketProvider === 'jira' && (
                            <div className="space-y-3">
                                {[
                                    { key: 'jira_base_url', label: 'Jira Base URL', placeholder: 'https://yourorg.atlassian.net', type: 'url' },
                                    { key: 'jira_email', label: 'Email', placeholder: 'you@company.com', type: 'email' },
                                    { key: 'jira_api_token', label: 'API Token', placeholder: 'From id.atlassian.com/manage-profile/security', type: 'password' },
                                    { key: 'jira_project', label: 'Project Key', placeholder: 'SEC', type: 'text' },
                                    { key: 'jira_issue_type', label: 'Issue Type', placeholder: 'Bug', type: 'text' },
                                ].map(({ key, label, placeholder, type }) => (
                                    <div key={key}>
                                        <label className="text-[10px] text-text-muted block mb-1 uppercase tracking-widest">{label}</label>
                                        <input type={type} value={config[key] || ''} onChange={e => setConfig(prev => ({ ...prev, [key]: e.target.value }))}
                                            placeholder={placeholder}
                                            className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-text-primary outline-none focus:border-accent-cyan/40 font-mono" />
                                    </div>
                                ))}
                            </div>
                        )}

                        {ticketProvider === 'github' && (
                            <div className="space-y-3">
                                {[
                                    { key: 'github_token', label: 'Personal Access Token', placeholder: 'ghp_...', type: 'password' },
                                    { key: 'github_owner', label: 'Repository Owner', placeholder: 'myorg', type: 'text' },
                                    { key: 'github_repo', label: 'Repository Name', placeholder: 'security-findings', type: 'text' },
                                ].map(({ key, label, placeholder, type }) => (
                                    <div key={key}>
                                        <label className="text-[10px] text-text-muted block mb-1 uppercase tracking-widest">{label}</label>
                                        <input type={type} value={config[key] || ''} onChange={e => setConfig(prev => ({ ...prev, [key]: e.target.value }))}
                                            placeholder={placeholder}
                                            className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-text-primary outline-none focus:border-accent-cyan/40 font-mono" />
                                    </div>
                                ))}
                            </div>
                        )}

                        {ticketProvider === 'linear' && (
                            <div className="space-y-3">
                                {[
                                    { key: 'linear_api_key', label: 'Linear API Key', placeholder: 'lin_api_...', type: 'password' },
                                    { key: 'linear_team_id', label: 'Team ID', placeholder: 'From Linear Settings → API', type: 'text' },
                                    { key: 'linear_project_id', label: 'Project ID (optional)', placeholder: '', type: 'text' },
                                ].map(({ key, label, placeholder, type }) => (
                                    <div key={key}>
                                        <label className="text-[10px] text-text-muted block mb-1 uppercase tracking-widest">{label}</label>
                                        <input type={type} value={config[key] || ''} onChange={e => setConfig(prev => ({ ...prev, [key]: e.target.value }))}
                                            placeholder={placeholder}
                                            className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-text-primary outline-none focus:border-accent-cyan/40 font-mono" />
                                    </div>
                                ))}
                            </div>
                        )}

                        <div className="flex items-center gap-3">
                            <button onClick={testTicketIntegration} disabled={ticketTesting}
                                className="flex items-center gap-2 px-4 py-2 rounded-xl border border-white/15 bg-white/5 text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-white/10 transition-colors disabled:opacity-50">
                                {ticketTesting ? <div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin" /> : <Link2 className="w-3 h-3" />}
                                Test Connection
                            </button>
                            {ticketTestResult === 'success' && (
                                <span className="flex items-center gap-1.5 text-xs text-accent-green"><CheckCircle className="w-3.5 h-3.5" /> Connected successfully</span>
                            )}
                            {ticketTestResult && ticketTestResult !== 'success' && (
                                <span className="flex items-center gap-1.5 text-xs text-accent-red"><AlertTriangle className="w-3.5 h-3.5" /> {ticketTestResult.error}</span>
                            )}
                        </div>
                    </div>
                )}

                {activeTab === 'sso' && (
                    <div className="space-y-5">
                        <div>
                            <h3 className="text-sm font-bold text-text-primary">Single Sign-On (OIDC / OAuth2)</h3>
                            <p className="text-xs text-text-muted mt-1">Allow team members to log in with Google, GitHub, or Okta.</p>
                        </div>

                        <div className="space-y-4">
                            {/* Google */}
                            <div className="rounded-lg bg-white/4 border border-white/10 p-4 space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs font-bold text-text-primary">Google Workspace</span>
                                    <a href="/api/auth/oidc/begin?provider=google" className="text-[10px] text-accent-cyan hover:underline">Test Login →</a>
                                </div>
                                {[
                                    { key: 'oidc_google_client_id', label: 'Client ID', placeholder: '...apps.googleusercontent.com' },
                                    { key: 'oidc_google_client_secret', label: 'Client Secret', placeholder: '', type: 'password' },
                                ].map(({ key, label, placeholder, type = 'text' }) => (
                                    <div key={key}>
                                        <label className="text-[10px] text-text-muted block mb-1">{label}</label>
                                        <input type={type} value={config[key] || ''} onChange={e => setConfig(prev => ({ ...prev, [key]: e.target.value }))}
                                            placeholder={placeholder}
                                            className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-text-primary outline-none font-mono" />
                                    </div>
                                ))}
                            </div>

                            {/* GitHub */}
                            <div className="rounded-lg bg-white/4 border border-white/10 p-4 space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs font-bold text-text-primary">GitHub OAuth</span>
                                    <a href="/api/auth/oidc/begin?provider=github" className="text-[10px] text-accent-cyan hover:underline">Test Login →</a>
                                </div>
                                {[
                                    { key: 'oidc_github_client_id', label: 'Client ID', placeholder: 'Oauth App Client ID' },
                                    { key: 'oidc_github_client_secret', label: 'Client Secret', placeholder: '', type: 'password' },
                                ].map(({ key, label, placeholder, type = 'text' }) => (
                                    <div key={key}>
                                        <label className="text-[10px] text-text-muted block mb-1">{label}</label>
                                        <input type={type} value={config[key] || ''} onChange={e => setConfig(prev => ({ ...prev, [key]: e.target.value }))}
                                            placeholder={placeholder}
                                            className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-text-primary outline-none font-mono" />
                                    </div>
                                ))}
                            </div>

                            {/* Okta */}
                            <div className="rounded-lg bg-white/4 border border-white/10 p-4 space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs font-bold text-text-primary">Okta</span>
                                    <a href="/api/auth/oidc/begin?provider=okta" className="text-[10px] text-accent-cyan hover:underline">Test Login →</a>
                                </div>
                                {[
                                    { key: 'oidc_okta_domain', label: 'Okta Domain', placeholder: 'yourorg.okta.com' },
                                    { key: 'oidc_okta_client_id', label: 'Client ID', placeholder: '' },
                                    { key: 'oidc_okta_client_secret', label: 'Client Secret', placeholder: '', type: 'password' },
                                ].map(({ key, label, placeholder, type = 'text' }) => (
                                    <div key={key}>
                                        <label className="text-[10px] text-text-muted block mb-1">{label}</label>
                                        <input type={type} value={config[key] || ''} onChange={e => setConfig(prev => ({ ...prev, [key]: e.target.value }))}
                                            placeholder={placeholder}
                                            className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-text-primary outline-none font-mono" />
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="rounded-lg bg-white/[0.03] border border-white/[0.08] p-4">
                            <h4 className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-2">Callback URL</h4>
                            <code className="text-[11px] text-accent-cyan bg-white/5 px-2 py-1 rounded block">/api/auth/oidc/callback</code>
                            <p className="text-[10px] text-text-muted mt-2">Register this as the Redirect URI in your OAuth2 application settings.</p>
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
