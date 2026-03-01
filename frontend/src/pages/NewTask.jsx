import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

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

    // Fetch available models on mount
    useEffect(() => {
        fetchModels()
    }, [])

    async function fetchModels() {
        try {
            const res = await fetch(`${API_BASE}/models`)
            if (res.ok) {
                const data = await res.json()
                setModels(data || [])
                // Auto-select the current model (marked by backend)
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
            name: 'Full Port Scan',
            description: 'Perform a comprehensive port scan, identify all running services, detect OS and versions, then enumerate discovered services for potential vulnerabilities.',
            icon: '🔍',
        },
        {
            name: 'Web Application Test',
            description: 'Scan the web application for common vulnerabilities including SQL injection, XSS, directory traversal, misconfigured headers, and known CVEs using automated tools.',
            icon: '🌐',
        },
        {
            name: 'Network Recon',
            description: 'Perform DNS enumeration, subdomain discovery, reverse DNS lookup, and map the target network infrastructure. Identify related hosts and services.',
            icon: '🗺️',
        },
        {
            name: 'Vulnerability Assessment',
            description: 'Run a comprehensive vulnerability scan using nuclei templates and other scanners. Identify known CVEs, misconfigurations, and security weaknesses with severity ratings.',
            icon: '🛡️',
        },
    ]

    // Group models by category
    const modelsByCategory = models.reduce((acc, model) => {
        if (!acc[model.category]) acc[model.category] = []
        acc[model.category].push(model)
        return acc
    }, {})

    const selectedModel = models.find((m) => m.id === form.model)

    return (
        <div>
            <div className="page-header">
                <div>
                    <h1 className="page-title">⚡ New Penetration Test</h1>
                    <p className="page-subtitle">Configure and launch an autonomous security assessment</p>
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px' }}>
                {/* Form */}
                <div>
                    <div className="card" style={{ marginBottom: '24px' }}>
                        <h3 className="card-title" style={{ marginBottom: '20px' }}>Scan Configuration</h3>
                        <form onSubmit={handleSubmit}>
                            {/* Model Selector */}
                            <div className="form-group">
                                <label className="form-label">
                                    🧠 AI Model
                                    {selectedModel?.current && (
                                        <span style={{
                                            marginLeft: '8px',
                                            padding: '2px 8px',
                                            background: 'var(--accent-green)',
                                            color: '#000',
                                            borderRadius: '4px',
                                            fontSize: '10px',
                                            fontWeight: '700',
                                            textTransform: 'uppercase',
                                            letterSpacing: '0.5px',
                                        }}>
                                            Current
                                        </span>
                                    )}
                                </label>
                                {modelsLoading ? (
                                    <div style={{
                                        padding: '12px 16px',
                                        background: 'var(--bg-input)',
                                        border: '1px solid var(--border-color)',
                                        borderRadius: 'var(--radius-md)',
                                        color: 'var(--text-muted)',
                                        fontSize: '13px',
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '8px',
                                    }}>
                                        <div className="spinner" style={{ width: '14px', height: '14px' }}></div>
                                        Loading models from Codex CLI...
                                    </div>
                                ) : (
                                    <select
                                        name="model"
                                        value={form.model}
                                        onChange={handleChange}
                                        className="form-input"
                                        style={{ cursor: 'pointer' }}
                                    >
                                        {Object.entries(modelsByCategory).map(([category, catModels]) => (
                                            <optgroup key={category} label={category}>
                                                {catModels.map((m) => (
                                                    <option key={m.id} value={m.id}>
                                                        {m.name} {m.current ? '✓' : ''}
                                                    </option>
                                                ))}
                                            </optgroup>
                                        ))}
                                    </select>
                                )}
                                {selectedModel && (
                                    <p style={{
                                        fontSize: '12px',
                                        color: 'var(--text-muted)',
                                        marginTop: '6px',
                                        lineHeight: '1.4',
                                    }}>
                                        {selectedModel.description}
                                    </p>
                                )}
                            </div>

                            <div className="form-group">
                                <label className="form-label">Scan Name</label>
                                <input
                                    type="text"
                                    name="name"
                                    value={form.name}
                                    onChange={handleChange}
                                    className="form-input"
                                    placeholder="e.g., Production Server Assessment"
                                />
                            </div>

                            <div className="form-group">
                                <label className="form-label">Target</label>
                                <input
                                    type="text"
                                    name="target"
                                    value={form.target}
                                    onChange={handleChange}
                                    className="form-input"
                                    placeholder="e.g., 192.168.1.1, example.com, 10.0.0.0/24"
                                />
                            </div>

                            <div className="form-group">
                                <label className="form-label">Task Description</label>
                                <textarea
                                    name="description"
                                    value={form.description}
                                    onChange={handleChange}
                                    className="form-textarea"
                                    placeholder="Describe what you want the AI agent to do. Be specific about scope, depth, and any particular areas of interest..."
                                    rows={5}
                                />
                            </div>

                            {error && (
                                <div style={{
                                    padding: '12px 16px',
                                    background: '#ff475720',
                                    border: '1px solid #ff475740',
                                    borderRadius: 'var(--radius-md)',
                                    color: 'var(--accent-red)',
                                    fontSize: '13px',
                                    marginBottom: '16px',
                                }}>
                                    ⚠️ {error}
                                </div>
                            )}

                            <button
                                type="submit"
                                className="btn btn-primary btn-lg"
                                disabled={loading}
                                style={{ width: '100%', justifyContent: 'center' }}
                            >
                                {loading ? (
                                    <>
                                        <div className="spinner"></div>
                                        Launching Agent...
                                    </>
                                ) : (
                                    '🚀 Launch Autonomous Scan'
                                )}
                            </button>
                        </form>
                    </div>
                </div>

                {/* Right column: Presets + Tips */}
                <div>
                    <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '16px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        Quick Presets
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        {presets.map((preset) => (
                            <div
                                key={preset.name}
                                className="card"
                                style={{ cursor: 'pointer', padding: '16px' }}
                                onClick={() =>
                                    setForm({
                                        ...form,
                                        name: preset.name,
                                        description: preset.description,
                                    })
                                }
                            >
                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                                    <span style={{ fontSize: '20px' }}>{preset.icon}</span>
                                    <span style={{ fontWeight: '600', fontSize: '14px' }}>{preset.name}</span>
                                </div>
                                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                                    {preset.description}
                                </p>
                            </div>
                        ))}
                    </div>

                    <div className="card" style={{ marginTop: '16px', padding: '16px', borderColor: '#a855f720' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                            <span style={{ fontSize: '16px' }}>💡</span>
                            <span style={{ fontWeight: '600', fontSize: '13px', color: 'var(--accent-purple)' }}>Pro Tip</span>
                        </div>
                        <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                            Be as specific as possible in your task description. The AI agent works best when it knows the scope
                            (e.g., "focus on web services on ports 80 and 443") and any constraints ("do not run exploits, recon only").
                        </p>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default NewTask
