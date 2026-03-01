import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

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
        const classes = {
            active: 'badge-active',
            running: 'badge-running',
            completed: 'badge-completed',
            failed: 'badge-failed',
            paused: 'badge-pending',
        }
        return `badge ${classes[status] || 'badge-pending'}`
    }

    function formatDate(dateStr) {
        return new Date(dateStr).toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        })
    }

    if (loading) {
        return (
            <div className="loading-container">
                <div className="spinner"></div>
                Loading scans...
            </div>
        )
    }

    return (
        <div>
            <div className="page-header">
                <div>
                    <h1 className="page-title">🎯 Scan Dashboard</h1>
                    <p className="page-subtitle">Monitor your autonomous penetration tests</p>
                </div>
                <Link to="/new" className="btn btn-primary btn-lg">
                    ⚡ Launch New Scan
                </Link>
            </div>

            {flows.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-state-icon">🔍</div>
                    <h2 className="empty-state-title">No scans yet</h2>
                    <p className="empty-state-text">
                        Launch your first autonomous penetration test. The AI agent will handle
                        reconnaissance, enumeration, vulnerability scanning, and reporting automatically.
                    </p>
                    <Link to="/new" className="btn btn-primary btn-lg">
                        ⚡ Launch First Scan
                    </Link>
                </div>
            ) : (
                <div className="flow-grid">
                    {flows.map((flow) => (
                        <Link
                            key={flow.id}
                            to={`/flow/${flow.id}`}
                            style={{ textDecoration: 'none' }}
                        >
                            <div className="card flow-card">
                                <div className="card-header">
                                    <h3 className="card-title">{flow.name}</h3>
                                    <span className={getStatusBadge(flow.status)}>
                                        {flow.status}
                                    </span>
                                </div>
                                {flow.description && (
                                    <p className="card-description">
                                        {flow.description.length > 120
                                            ? flow.description.substring(0, 120) + '...'
                                            : flow.description}
                                    </p>
                                )}
                                <div className="card-target">
                                    🎯 {flow.target}
                                </div>
                                <div className="card-meta">
                                    <span>📅 {formatDate(flow.created_at)}</span>
                                    {flow.updated_at && (
                                        <span>🔄 {formatDate(flow.updated_at)}</span>
                                    )}
                                </div>
                            </div>
                        </Link>
                    ))}
                </div>
            )}
        </div>
    )
}

export default Dashboard
