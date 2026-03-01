import React, { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'

const API_BASE = '/api'

function FlowDetail() {
    const { id } = useParams()
    const [flow, setFlow] = useState(null)
    const [events, setEvents] = useState([])
    const [connected, setConnected] = useState(false)
    const [loading, setLoading] = useState(true)
    const eventsEndRef = useRef(null)
    const wsRef = useRef(null)

    useEffect(() => {
        fetchFlow()
        fetchEvents()
        connectWebSocket()

        return () => {
            if (wsRef.current) {
                // Ensure we clean up the websocket fully on unmount or re-render
                wsRef.current.onclose = null; // Prevent reconnect loop on unmount
                wsRef.current.close()
                wsRef.current = null
            }
        }
    }, [id])

    useEffect(() => {
        eventsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [events])

    async function fetchFlow() {
        try {
            const res = await fetch(`${API_BASE}/flows/${id}`)
            if (res.ok) {
                const data = await res.json()
                setFlow(data)
            }
        } catch (err) {
            console.error('Failed to fetch flow:', err)
        } finally {
            setLoading(false)
        }
    }

    async function fetchEvents() {
        try {
            const res = await fetch(`${API_BASE}/flows/${id}/events`)
            if (res.ok) {
                const data = await res.json()
                if (data && Array.isArray(data)) {
                    setEvents(data)
                }
            }
        } catch (err) {
            console.error('Failed to fetch historical events:', err)
        }
    }

    function connectWebSocket() {
        if (wsRef.current) {
            // If one already exists (e.g., React Strict Mode double-render), don't connect again
            return;
        }

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl = `${protocol}//${window.location.host}/ws`

        const ws = new WebSocket(wsUrl)
        wsRef.current = ws

        ws.onopen = () => {
            setConnected(true)
            console.log('WebSocket connected')
        }

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data)
                // Only show events for this flow
                if (data.flow_id === id) {
                    setEvents((prev) => {
                        // Prevent duplicates if fetchEvents and WebSocket overlap
                        const alreadyExists = prev.some(e =>
                            e.timestamp === data.timestamp && e.content === data.content
                        );
                        if (alreadyExists) return prev;
                        return [...prev, data];
                    })

                    // Re-fetch flow status on completion
                    if (data.type === 'complete' || data.type === 'error') {
                        setTimeout(fetchFlow, 1000)
                    }
                }
            } catch (err) {
                console.error('Failed to parse WS message:', err)
            }
        }

        ws.onclose = () => {
            setConnected(false)
            console.log('WebSocket disconnected')
            // Reconnect after 3 seconds
            setTimeout(connectWebSocket, 3000)
        }

        ws.onerror = () => {
            setConnected(false)
        }
    }

    function formatTime(timestamp) {
        if (!timestamp) return ''
        return new Date(timestamp).toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        })
    }

    function getEventIcon(type) {
        const icons = {
            thinking: '🧠',
            tool_call: '🔧',
            tool_result: '📋',
            message: '💬',
            complete: '✅',
            error: '❌',
        }
        return icons[type] || '📌'
    }

    function getEventColor(type) {
        const colors = {
            thinking: 'var(--accent-purple)',
            tool_call: 'var(--accent-cyan)',
            tool_result: 'var(--accent-green)',
            message: 'var(--accent-yellow)',
            complete: 'var(--accent-green)',
            error: 'var(--accent-red)',
        }
        return colors[type] || 'var(--text-secondary)'
    }

    if (loading) {
        return (
            <div className="loading-container">
                <div className="spinner"></div>
                Loading scan details...
            </div>
        )
    }

    if (!flow) {
        return (
            <div className="empty-state">
                <div className="empty-state-icon">⚠️</div>
                <h2 className="empty-state-title">Scan not found</h2>
                <Link to="/" className="btn btn-primary">Back to Dashboard</Link>
            </div>
        )
    }

    const isActive = flow.status === 'active'

    return (
        <div>
            <div className="page-header">
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '4px' }}>
                        <Link to="/" style={{ color: 'var(--text-muted)', textDecoration: 'none', fontSize: '14px' }}>
                            ← Dashboard
                        </Link>
                    </div>
                    <h1 className="page-title">{flow.name}</h1>
                    <p className="page-subtitle">{flow.description}</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span className={`badge badge-${flow.status}`}>{flow.status}</span>
                    <span className={`badge ${connected ? 'badge-active' : 'badge-failed'}`}>
                        {connected ? '● Live' : '○ Offline'}
                    </span>
                </div>
            </div>

            {/* Info Cards */}
            <div className="detail-info">
                <div className="info-item">
                    <div className="info-label">Target</div>
                    <div className="info-value" style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                        {flow.target}
                    </div>
                </div>
                <div className="info-item">
                    <div className="info-label">Status</div>
                    <div className="info-value">{flow.status}</div>
                </div>
                <div className="info-item">
                    <div className="info-label">Started</div>
                    <div className="info-value">{new Date(flow.created_at).toLocaleString()}</div>
                </div>
                <div className="info-item">
                    <div className="info-label">Events</div>
                    <div className="info-value">{events.length}</div>
                </div>
            </div>

            {/* Main content */}
            <div className="detail-grid">
                {/* Terminal / Event Stream */}
                <div>
                    <div className="terminal">
                        <div className="terminal-header">
                            <div className="terminal-dot red"></div>
                            <div className="terminal-dot yellow"></div>
                            <div className="terminal-dot green"></div>
                            <span className="terminal-title">
                                Agent Terminal — {flow.target}
                            </span>
                            {isActive && (
                                <div className="spinner" style={{ width: '14px', height: '14px' }}></div>
                            )}
                        </div>
                        <div className="terminal-body" style={{ height: '600px' }}>
                            {events.length === 0 ? (
                                <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '40px' }}>
                                    {isActive ? (
                                        <>
                                            <div className="spinner" style={{ margin: '0 auto 16px' }}></div>
                                            Waiting for agent to begin...
                                        </>
                                    ) : (
                                        'No events recorded for this scan.'
                                    )}
                                </div>
                            ) : (
                                events.map((event, i) => {
                                    const meta = event.metadata || {}
                                    return (
                                        <div key={i}>
                                            {event.type === 'tool_call' && meta.tool === 'execute_command' && (
                                                <div className="terminal-line cmd">
                                                    {(() => {
                                                        try {
                                                            const args = JSON.parse(meta.args || '{}')
                                                            return args.command || meta.args
                                                        } catch {
                                                            return meta.args
                                                        }
                                                    })()}
                                                </div>
                                            )}
                                            {event.type === 'tool_call' && meta.tool === 'think' && (
                                                <div className="terminal-line thinking">
                                                    {(() => {
                                                        try {
                                                            const args = JSON.parse(meta.args || '{}')
                                                            return `[Thinking] ${args.thought || ''}`
                                                        } catch {
                                                            return `[Thinking] ${meta.args}`
                                                        }
                                                    })()}
                                                </div>
                                            )}
                                            {event.type === 'tool_result' && meta.tool === 'execute_command' && (
                                                <div className="terminal-line output">
                                                    {event.content}
                                                </div>
                                            )}
                                            {event.type === 'tool_result' && meta.tool !== 'execute_command' && (
                                                <div className="terminal-line info">
                                                    {event.content}
                                                </div>
                                            )}
                                            {event.type === 'thinking' && (
                                                <div className="terminal-line thinking">
                                                    {event.content}
                                                </div>
                                            )}
                                            {event.type === 'message' && (
                                                <div className="terminal-line info">
                                                    {event.content}
                                                </div>
                                            )}
                                            {event.type === 'error' && (
                                                <div className="terminal-line error">
                                                    ❌ {event.content}
                                                </div>
                                            )}
                                            {event.type === 'complete' && (
                                                <div className="terminal-line" style={{ color: 'var(--accent-green)' }}>
                                                    ✅ {event.content}
                                                </div>
                                            )}
                                        </div>
                                    )
                                })
                            )}
                            <div ref={eventsEndRef} />
                        </div>
                    </div>
                </div>

                {/* Event Timeline Sidebar */}
                <div>
                    <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '16px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        Event Timeline
                    </h3>
                    <div className="event-log" style={{ height: '600px', overflowY: 'auto' }}>
                        {events.length === 0 ? (
                            <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No events yet...</p>
                        ) : (
                            events.map((event, i) => (
                                <div key={i} className={`event-item ${event.type}`}>
                                    <div>
                                        <span className="event-time">{formatTime(event.timestamp)}</span>
                                    </div>
                                    <div style={{ flex: 1 }}>
                                        <div className="event-type" style={{ color: getEventColor(event.type), marginBottom: '4px' }}>
                                            {getEventIcon(event.type)} {event.type.replace('_', ' ')}
                                        </div>
                                        <div className="event-content">
                                            {event.content.length > 200
                                                ? event.content.substring(0, 200) + '...'
                                                : event.content}
                                            {event.metadata?.tool && (
                                                <span style={{
                                                    display: 'inline-block',
                                                    marginLeft: '8px',
                                                    padding: '2px 8px',
                                                    background: 'var(--bg-input)',
                                                    borderRadius: '4px',
                                                    fontFamily: 'var(--font-mono)',
                                                    fontSize: '11px',
                                                    color: 'var(--accent-cyan)',
                                                }}>
                                                    {event.metadata.tool}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>
        </div>
    )
}

export default FlowDetail
