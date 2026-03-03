import React, { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ArrowLeft, Target, Clock, Activity, Cpu, Wrench, MessageSquare, CheckCircle, XCircle, ChevronRight, Terminal } from 'lucide-react'

const API_BASE = '/api'

function FlowDetail() {
    const { id } = useParams()
    const [flow, setFlow] = useState(null)
    const [events, setEvents] = useState([])
    const [connected, setConnected] = useState(false)
    const [loading, setLoading] = useState(true)
    const [stopping, setStopping] = useState(false)
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
        if (wsRef.current) return;

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
                if (data.flow_id === id) {
                    setEvents((prev) => {
                        const alreadyExists = prev.some(e =>
                            e.timestamp === data.timestamp && e.content === data.content
                        );
                        if (alreadyExists) return prev;
                        return [...prev, data];
                    })

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
            setTimeout(connectWebSocket, 3000)
        }

        ws.onerror = () => {
            setConnected(false)
        }
    }

    function formatTime(timestamp) {
        if (!timestamp) return ''
        return new Date(timestamp).toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', second: '2-digit',
        })
    }

    function getEventIcon(type) {
        switch (type) {
            case 'thinking': return <Cpu className="w-4 h-4" />
            case 'tool_call': return <Wrench className="w-4 h-4" />
            case 'tool_result': return <CheckCircle className="w-4 h-4" />
            case 'message': return <MessageSquare className="w-4 h-4" />
            case 'complete': return <CheckCircle className="w-4 h-4" />
            case 'error': return <XCircle className="w-4 h-4" />
            default: return <ChevronRight className="w-4 h-4" />
        }
    }

    function getEventColorClass(type) {
        switch (type) {
            case 'thinking': return 'text-accent-purple'
            case 'tool_call': return 'text-accent-cyan'
            case 'tool_result': return 'text-accent-green'
            case 'message': return 'text-accent-yellow'
            case 'complete': return 'text-accent-green'
            case 'error': return 'text-accent-red'
            default: return 'text-text-secondary'
        }
    }

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
                <div className="w-12 h-12 border-4 border-accent-cyan/20 border-t-accent-cyan rounded-full animate-spin shadow-glow"></div>
                <div className="text-text-muted font-mono tracking-widest animate-pulse">Establishing Telemetry...</div>
            </div>
        )
    }

    if (!flow) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[40vh] p-12 text-center border border-border/50 rounded-2xl bg-card-bg/30 backdrop-blur-sm">
                <div className="w-20 h-20 bg-accent-red/10 border border-accent-red/30 rounded-full flex items-center justify-center mb-6">
                    <XCircle className="w-8 h-8 text-accent-red" />
                </div>
                <h2 className="text-2xl font-bold text-text-primary mb-3">Trace Cannot Be Located</h2>
                <Link to="/" className="btn btn-primary mt-4">Return to HQ</Link>
            </div>
        )
    }

    const isActive = flow.status === 'active' || flow.status === 'running' || flow.status === 'pending'

    async function handleStopScan() {
        if (!confirm('Are you sure you want to stop this scan?')) return;
        setStopping(true);
        try {
            const res = await fetch(`${API_BASE}/flows/${id}/cancel`, { method: 'POST' });
            if (res.ok) {
                // Optimistically update
                setFlow(prev => ({ ...prev, status: 'failed' }));
            }
        } catch (err) {
            console.error('Failed to stop scan:', err);
        } finally {
            setStopping(false);
        }
    }

    return (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="pb-12 max-w-[1600px] mx-auto">
            {/* Header */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-6 border-b border-border/50 pb-6">
                <div>
                    <Link to="/" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-cyan transition-colors mb-4 text-sm font-semibold uppercase tracking-wider relative group">
                        <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" /> Dashboard
                    </Link>
                    <h1 className="text-3xl font-display font-black text-transparent bg-clip-text bg-gradient-to-r from-text-primary to-text-muted mb-2 tracking-tight">
                        {flow.name}
                    </h1>
                    <p className="text-text-muted/80 max-w-2xl text-sm leading-relaxed">{flow.description}</p>
                </div>
                <div className="flex items-center gap-3">
                    <span className={`px-4 py-1.5 rounded-full text-xs font-mono font-bold tracking-widest uppercase border backdrop-blur-md shadow-sm ${isActive ? 'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30 animate-pulse' :
                        flow.status === 'completed' ? 'bg-accent-green/10 text-accent-green border-accent-green/30' :
                            'bg-accent-red/10 text-accent-red border-accent-red/30'
                        }`}>
                        {flow.status}
                    </span>
                    <span className={`flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-mono font-bold tracking-widest uppercase border backdrop-blur-md shadow-sm ${connected ? 'bg-accent-green/10 text-accent-green border-accent-green/30' : 'bg-text-muted/10 text-text-muted border-text-muted/30'
                        }`}>
                        <span className={`w-2 h-2 rounded-full ${connected ? 'bg-accent-green animate-ping' : 'bg-text-muted'}`}></span>
                        {connected ? 'Uplink Live' : 'Offline'}
                    </span>

                    {isActive && (
                        <button
                            onClick={handleStopScan}
                            disabled={stopping}
                            className={`flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-mono font-bold tracking-widest uppercase border backdrop-blur-md shadow-sm transition-all
                                ${stopping ? 'bg-text-muted/10 text-text-muted border-text-muted/30 cursor-not-allowed' : 'bg-accent-red/10 text-accent-red border-accent-red/30 hover:bg-accent-red/20 hover:scale-105'}`}
                        >
                            {stopping ? 'Stopping...' : <><XCircle className="w-3 h-3" /> Stop Scan</>}
                        </button>
                    )}
                </div>
            </div>

            {/* Info Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-card-bg/40 backdrop-blur-sm border border-border rounded-xl p-5 hover:border-accent-cyan/30 transition-colors group">
                    <div className="flex items-center gap-2 text-text-muted mb-2"><Target className="w-4 h-4 text-accent-cyan group-hover:scale-110 transition-transform" /> <span className="text-xs font-bold uppercase tracking-wider">Target Node</span></div>
                    <div className="font-mono text-accent-cyan text-sm sm:text-base font-medium truncate" title={flow.target}>{flow.target}</div>
                </div>
                <div className="bg-card-bg/40 backdrop-blur-sm border border-border rounded-xl p-5 hover:border-accent-cyan/30 transition-colors group">
                    <div className="flex items-center gap-2 text-text-muted mb-2"><Activity className="w-4 h-4 text-accent-purple group-hover:scale-110 transition-transform" /> <span className="text-xs font-bold uppercase tracking-wider">Current State</span></div>
                    <div className="text-text-primary text-sm sm:text-base font-medium capitalize">{flow.status}</div>
                </div>
                <div className="bg-card-bg/40 backdrop-blur-sm border border-border rounded-xl p-5 hover:border-accent-cyan/30 transition-colors group">
                    <div className="flex items-center gap-2 text-text-muted mb-2"><Clock className="w-4 h-4 text-accent-yellow group-hover:scale-110 transition-transform" /> <span className="text-xs font-bold uppercase tracking-wider">Time Initiated</span></div>
                    <div className="text-text-primary text-sm font-medium">{new Date(flow.created_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</div>
                </div>
                <div className="bg-card-bg/40 backdrop-blur-sm border border-border rounded-xl p-5 hover:border-accent-cyan/30 transition-colors group relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-16 h-16 bg-accent-green/10 rounded-full blur-[20px]"></div>
                    <div className="flex items-center gap-2 text-text-muted mb-2 relative z-10"><Terminal className="w-4 h-4 text-accent-green group-hover:scale-110 transition-transform" /> <span className="text-xs font-bold uppercase tracking-wider">Telemetry Events</span></div>
                    <div className="text-text-primary text-2xl font-black relative z-10">{events.length}</div>
                </div>
            </div>

            {/* Main Terminal & Timeline Split */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-8 pb-8">

                {/* 1. Terminal Window */}
                <div className="lg:col-span-2 flex flex-col h-[600px] bg-[#0a0f18] rounded-2xl border border-border/80 shadow-2xl overflow-hidden relative group">
                    {/* Mac-style Terminal Header */}
                    <div className="px-4 py-3 bg-[#111827] border-b border-border/80 flex items-center justify-between sticky top-0 z-10 backdrop-blur-md">
                        <div className="flex items-center gap-2">
                            <div className="w-3 h-3 rounded-full bg-accent-red/80"></div>
                            <div className="w-3 h-3 rounded-full bg-accent-yellow/80"></div>
                            <div className="w-3 h-3 rounded-full bg-accent-green/80"></div>
                        </div>
                        <div className="text-xs font-mono tracking-widest text-text-muted flex items-center gap-2">
                            <Terminal className="w-3 h-3" /> mirage_agent@{flow.target}
                        </div>
                        <div className="w-12 flex justify-end">
                            {isActive && <div className="w-4 h-4 border-2 border-accent-cyan/40 border-t-accent-cyan rounded-full animate-spin"></div>}
                        </div>
                    </div>

                    {/* Terminal Body */}
                    <div className="flex-1 min-h-0 p-5 lg:p-6 overflow-y-auto font-mono text-[13px] leading-relaxed relative scroll-smooth terminal-scrollbar">
                        {/* Glow overlay */}
                        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-accent-cyan/5 blur-[120px] pointer-events-none"></div>

                        {events.length === 0 ? (
                            <div className="h-full flex flex-col items-center justify-center text-text-muted/60">
                                {isActive ? (
                                    <>
                                        <div className="w-8 h-8 border-2 border-accent-cyan/20 border-t-accent-cyan rounded-full animate-spin mb-4 shadow-[0_0_15px_rgba(0,212,255,0.3)]"></div>
                                        <p className="animate-pulse tracking-widest text-xs uppercase">Awaiting secure shell initialization...</p>
                                    </>
                                ) : (
                                    <p>No telemetry recorded for this operation.</p>
                                )}
                            </div>
                        ) : (
                            events.map((event, i) => {
                                const meta = event.metadata || {}
                                return (
                                    <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} key={i} className="mb-4 break-words">
                                        {/* Command Execution */}
                                        {event.type === 'tool_call' && meta.tool === 'execute_command' && (
                                            <div className="text-accent-cyan/90 font-bold flex gap-3">
                                                <span className="text-accent-purple select-none mt-0.5">λ</span>
                                                <span className="whitespace-pre-wrap flex-1">
                                                    {(() => {
                                                        try {
                                                            const args = JSON.parse(meta.args || '{}')
                                                            return args.command || meta.args
                                                        } catch {
                                                            return meta.args
                                                        }
                                                    })()}
                                                </span>
                                            </div>
                                        )}
                                        {/* Agent Thinking */}
                                        {(event.type === 'thinking' || (event.type === 'tool_call' && meta.tool === 'think')) && (
                                            <div className="text-text-muted/70 italic flex gap-3 pl-5 border-l-2 border-text-muted/20 my-2.5">
                                                <Cpu className="w-4 h-4 mt-1 flex-shrink-0 opacity-40 text-accent-purple" />
                                                <span className="whitespace-pre-wrap flex-1">
                                                    {(() => {
                                                        if (event.type === 'tool_call') {
                                                            try {
                                                                const args = JSON.parse(meta.args || '{}')
                                                                return args.thought || meta.args
                                                            } catch { return meta.args }
                                                        }
                                                        return event.content
                                                    })()}
                                                </span>
                                            </div>
                                        )}
                                        {/* Command Result Output */}
                                        {event.type === 'tool_result' && meta.tool === 'execute_command' && (
                                            <div className="text-[#a8b2c2] mt-2 pl-7 whitespace-pre-wrap relative text-xs bg-[#111827]/40 p-3 rounded border border-border/20 shadow-inner">
                                                {event.content}
                                            </div>
                                        )}
                                        {/* Agent Message / System Info */}
                                        {(event.type === 'message' || (event.type === 'tool_result' && meta.tool !== 'execute_command')) && (
                                            <div className="text-accent-yellow/90 bg-accent-yellow/5 px-4 py-3 rounded-lg border border-accent-yellow/10 my-3 whitespace-pre-wrap flex gap-3">
                                                <MessageSquare className="w-4 h-4 flex-shrink-0 mt-0.5" />
                                                <span className="flex-1">{event.content}</span>
                                            </div>
                                        )}
                                        {/* Errors */}
                                        {event.type === 'error' && (
                                            <div className="text-accent-red bg-accent-red/5 px-4 py-3 rounded-lg border border-accent-red/20 my-3 flex gap-3">
                                                <XCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                                                <span className="font-bold flex-1">{event.content}</span>
                                            </div>
                                        )}
                                        {/* Completion */}
                                        {event.type === 'complete' && (
                                            <div className="text-accent-green bg-accent-green/5 px-4 py-3 rounded-lg border border-accent-green/20 mt-6 flex gap-3 shadow-[0_0_15px_rgba(0,230,118,0.1)]">
                                                <CheckCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                                                <span className="font-bold flex-1 text-sm tracking-wide">Execution Finalized: {event.content}</span>
                                            </div>
                                        )}
                                    </motion.div>
                                )
                            })
                        )}
                        {/* Blinking Cursor */}
                        {isActive && (
                            <div className="flex items-center gap-3 text-accent-cyan h-6 mt-3 pl-1">
                                <span className="text-accent-purple select-none mt-0.5 font-bold">λ</span>
                                <div className="w-2.5 h-4 bg-accent-cyan animate-[blink_1s_step-end_infinite] shadow-[0_0_8px_rgba(0,212,255,0.8)]"></div>
                            </div>
                        )}
                        <div ref={eventsEndRef} className="h-8" />
                    </div>
                </div>

                {/* 2. Timeline Sidebar */}
                <div className="flex flex-col h-[600px]">
                    <h3 className="text-sm font-bold text-text-muted tracking-widest uppercase mb-4 flex items-center gap-2">
                        <Activity className="w-4 h-4 text-accent-cyan" /> Event Timeline
                    </h3>
                    <div className="flex-1 min-h-0 bg-card-bg/40 backdrop-blur-sm border border-border rounded-xl p-5 overflow-y-auto timeline-scrollbar relative shadow-xl">
                        {events.length === 0 ? (
                            <div className="h-full flex items-center justify-center text-text-muted text-sm italic py-10">
                                Waiting for signals...
                            </div>
                        ) : (
                            <div className="relative border-l-2 border-border/60 ml-3 space-y-6 pb-4 pt-2">
                                {events.map((event, i) => (
                                    <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} key={i} className="relative pl-6 group">
                                        {/* Timeline Dot */}
                                        <div className={`absolute -left-[7px] top-1.5 w-3 h-3 rounded-full border-2 border-card-bg transition-transform group-hover:scale-125 ${event.type === 'error' ? 'bg-accent-red shadow-[0_0_10px_rgba(255,49,49,0.5)]' : event.type === 'complete' ? 'bg-accent-green shadow-[0_0_10px_rgba(0,230,118,0.5)]' : 'bg-text-muted'}`}></div>

                                        <div className="flex justify-between items-start mb-1.5">
                                            <div className={`flex items-center gap-2 text-xs font-bold uppercase tracking-wider ${getEventColorClass(event.type)}`}>
                                                {getEventIcon(event.type)}
                                                {event.type.replace('_', ' ')}
                                            </div>
                                        </div>

                                        <div className="text-sm text-text-primary/80 leading-relaxed bg-[#111827]/50 rounded border border-border/30 p-2.5 shadow-sm group-hover:border-accent-cyan/20 transition-colors">
                                            {event.content.length > 100 ? event.content.substring(0, 100) + '...' : event.content}

                                            <div className="flex items-center justify-between mt-2 pt-2 border-t border-border/30">
                                                <span className="text-[10px] font-mono text-text-muted/60 tracking-wider">
                                                    {formatTime(event.timestamp)}
                                                </span>
                                                {event.metadata?.tool && (
                                                    <span className="inline-block px-1.5 py-0.5 bg-accent-cyan/10 border border-accent-cyan/20 rounded text-[9px] font-mono text-accent-cyan uppercase tracking-wider">
                                                        {event.metadata.tool}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    </motion.div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>

            </div>
        </motion.div>
    )
}

export default FlowDetail
