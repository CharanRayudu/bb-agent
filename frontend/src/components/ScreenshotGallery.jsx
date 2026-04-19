import React, { useState, useEffect, useCallback } from 'react'
import { Camera, X, ExternalLink, Loader, Image } from 'lucide-react'

const API_BASE = '/api'

function ScreenshotGallery({ flowId }) {
    const [screenshots, setScreenshots] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [modal, setModal] = useState(null) // { id, url, title, captured_at, imgSrc }
    const [modalLoading, setModalLoading] = useState(false)
    const [captureUrl, setCaptureUrl] = useState('')
    const [captureTitle, setCaptureTitle] = useState('')
    const [capturing, setCapturing] = useState(false)
    const [captureError, setCaptureError] = useState(null)

    const fetchScreenshots = useCallback(() => {
        setLoading(true)
        fetch(`${API_BASE}/flows/${flowId}/screenshots`)
            .then((r) => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`)
                return r.json()
            })
            .then((data) => {
                setScreenshots(data || [])
                setError(null)
            })
            .catch((err) => {
                setError(err.message || 'Failed to load screenshots')
            })
            .finally(() => setLoading(false))
    }, [flowId])

    useEffect(() => {
        fetchScreenshots()
    }, [fetchScreenshots])

    async function openModal(shot) {
        // Revoke previous blob URL to free memory
        setModal((prev) => {
            if (prev?.imgSrc?.startsWith('blob:')) URL.revokeObjectURL(prev.imgSrc)
            return { ...shot, imgSrc: null }
        })
        setModalLoading(true)
        try {
            const res = await fetch(`${API_BASE}/flows/${flowId}/screenshots/${shot.id}`)
            if (!res.ok) throw new Error(`HTTP ${res.status}`)
            const blob = await res.blob()
            // Use blob URL instead of base64 data URI — avoids large string allocation
            const blobUrl = URL.createObjectURL(blob)
            setModal((prev) => prev && { ...prev, imgSrc: blobUrl })
        } catch (err) {
            console.error('Failed to load screenshot:', err)
        } finally {
            setModalLoading(false)
        }
    }

    async function handleCapture(e) {
        e.preventDefault()
        if (!captureUrl.trim()) return
        setCaptureError(null)
        setCapturing(true)

        try {
            const res = await fetch(`${API_BASE}/flows/${flowId}/screenshots/capture`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: captureUrl.trim(), title: captureTitle.trim() || captureUrl.trim() }),
            })
            if (!res.ok) {
                const text = await res.text()
                throw new Error(text || `HTTP ${res.status}`)
            }
            const newShot = await res.json()
            setScreenshots((prev) => [newShot, ...prev])
            setCaptureUrl('')
            setCaptureTitle('')
        } catch (err) {
            setCaptureError(err.message || 'Capture failed')
        } finally {
            setCapturing(false)
        }
    }

    function formatDate(dateStr) {
        return new Date(dateStr).toLocaleString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
        })
    }

    return (
        <div className="space-y-6">
            {/* Capture form */}
            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                <div className="flex items-center gap-2 mb-3">
                    <Camera className="w-4 h-4 text-accent-cyan" />
                    <span className="text-xs font-mono font-bold uppercase tracking-widest text-text-muted">Capture Screenshot</span>
                </div>
                <form onSubmit={handleCapture} className="flex flex-col sm:flex-row gap-2">
                    <input
                        type="url"
                        placeholder="https://target.example.com/page"
                        value={captureUrl}
                        onChange={(e) => setCaptureUrl(e.target.value)}
                        required
                        className="flex-1 min-w-0 bg-white/8 border border-white/15 rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted/50 focus:outline-none focus:border-accent-cyan/50 font-mono"
                    />
                    <input
                        type="text"
                        placeholder="Title (optional)"
                        value={captureTitle}
                        onChange={(e) => setCaptureTitle(e.target.value)}
                        className="sm:w-48 bg-white/8 border border-white/15 rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted/50 focus:outline-none focus:border-accent-cyan/50"
                    />
                    <button
                        type="submit"
                        disabled={capturing || !captureUrl.trim()}
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-accent-cyan/20 border border-accent-cyan/40 text-accent-cyan text-sm font-semibold hover:bg-accent-cyan/30 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                        {capturing ? (
                            <Loader className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                            <Camera className="w-3.5 h-3.5" />
                        )}
                        {capturing ? 'Capturing…' : 'Capture'}
                    </button>
                </form>
                {captureError && (
                    <p className="mt-2 text-xs text-accent-red font-mono">{captureError}</p>
                )}
            </div>

            {/* Gallery */}
            {loading ? (
                <div className="flex items-center justify-center h-32 text-text-muted text-sm gap-2">
                    <Loader className="w-4 h-4 animate-spin" />
                    Loading screenshots…
                </div>
            ) : error ? (
                <div className="rounded-xl border border-accent-red/30 bg-accent-red/10 px-4 py-3 text-sm text-accent-red font-mono">
                    {error}
                </div>
            ) : screenshots.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-40 text-text-muted gap-3 rounded-xl border border-white/8 bg-white/3">
                    <Image className="w-8 h-8 opacity-40" />
                    <span className="text-sm">No screenshots captured yet</span>
                </div>
            ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    {screenshots.map((shot) => (
                        <button
                            key={shot.id}
                            type="button"
                            onClick={() => openModal(shot)}
                            className="group text-left rounded-xl border border-white/10 bg-white/5 p-3 hover:border-accent-cyan/40 hover:bg-white/8 transition-all"
                        >
                            <div className="flex items-start justify-between gap-2 mb-2">
                                <span className="text-xs font-semibold text-text-primary line-clamp-2 leading-snug">
                                    {shot.title || shot.url}
                                </span>
                                <ExternalLink className="w-3.5 h-3.5 flex-shrink-0 text-text-muted/40 group-hover:text-accent-cyan/60 transition-colors mt-0.5" />
                            </div>
                            <p className="text-[10px] font-mono text-text-muted/60 truncate mb-2">{shot.url}</p>
                            <p className="text-[10px] font-mono text-text-muted/40">{formatDate(shot.captured_at)}</p>
                        </button>
                    ))}
                </div>
            )}

            {/* Full-size modal */}
            {modal && (
                <div
                    className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
                    onClick={() => {
                        if (modal?.imgSrc?.startsWith('blob:')) URL.revokeObjectURL(modal.imgSrc)
                        setModal(null)
                    }}
                >
                    <div
                        className="relative max-w-5xl w-full max-h-[90vh] overflow-auto rounded-2xl border border-white/15 bg-[#0b1121] shadow-[0_20px_80px_rgba(0,0,0,0.9)]"
                        onClick={(e) => e.stopPropagation()}
                    >
                        {/* Modal header */}
                        <div className="flex items-center justify-between px-5 py-3 border-b border-white/10 bg-white/5">
                            <div className="min-w-0">
                                <p className="text-sm font-semibold text-text-primary truncate">{modal.title || modal.url}</p>
                                <p className="text-[10px] font-mono text-text-muted/60 truncate">{modal.url}</p>
                            </div>
                            <button
                                type="button"
                                onClick={() => {
                                    if (modal?.imgSrc?.startsWith('blob:')) URL.revokeObjectURL(modal.imgSrc)
                                    setModal(null)
                                }}
                                className="flex-shrink-0 ml-3 p-1.5 rounded-lg hover:bg-white/10 text-text-muted hover:text-text-primary transition-colors"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        </div>

                        {/* Modal body */}
                        <div className="p-4">
                            {modalLoading ? (
                                <div className="flex items-center justify-center h-64 gap-2 text-text-muted text-sm">
                                    <Loader className="w-5 h-5 animate-spin" />
                                    Loading image…
                                </div>
                            ) : modal.imgSrc ? (
                                <img
                                    src={modal.imgSrc}
                                    alt={modal.title || modal.url}
                                    className="w-full h-auto rounded-lg shadow-lg"
                                />
                            ) : (
                                <div className="flex items-center justify-center h-64 text-text-muted text-sm">
                                    Failed to load image
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}

export default ScreenshotGallery
