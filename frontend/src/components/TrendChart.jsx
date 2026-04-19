import React, { useState, useEffect, useRef } from 'react'

const API_BASE = '/api'

// Severity color mapping
const SEVERITY_COLOR = {
    critical: '#ff4757',
    high: '#ff7f50',
    medium: '#eccc68',
    low: '#2ed573',
    info: '#00d4ff',
}

// Returns the "highest" severity from a list
function maxSeverity(severities) {
    const order = ['critical', 'high', 'medium', 'low', 'info']
    for (const s of order) {
        if (severities.includes(s)) return s
    }
    return 'info'
}

// Format date for axis labels
function fmtDate(dateStr) {
    const d = new Date(dateStr)
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

function TrendChart({ flows }) {
    const [findings, setFindings] = useState([])
    const [tooltip, setTooltip] = useState(null)
    const svgRef = useRef(null)

    useEffect(() => {
        fetch(`${API_BASE}/findings`)
            .then((r) => r.json())
            .then((data) => setFindings(data || []))
            .catch(() => {})
    }, [])

    if (!flows || flows.length === 0) {
        return (
            <div className="flex items-center justify-center h-32 text-text-muted text-sm">
                No scan data to display
            </div>
        )
    }

    // Take the last 10 flows sorted by created_at ascending
    const sorted = [...flows]
        .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
        .slice(-10)

    // Build per-flow stats
    const points = sorted.map((flow) => {
        const flowFindings = findings.filter((f) => f.flowId === flow.id)
        const severities = flowFindings.map((f) => f.severity || 'info')
        return {
            flow,
            count: flowFindings.length,
            severity: maxSeverity(severities),
        }
    })

    // SVG dimensions
    const W = 600
    const H = 180
    const PAD = { top: 16, right: 20, bottom: 40, left: 36 }
    const chartW = W - PAD.left - PAD.right
    const chartH = H - PAD.top - PAD.bottom

    const maxCount = Math.max(...points.map((p) => p.count), 1)

    // Map point index → x coordinate
    const xOf = (i) =>
        points.length === 1
            ? PAD.left + chartW / 2
            : PAD.left + (i / (points.length - 1)) * chartW

    // Map count → y coordinate (inverted, 0 at bottom)
    const yOf = (count) =>
        PAD.top + chartH - (count / maxCount) * chartH

    // Build polyline points string
    const linePoints = points.map((p, i) => `${xOf(i)},${yOf(p.count)}`).join(' ')

    // Y-axis tick values (0 and maxCount)
    const yTicks = [0, Math.ceil(maxCount / 2), maxCount]

    return (
        <div className="relative w-full overflow-x-auto">
            <svg
                ref={svgRef}
                viewBox={`0 0 ${W} ${H}`}
                className="w-full"
                style={{ minWidth: '300px', maxHeight: '200px' }}
                onMouseLeave={() => setTooltip(null)}
            >
                {/* Y-axis gridlines */}
                {yTicks.map((tick) => (
                    <g key={tick}>
                        <line
                            x1={PAD.left}
                            y1={yOf(tick)}
                            x2={PAD.left + chartW}
                            y2={yOf(tick)}
                            stroke="rgba(255,255,255,0.08)"
                            strokeWidth={1}
                        />
                        <text
                            x={PAD.left - 6}
                            y={yOf(tick) + 4}
                            textAnchor="end"
                            fontSize={10}
                            fill="rgba(255,255,255,0.35)"
                            fontFamily="monospace"
                        >
                            {tick}
                        </text>
                    </g>
                ))}

                {/* Gradient fill under line */}
                <defs>
                    <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.25" />
                        <stop offset="100%" stopColor="#00d4ff" stopOpacity="0" />
                    </linearGradient>
                </defs>

                {/* Area fill */}
                {points.length > 1 && (
                    <polygon
                        points={[
                            ...points.map((p, i) => `${xOf(i)},${yOf(p.count)}`),
                            `${xOf(points.length - 1)},${yOf(0)}`,
                            `${xOf(0)},${yOf(0)}`,
                        ].join(' ')}
                        fill="url(#trendFill)"
                    />
                )}

                {/* Line */}
                {points.length > 1 && (
                    <polyline
                        points={linePoints}
                        fill="none"
                        stroke="#00d4ff"
                        strokeWidth={2}
                        strokeLinejoin="round"
                        strokeLinecap="round"
                    />
                )}

                {/* Data points */}
                {points.map((p, i) => {
                    const cx = xOf(i)
                    const cy = yOf(p.count)
                    const color = SEVERITY_COLOR[p.severity] || '#00d4ff'

                    return (
                        <g key={p.flow.id}>
                            {/* Outer glow ring */}
                            <circle cx={cx} cy={cy} r={7} fill={color} opacity={0.2} />
                            {/* Main dot */}
                            <circle
                                cx={cx}
                                cy={cy}
                                r={5}
                                fill={color}
                                stroke="#0f172a"
                                strokeWidth={1.5}
                                style={{ cursor: 'pointer' }}
                                onMouseEnter={(e) => {
                                    setTooltip({
                                        x: cx,
                                        y: cy,
                                        name: p.flow.name,
                                        count: p.count,
                                        severity: p.severity,
                                        date: p.flow.created_at,
                                        color,
                                    })
                                }}
                                onMouseLeave={() => setTooltip(null)}
                            />

                            {/* X-axis label */}
                            <text
                                x={cx}
                                y={H - PAD.bottom + 14}
                                textAnchor="middle"
                                fontSize={9}
                                fill="rgba(255,255,255,0.35)"
                                fontFamily="monospace"
                            >
                                {fmtDate(p.flow.created_at)}
                            </text>
                        </g>
                    )
                })}

                {/* Tooltip */}
                {tooltip && (() => {
                    const tw = 140
                    const th = 56
                    // Flip to left side if near right edge
                    const tx = tooltip.x + tw + 10 > W ? tooltip.x - tw - 10 : tooltip.x + 10
                    const ty = Math.max(PAD.top, Math.min(tooltip.y - th / 2, H - PAD.bottom - th))

                    return (
                        <g>
                            <rect
                                x={tx}
                                y={ty}
                                width={tw}
                                height={th}
                                rx={6}
                                fill="#0f172a"
                                stroke="rgba(255,255,255,0.15)"
                                strokeWidth={1}
                            />
                            <text
                                x={tx + 8}
                                y={ty + 16}
                                fontSize={9}
                                fill="rgba(255,255,255,0.6)"
                                fontFamily="monospace"
                            >
                                {fmtDate(tooltip.date)}
                            </text>
                            <text
                                x={tx + 8}
                                y={ty + 30}
                                fontSize={10}
                                fill="white"
                                fontWeight="bold"
                                fontFamily="sans-serif"
                            >
                                {tooltip.name.length > 18 ? tooltip.name.slice(0, 18) + '…' : tooltip.name}
                            </text>
                            <text
                                x={tx + 8}
                                y={ty + 46}
                                fontSize={10}
                                fill={tooltip.color}
                                fontFamily="monospace"
                            >
                                {tooltip.count} finding{tooltip.count !== 1 ? 's' : ''} · {tooltip.severity}
                            </text>
                        </g>
                    )
                })()}
            </svg>
        </div>
    )
}

export default TrendChart
