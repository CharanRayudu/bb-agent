/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                // ── Core surfaces (DS canonical) ──
                "bg":            "#0a0b0f",
                "surface":       "#111318",
                "card":          "#161b24",
                "card-hover":    "#1a2030",
                "deep":          "#070a0f",

                // Legacy compat aliases
                "primary-bg":    "#0a0b0f",
                "secondary-bg":  "#111318",
                "card-bg":       "#161b24",

                // ── Borders ──
                "border":        "#1e2535",
                "border-muted":  "#162033",
                "border-focus":  "#2d3a52",

                // ── Text (fg1/fg2/fg3 + legacy names) ──
                "fg1":           "#e2e8f0",
                "fg2":           "#8b98b1",
                "fg3":           "#4b5675",
                "text-primary":  "#e2e8f0",
                "text-secondary":"#8b98b1",
                "text-muted":    "#4b5675",

                // ── Accents ──
                "accent-cyan":   "#06b6d4",
                "accent-green":  "#10b981",
                "accent-purple": "#8b5cf6",
                "accent-orange": "#f97316",
                "accent-yellow": "#eab308",
                "accent-red":    "#ef4444",
                "accent-amber":  "#f59e0b",
                "accent-pink":   "#ec4899",
                "accent-blue":   "#3b82f6",

                // ── Severity ──
                "severity-critical": "#ef4444",
                "severity-high":     "#f97316",
                "severity-medium":   "#eab308",
                "severity-low":      "#3b82f6",
                "severity-info":     "#06b6d4",
            },
            fontFamily: {
                "display": ["Inter", "sans-serif"],
                "mono": ["JetBrains Mono", "Fira Code", "monospace"],
            },
            spacing: {
                "sidebar": "220px",
            },
            borderRadius: {
                "xl": "14px",
                "2xl": "20px",
                "3xl": "28px",
                "liquid": "22px",
            },
            backdropBlur: {
                xs: "4px",
                "2xl": "28px",
                "3xl": "40px",
            },
            boxShadow: {
                "liquid": "0 10px 30px rgba(3,6,16,0.50), 0 2px 6px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.14), inset 0 -1px 0 rgba(0,0,0,0.45)",
                "liquid-xl": "0 28px 80px rgba(3,6,16,0.65), 0 4px 12px rgba(0,0,0,0.55), inset 0 1px 0 rgba(255,255,255,0.22), inset 0 -1px 0 rgba(0,0,0,0.55)",
                "halo-cyan": "0 0 0 1px rgba(34,211,238,0.25), 0 0 40px rgba(34,211,238,0.25)",
                "halo-purple": "0 0 0 1px rgba(167,139,250,0.25), 0 0 40px rgba(167,139,250,0.25)",
                "halo-green": "0 0 0 1px rgba(16,185,129,0.25), 0 0 40px rgba(16,185,129,0.25)",
                "inner-top": "inset 0 1px 0 rgba(255,255,255,0.14)",
            },
            backgroundImage: {
                "aurora": "radial-gradient(1100px 800px at 15% -10%, rgba(34,211,238,0.18), transparent 60%), radial-gradient(900px 700px at 90% 10%, rgba(167,139,250,0.18), transparent 55%), radial-gradient(900px 800px at 70% 120%, rgba(16,185,129,0.12), transparent 60%)",
                "noise": "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/></filter><rect width='100%' height='100%' filter='url(%23n)' opacity='0.5'/></svg>\")",
                "liquid-cyan": "linear-gradient(180deg, rgba(255,255,255,0.14), rgba(255,255,255,0.04)), linear-gradient(135deg, rgba(34,211,238,0.55), rgba(167,139,250,0.55))",
            },
            animation: {
                "float": "float 6s ease-in-out infinite",
                "float-soft": "float-soft 8s ease-in-out infinite",
                "glow": "glow 3s ease-in-out infinite alternate",
                "pulse-slow": "pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
                "grid-move": "grid-move 20s linear infinite",
                "fade-in": "fade-in 0.25s ease-out",
                "slide-in-left": "slide-in-left 0.28s cubic-bezier(0.2,0.8,0.2,1)",
                "slide-in-right": "slide-in-right 0.28s cubic-bezier(0.2,0.8,0.2,1)",
                "slide-up": "slide-up 0.25s cubic-bezier(0.2,0.8,0.2,1)",
                "shimmer": "shimmer 2s linear infinite",
                "aurora-drift": "aurora-drift 28s ease-in-out infinite alternate",
                "shine-sweep": "shine-sweep 1.2s ease forwards",
                "ring-spin": "ring-spin 12s linear infinite",
                "gradient-pan": "gradient-pan 12s ease infinite",
            },
            keyframes: {
                float: {
                    "0%, 100%": { transform: "translateY(0)" },
                    "50%": { transform: "translateY(-10px)" },
                },
                "float-soft": {
                    "0%, 100%": { transform: "translateY(0) translateX(0)" },
                    "50%": { transform: "translateY(-8px) translateX(4px)" },
                },
                glow: {
                    "0%": { filter: "drop-shadow(0 0 10px rgba(34,211,238,0.2))" },
                    "100%": { filter: "drop-shadow(0 0 30px rgba(34,211,238,0.6))" },
                },
                "grid-move": {
                    "0%": { backgroundPosition: "0 0" },
                    "100%": { backgroundPosition: "50px 50px" },
                },
                "fade-in": {
                    "0%": { opacity: "0" },
                    "100%": { opacity: "1" },
                },
                "slide-in-left": {
                    "0%": { opacity: "0", transform: "translateX(-12px)" },
                    "100%": { opacity: "1", transform: "translateX(0)" },
                },
                "slide-in-right": {
                    "0%": { opacity: "0", transform: "translateX(12px)" },
                    "100%": { opacity: "1", transform: "translateX(0)" },
                },
                "slide-up": {
                    "0%": { opacity: "0", transform: "translateY(8px)" },
                    "100%": { opacity: "1", transform: "translateY(0)" },
                },
                shimmer: {
                    "0%": { backgroundPosition: "-200% 0" },
                    "100%": { backgroundPosition: "200% 0" },
                },
                "aurora-drift": {
                    "0%": { transform: "translate3d(0,0,0) rotate(0deg)" },
                    "50%": { transform: "translate3d(-4%,2%,0) rotate(8deg)" },
                    "100%": { transform: "translate3d(3%,-3%,0) rotate(-6deg)" },
                },
                "shine-sweep": {
                    "from": { transform: "translateX(-120%)" },
                    "to": { transform: "translateX(120%)" },
                },
                "ring-spin": {
                    "to": { transform: "rotate(1turn)" },
                },
                "gradient-pan": {
                    "0%": { backgroundPosition: "0% 50%" },
                    "50%": { backgroundPosition: "100% 50%" },
                    "100%": { backgroundPosition: "0% 50%" },
                },
            },
        },
    },
    plugins: [],
}
