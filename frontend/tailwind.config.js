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
                // New design system palette
                "bg": "#0a0b0f",
                "surface": "#111318",
                "card": "#161b24",
                "border": "#1e2535",
                "border-muted": "#162033",

                // Legacy compat
                "primary-bg": "#0a0b0f",
                "secondary-bg": "#111318",
                "card-bg": "#161b24",
                "card-hover": "#1e2535",

                // Text
                "text-primary": "#e2e8f0",
                "text-secondary": "#8b98b1",
                "text-muted": "#4b5675",

                // Accents
                "accent-cyan": "#06b6d4",
                "accent-green": "#10b981",
                "accent-purple": "#8b5cf6",
                "accent-orange": "#f97316",
                "accent-yellow": "#eab308",
                "accent-red": "#ef4444",
                "accent-amber": "#f59e0b",
                "accent-pink": "#ec4899",

                // Severity
                "severity-critical": "#ef4444",
                "severity-high": "#f97316",
                "severity-medium": "#eab308",
                "severity-low": "#3b82f6",
                "severity-info": "#06b6d4",
            },
            fontFamily: {
                "display": ["Inter", "sans-serif"],
                "mono": ["JetBrains Mono", "Fira Code", "monospace"],
            },
            spacing: {
                "sidebar": "220px",
            },
            animation: {
                "float": "float 6s ease-in-out infinite",
                "glow": "glow 3s ease-in-out infinite alternate",
                "pulse-slow": "pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
                "grid-move": "grid-move 20s linear infinite",
                "fade-in": "fade-in 0.2s ease-out",
                "slide-in-left": "slide-in-left 0.25s ease-out",
                "slide-in-right": "slide-in-right 0.25s ease-out",
                "slide-up": "slide-up 0.2s ease-out",
                "shimmer": "shimmer 2s linear infinite",
            },
            keyframes: {
                float: {
                    "0%, 100%": { transform: "translateY(0)" },
                    "50%": { transform: "translateY(-10px)" },
                },
                glow: {
                    "0%": { filter: "drop-shadow(0 0 10px rgba(6,182,212,0.2))" },
                    "100%": { filter: "drop-shadow(0 0 30px rgba(6,182,212,0.6))" },
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
            },
        },
    },
    plugins: [],
}
