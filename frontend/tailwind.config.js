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
                "primary-bg": "#0a0e1a",
                "secondary-bg": "#111827",
                "card-bg": "#151d2e",
                "card-hover": "#1c2640",
                "accent-cyan": "#00d4ff",
                "accent-green": "#00e676",
                "accent-purple": "#a855f7",
                "text-primary": "#e8ecf4",
                "text-muted": "#8896b3",
            },
            fontFamily: {
                "display": ["Inter", "sans-serif"],
                "mono": ["JetBrains Mono", "monospace"]
            },
            animation: {
                "float": "float 6s ease-in-out infinite",
                "glow": "glow 3s ease-in-out infinite alternate",
                "pulse-slow": "pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
                "grid-move": "grid-move 20s linear infinite",
            },
            keyframes: {
                float: {
                    "0%, 100%": { transform: "translateY(0)" },
                    "50%": { transform: "translateY(-10px)" },
                },
                glow: {
                    "0%": { filter: "drop-shadow(0 0 10px rgba(0,212,255,0.2))" },
                    "100%": { filter: "drop-shadow(0 0 30px rgba(0,212,255,0.6))" },
                },
                "grid-move": {
                    "0%": { backgroundPosition: "0 0" },
                    "100%": { backgroundPosition: "50px 50px" },
                }
            }
        },
    },
    plugins: [],
}
