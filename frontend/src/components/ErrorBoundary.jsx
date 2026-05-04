import { Component } from 'react'

export default class ErrorBoundary extends Component {
    constructor(props) {
        super(props)
        this.state = { hasError: false, error: null }
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error }
    }

    componentDidCatch(error, info) {
        console.error('[ErrorBoundary]', error, info.componentStack)
    }

    render() {
        if (this.state.hasError) {
            const msg = this.state.error?.message || 'Unknown error'
            return (
                <div className="flex flex-col items-center justify-center py-20 px-6 text-center">
                    <div className="relative mb-5">
                        <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-red-500/10 to-red-900/10 border border-red-500/20 flex items-center justify-center shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]">
                            <svg className="w-7 h-7 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                            </svg>
                        </div>
                        <span className="absolute -inset-3 rounded-2xl bg-red-500/[0.06] blur-xl -z-10" />
                    </div>

                    <p className="text-[15px] font-semibold text-red-400 mb-1">Something went wrong</p>
                    <p className="text-[12px] text-text-muted font-mono mb-6 max-w-xs break-all leading-relaxed">{msg}</p>

                    <button
                        type="button"
                        onClick={() => this.setState({ hasError: false, error: null })}
                        className="lg-btn text-[12px] px-4 py-2"
                    >
                        Try again
                    </button>
                </div>
            )
        }
        return this.props.children
    }
}

// Inline motion usage: wrap in a div so component itself stays a class component
// (motion.div cannot be used directly in class render without importing React — handled at call site)
ErrorBoundary.displayName = 'ErrorBoundary'
