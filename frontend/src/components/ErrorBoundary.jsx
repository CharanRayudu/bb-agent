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
            return (
                <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
                    <div className="w-12 h-12 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center mb-4">
                        <span className="text-red-400 text-xl font-bold">!</span>
                    </div>
                    <p className="text-[13px] font-semibold text-red-400 mb-1">Component crashed</p>
                    <p className="text-[11px] text-[#4b5675] mb-4 font-mono max-w-sm break-all">
                        {this.state.error?.message || 'Unknown error'}
                    </p>
                    <button
                        type="button"
                        onClick={() => this.setState({ hasError: false, error: null })}
                        className="px-3 py-1.5 text-[11px] font-mono bg-[#1e2535] border border-[#2d3a52] text-[#8b98b1] rounded hover:text-white hover:border-cyan-500/40 transition-colors"
                    >
                        Retry
                    </button>
                </div>
            )
        }
        return this.props.children
    }
}
