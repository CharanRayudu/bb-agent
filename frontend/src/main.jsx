import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

const nativeFetch = window.fetch.bind(window)

window.fetch = (input, init = {}) => {
    const token = window.localStorage?.getItem('mirage_token')
    const url = typeof input === 'string' ? input : input?.url
    const apiOrigin = `${window.location.origin}/api`
    const isMirageAPI = typeof url === 'string' && (url.startsWith('/api') || url.startsWith(apiOrigin))

    if (!token || !isMirageAPI) {
        return nativeFetch(input, init)
    }

    const requestHeaders = typeof input !== 'string' ? input.headers : undefined
    const headers = new Headers(init.headers || requestHeaders || {})
    if (!headers.has('Authorization')) {
        headers.set('Authorization', `Bearer ${token}`)
    }

    return nativeFetch(input, { ...init, headers })
}

ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
        <App />
    </React.StrictMode>,
)
