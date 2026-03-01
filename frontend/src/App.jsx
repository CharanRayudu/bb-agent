import React from 'react'
import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import NewTask from './pages/NewTask'
import FlowDetail from './pages/FlowDetail'

function Navbar() {
    const location = useLocation()

    return (
        <nav className="navbar">
            <Link to="/" className="navbar-brand">
                <span className="navbar-logo">🛡️</span>
                <div>
                    <div className="navbar-title">Mirage</div>
                    <div className="navbar-subtitle">Autonomous Pentest Agent</div>
                </div>
            </Link>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                <Link
                    to="/"
                    className={`btn btn-sm ${location.pathname === '/' ? 'btn-primary' : 'btn-secondary'}`}
                >
                    📊 Dashboard
                </Link>
                <Link to="/new" className="btn btn-sm btn-primary">
                    ⚡ New Scan
                </Link>
                <div className="navbar-status">
                    <span className="status-dot"></span>
                    System Online
                </div>
            </div>
        </nav>
    )
}

function App() {
    return (
        <BrowserRouter>
            <div className="app-container">
                <Navbar />
                <main className="main-content">
                    <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/new" element={<NewTask />} />
                        <Route path="/flow/:id" element={<FlowDetail />} />
                    </Routes>
                </main>
            </div>
        </BrowserRouter>
    )
}

export default App
