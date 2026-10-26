import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  KeyRound, 
  Network, 
  Layers, 
  Cpu, 
  Radio, 
  Flame, 
  Activity,
  Terminal,
  RefreshCw
} from 'lucide-react';

import OverviewConsole from './components/OverviewConsole';
import AegisCryptConsole from './components/AegisCryptConsole';
import NexusTunnelConsole from './components/NexusTunnelConsole';
import CitadelConsole from './components/CitadelConsole';

export default function App() {
  const [activeConsole, setActiveConsole] = useState('overview'); // overview, project1, project2, project3

  // Backend Live Health States
  const [p1Live, setP1Live] = useState(false);
  const [p2Live, setP2Live] = useState(false);
  const [p3Live, setP3Live] = useState(false);

  const pollBackendHealth = async () => {
    // Project 1: AegisCrypt (5101)
    try {
      const r1 = await fetch('/p1/health');
      setP1Live(r1.ok);
    } catch {
      setP1Live(false);
    }
    // Project 2: NexusTunnel (5102)
    try {
      const r2 = await fetch('/p2/health');
      setP2Live(r2.ok);
    } catch {
      setP2Live(false);
    }
    // Project 3: Citadel Defense (5103)
    try {
      const r3 = await fetch('/p3/health');
      setP3Live(r3.ok);
    } catch {
      setP3Live(false);
    }
  };

  useEffect(() => {
    pollBackendHealth();
    const interval = setInterval(pollBackendHealth, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="aegis-app">
      {/* HUD Header */}
      <header className="command-header">
        <div className="command-header-inner">
          {/* Brand Identity */}
          <div className="brand-wrapper">
            <div className="brand-icon-hex">
              <ShieldCheck size={26} />
            </div>
            <div className="brand-meta">
              <div className="brand-title">
                AEGIS//OPS
                <span className="brand-tag">v2.4-V</span>
              </div>
              <div className="brand-sub">
                Applied Cyber Defense & Cryptography Suite • ALM-2
              </div>
            </div>
          </div>

          {/* Master Segmented Console Switcher */}
          <nav className="deck-navigation">
            <button 
              className={`deck-nav-btn ${activeConsole === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveConsole('overview')}
            >
              <Layers size={16} /> Overview
            </button>
            <button 
              className={`deck-nav-btn p1 ${activeConsole === 'project1' ? 'active' : ''}`}
              onClick={() => setActiveConsole('project1')}
            >
              <KeyRound size={16} /> Project 1: AegisCrypt
            </button>
            <button 
              className={`deck-nav-btn p2 ${activeConsole === 'project2' ? 'active' : ''}`}
              onClick={() => setActiveConsole('project2')}
            >
              <Network size={16} /> Project 2: NexusTunnel
            </button>
            <button 
              className={`deck-nav-btn p3 ${activeConsole === 'project3' ? 'active' : ''}`}
              onClick={() => setActiveConsole('project3')}
            >
              <ShieldCheck size={16} /> Project 3: Citadel
            </button>
          </nav>

          {/* Telemetry Cluster */}
          <div className="telemetry-cluster">
            <div className="telemetry-chip" title="AegisCrypt REST API (Port 5101)">
              <span className={`pulse-node ${p1Live ? 'online' : 'offline'}`} />
              <span>P1: 5101</span>
            </div>
            <div className="telemetry-chip" title="NexusTunnel REST API (Port 5102)">
              <span className={`pulse-node ${p2Live ? 'online' : 'offline'}`} />
              <span>P2: 5102</span>
            </div>
            <div className="telemetry-chip" title="Citadel Defense REST API (Port 5103)">
              <span className={`pulse-node ${p3Live ? 'online' : 'offline'}`} />
              <span>P3: 5103</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Console Viewport */}
      <main className="console-viewport">
        {activeConsole === 'overview' && (
          <OverviewConsole 
            onNavigate={(dest) => setActiveConsole(dest)}
            p1Online={p1Live}
            p2Online={p2Live}
            p3Online={p3Live}
          />
        )}

        {activeConsole === 'project1' && <AegisCryptConsole />}

        {activeConsole === 'project2' && <NexusTunnelConsole />}

        {activeConsole === 'project3' && <CitadelConsole />}
      </main>

      {/* Footer */}
      <footer className="master-footer">
        <div>
          <strong>AegisOps Cybersecurity Suite (ALM-2)</strong> • Built with React 19, Vite, and Flask Microservices
        </div>
        <div style={{ marginTop: '0.25rem', color: '#64748b', fontSize: '0.74rem' }}>
          All 3 Project Backends running independently on ports 5001, 5002, 5003 • Unified Port 3000
        </div>
      </footer>
    </div>
  );
}
