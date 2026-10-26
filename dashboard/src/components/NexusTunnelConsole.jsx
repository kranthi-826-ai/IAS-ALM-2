import React, { useState } from 'react';
import { 
  Network, 
  Lock, 
  Terminal, 
  Layers, 
  CheckCircle2, 
  ArrowRight, 
  RefreshCw, 
  Send, 
  Key, 
  ShieldCheck, 
  Radio, 
  FileCode2,
  Cpu
} from 'lucide-react';

const API_ROOT = '/p2';

export default function NexusTunnelConsole() {
  const [activeTab, setActiveTab] = useState('tls'); // tls, ssh, ipsec

  // ---------------- TLS State ----------------
  const [tlsSessionId, setTlsSessionId] = useState('');
  const [tlsStep, setTlsStep] = useState(0);
  const [tlsLogs, setTlsLogs] = useState([]);
  const [tlsChosenCipher, setTlsChosenCipher] = useState('TLS_AES_128_GCM_SHA256');
  const [tlsDataInput, setTlsDataInput] = useState('GET /telemetry/defense HTTP/1.1\r\nHost: aegis.internal\r\n\r\n');
  const [tlsDataResponse, setTlsDataResponse] = useState(null);
  const [tlsLoading, setTlsLoading] = useState(false);

  // ---------------- SSH State ----------------
  const [sshSessionId, setSshSessionId] = useState('');
  const [sshStep, setSshStep] = useState(0);
  const [sshLogs, setSshLogs] = useState([]);
  const [sshUser, setSshUser] = useState('v_officer');
  const [sshLoading, setSshLoading] = useState(false);

  // ---------------- IPsec State ----------------
  const [ipsecMode, setIpsecMode] = useState('transport'); // transport or tunnel
  const [ipsecPayload, setIpsecPayload] = useState('TOP_SECRET_DEFENSE_TELEMETRY');
  const [ipsecAnalysis, setIpsecAnalysis] = useState(null);
  const [ipsecLoading, setIpsecLoading] = useState(false);

  // TLS Handshake Methods
  const initTlsSession = async () => {
    setTlsLoading(true);
    setTlsLogs([]);
    setTlsDataResponse(null);
    try {
      const res = await fetch(`${API_ROOT}/api/tls/init`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setTlsSessionId(data.session_id);
        setTlsStep(0);
      }
    } finally {
      setTlsLoading(false);
    }
  };

  const advanceTlsStep = async (stepNum) => {
    if (!tlsSessionId) return;
    setTlsLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/tls/step/${stepNum}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: tlsSessionId,
          cipher_suite: tlsChosenCipher
        })
      });
      if (res.ok) {
        const logEntry = await res.json();
        setTlsLogs(prev => [...prev.filter(l => l.step !== stepNum), logEntry]);
        setTlsStep(stepNum);
      }
    } finally {
      setTlsLoading(false);
    }
  };

  const transmitTlsData = async () => {
    if (!tlsSessionId || tlsStep < 5) return;
    setTlsLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/tls/send-data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: tlsSessionId,
          message: tlsDataInput
        })
      });
      if (res.ok) {
        const result = await res.json();
        setTlsDataResponse(result);
      }
    } finally {
      setTlsLoading(false);
    }
  };

  // SSH Handshake Methods
  const initSshSession = async () => {
    setSshLoading(true);
    setSshLogs([]);
    try {
      const res = await fetch(`${API_ROOT}/api/ssh/init`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setSshSessionId(data.session_id);
        setSshStep(0);
      }
    } finally {
      setSshLoading(false);
    }
  };

  const advanceSshStep = async (stepNum) => {
    if (!sshSessionId) return;
    setSshLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/ssh/step/${stepNum}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sshSessionId,
          username: sshUser,
          auth_method: 'publickey'
        })
      });
      if (res.ok) {
        const logEntry = await res.json();
        setSshLogs(prev => [...prev.filter(l => l.step !== stepNum), logEntry]);
        setSshStep(stepNum);
      }
    } finally {
      setSshLoading(false);
    }
  };

  // IPsec Dissection
  const analyzeIpsec = async (mode) => {
    setIpsecLoading(true);
    setIpsecMode(mode);
    try {
      const res = await fetch(`${API_ROOT}/api/ipsec/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: mode,
          payload: ipsecPayload,
          src_ip: '192.168.1.105',
          dst_ip: '203.0.113.50',
          gateway_src: '198.51.100.1',
          gateway_dst: '203.0.113.1'
        })
      });
      if (res.ok) {
        const data = await res.json();
        setIpsecAnalysis(data);
      }
    } finally {
      setIpsecLoading(false);
    }
  };

  return (
    <div className="nexustunnel-console">
      {/* Subnav */}
      <div className="subnav-tabs">
        <button 
          className={`subnav-pill ${activeTab === 'tls' ? 'active' : ''}`}
          onClick={() => setActiveTab('tls')}
        >
          <Network size={16} /> TLS/SSL 1.2/1.3 Handshake Pipeline
        </button>
        <button 
          className={`subnav-pill ${activeTab === 'ssh' ? 'active' : ''}`}
          onClick={() => setActiveTab('ssh')}
        >
          <Terminal size={16} /> SSH-2.0 Protocol Negotiation
        </button>
        <button 
          className={`subnav-pill ${activeTab === 'ipsec' ? 'active' : ''}`}
          onClick={() => { setActiveTab('ipsec'); if (!ipsecAnalysis) analyzeIpsec(ipsecMode); }}
        >
          <Layers size={16} /> IPsec ESP Packet Encapsulation
        </button>
      </div>

      {/* 1. TLS/SSL HANDSHAKE */}
      {activeTab === 'tls' && (
        <div>
          <div className="deck-card" style={{ marginBottom: '1.5rem' }}>
            <div className="card-heading">
              <div className="card-title-group">
                <Network size={20} color="#8b5cf6" />
                <div>
                  <div className="card-title">TLS 1.2/1.3 Handshake Controller</div>
                  <div className="card-subtitle">Stateful asymmetric key exchange, PRF expansion, and authenticated channel</div>
                </div>
              </div>
              <button className="btn-secondary" onClick={initTlsSession} disabled={tlsLoading} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                <RefreshCw size={13} /> {tlsSessionId ? "Reset Session" : "Initialize TLS Session"}
              </button>
            </div>

            {tlsSessionId ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span className="tag-badge info">SESSION: {tlsSessionId}</span>
                  <span className={`tag-badge ${tlsStep === 5 ? 'success' : 'warning'}`}>
                    {tlsStep === 5 ? 'TUNNEL ESTABLISHED' : `PHASE ${tlsStep} / 5`}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Cipher Suite:</label>
                  <select 
                    className="select-box" 
                    style={{ width: 'auto', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                    value={tlsChosenCipher}
                    onChange={(e) => setTlsChosenCipher(e.target.value)}
                    disabled={tlsStep > 1}
                  >
                    <option value="TLS_AES_128_GCM_SHA256">TLS_AES_128_GCM_SHA256 (AEAD)</option>
                    <option value="TLS_AES_256_GCM_SHA384">TLS_AES_256_GCM_SHA384 (AEAD)</option>
                    <option value="TLS_RSA_WITH_AES_128_CBC_SHA256">TLS_RSA_WITH_AES_128_CBC_SHA256</option>
                  </select>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Click <strong>"Initialize TLS Session"</strong> to begin the 5-step handshake.
              </div>
            )}
          </div>

          {/* Stepper Node Flow */}
          {tlsSessionId && (
            <div className="steps-timeline">
              {[
                { s: 1, title: "1. Client Hello" },
                { s: 2, title: "2. Server Hello & Cert" },
                { s: 3, title: "3. Client Key Exchange" },
                { s: 4, title: "4. PRF Session Keys" },
                { s: 5, title: "5. Finished Verification" }
              ].map(({ s, title }) => (
                <div 
                  key={s}
                  className={`step-node ${tlsStep === s ? 'active' : ''} ${tlsStep >= s ? 'completed' : ''}`}
                  onClick={() => advanceTlsStep(s)}
                >
                  <div className="step-node-num">STEP 0{s}</div>
                  <div className="step-node-title">{title}</div>
                </div>
              ))}
            </div>
          )}

          {/* Handshake Transcript & Symmetric Transmission */}
          <div className="cards-grid">
            {/* Transcript Logs */}
            <div className="deck-card">
              <div className="card-heading">
                <div className="card-title-group">
                  <Terminal size={18} color="#6366f1" />
                  <div className="card-title">Handshake Transcript & Verification</div>
                </div>
                {tlsStep < 5 && tlsSessionId && (
                  <button className="btn-primary" onClick={() => advanceTlsStep(tlsStep + 1)} disabled={tlsLoading} style={{ fontSize: '0.78rem', padding: '0.35rem 0.8rem' }}>
                    Advance Step {tlsStep + 1} <ArrowRight size={14} />
                  </button>
                )}
              </div>

              {tlsLogs.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', maxHeight: '380px', overflowY: 'auto' }}>
                  {tlsLogs.map((log) => (
                    <div key={log.step} style={{ background: '#090d18', border: '1px solid #1a243a', padding: '0.85rem', borderRadius: '8px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                        <span style={{ fontWeight: 700, color: '#a5b4fc', fontSize: '0.85rem' }}>
                          Step {log.step}: {log.name}
                        </span>
                        <span className="tag-badge info" style={{ fontSize: '0.65rem' }}>{log.direction}</span>
                      </div>
                      <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>{log.explanation}</p>
                      <pre className="code-display" style={{ maxHeight: '90px', fontSize: '0.72rem' }}>
                        {JSON.stringify(log.details, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                  Initialize the session and advance through steps to inspect packet payloads.
                </div>
              )}
            </div>

            {/* Symmetric Tunnel Transmission */}
            <div className="deck-card">
              <div className="card-heading">
                <div className="card-title-group">
                  <Lock size={18} color="#10b981" />
                  <div>
                    <div className="card-title">AES-128-GCM Symmetric Tunnel</div>
                    <div className="card-subtitle">Application data transmission over established TLS channel</div>
                  </div>
                </div>
              </div>

              <div className="field-group">
                <label className="field-label">Application Data Payload (HTTP/API)</label>
                <textarea 
                  className="textarea-box" 
                  value={tlsDataInput} 
                  onChange={(e) => setTlsDataInput(e.target.value)} 
                  rows={3}
                  disabled={tlsStep < 5}
                />
              </div>

              <button 
                className="btn-primary" 
                style={{ width: '100%', background: tlsStep === 5 ? 'linear-gradient(135deg, #059669, #10b981)' : undefined }}
                onClick={transmitTlsData} 
                disabled={tlsStep < 5 || tlsLoading}
              >
                <Send size={15} /> Encrypt & Transmit over TLS Tunnel
              </button>

              {tlsStep < 5 && (
                <div style={{ marginTop: '0.85rem', fontSize: '0.78rem', color: 'var(--text-muted)', textAlign: 'center' }}>
                  Complete Handshake Steps 1–5 to activate symmetric tunnel encryption.
                </div>
              )}

              {tlsDataResponse && (
                <div style={{ marginTop: '1.25rem', padding: '1rem', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px' }}>
                  <div style={{ fontWeight: 700, color: '#34d399', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                    ✓ Symmetrically Transmitted (Cipher: {tlsDataResponse.cipher})
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                    <strong>Ciphertext Hex:</strong>
                  </div>
                  <pre className="code-display" style={{ maxHeight: '60px', marginBottom: '0.5rem' }}>
                    {tlsDataResponse.symmetric_ciphertext_hex}
                  </pre>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.74rem' }}>
                    <div><strong>GCM Auth Tag:</strong> <code>{tlsDataResponse.authentication_tag_hex}</code></div>
                    <div><strong>IV Nonce:</strong> <code>{tlsDataResponse.iv_nonce_hex}</code></div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 2. SSH-2.0 SIMULATION */}
      {activeTab === 'ssh' && (
        <div>
          <div className="deck-card" style={{ marginBottom: '1.5rem' }}>
            <div className="card-heading">
              <div className="card-title-group">
                <Terminal size={20} color="#8b5cf6" />
                <div>
                  <div className="card-title">SSH-2.0 Protocol Negotiation Engine</div>
                  <div className="card-subtitle">Version exchange, DH group key agreement, host signature verification, and PTY shell</div>
                </div>
              </div>
              <button className="btn-secondary" onClick={initSshSession} disabled={sshLoading} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                <RefreshCw size={13} /> {sshSessionId ? "Reset Session" : "Initialize SSH Session"}
              </button>
            </div>

            {sshSessionId && (
              <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                <span className="tag-badge info">SSH SESSION: {sshSessionId}</span>
                <span className={`tag-badge ${sshStep === 5 ? 'success' : 'warning'}`}>
                  {sshStep === 5 ? 'SHELL ACTIVE' : `STEP ${sshStep} / 5`}
                </span>
                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>User:</label>
                  <input className="input-box" style={{ width: '130px', padding: '0.3rem 0.6rem', fontSize: '0.78rem' }} value={sshUser} onChange={(e) => setSshUser(e.target.value)} disabled={sshStep > 3} />
                </div>
              </div>
            )}
          </div>

          {sshSessionId && (
            <div className="steps-timeline">
              {[
                { s: 1, title: "1. Version Exchange" },
                { s: 2, title: "2. DH Group KEX" },
                { s: 3, title: "3. Server Host Auth" },
                { s: 4, title: "4. User Auth" },
                { s: 5, title: "5. PTY Shell Allocation" }
              ].map(({ s, title }) => (
                <div 
                  key={s}
                  className={`step-node ${sshStep === s ? 'active' : ''} ${sshStep >= s ? 'completed' : ''}`}
                  onClick={() => advanceSshStep(s)}
                >
                  <div className="step-node-num">STAGE 0{s}</div>
                  <div className="step-node-title">{title}</div>
                </div>
              ))}
            </div>
          )}

          {sshSessionId && (
            <div className="deck-card">
              <div className="card-heading">
                <div className="card-title-group">
                  <Cpu size={18} color="#a855f7" />
                  <div className="card-title">Interactive SSH Session Terminal</div>
                </div>
                {sshStep < 5 && (
                  <button className="btn-primary" onClick={() => advanceSshStep(sshStep + 1)} disabled={sshLoading} style={{ fontSize: '0.78rem', padding: '0.35rem 0.8rem' }}>
                    Run Step {sshStep + 1} <ArrowRight size={14} />
                  </button>
                )}
              </div>

              {/* Terminal Screen Mock */}
              <div style={{ background: '#050810', border: '1px solid #1f293d', borderRadius: '10px', padding: '1.25rem', fontFamily: 'Fira Code', fontSize: '0.8rem' }}>
                <div style={{ color: '#64748b', marginBottom: '0.5rem' }}>// NexusTunnel SSH-2.0 Session Stream</div>
                {sshLogs.map((l) => (
                  <div key={l.step} style={{ marginBottom: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '0.5rem' }}>
                    <div style={{ color: '#38bdf8' }}>[STEP {l.step}] {l.name}</div>
                    <div style={{ color: '#94a3b8', fontSize: '0.75rem' }}>{l.explanation}</div>
                    {l.server_signature_over_H && (
                      <div style={{ color: '#34d399', fontSize: '0.72rem', marginTop: '0.2rem' }}>
                        Host Key Verified: {l.client_verification}
                      </div>
                    )}
                  </div>
                ))}

                {sshStep === 5 && (
                  <div style={{ color: '#34d399', marginTop: '0.5rem' }}>
                    <div>Authentication Succeeded (publickey).</div>
                    <div>PTY allocated: /dev/pts/1 (xterm-256color)</div>
                    <div style={{ color: '#fbbf24', marginTop: '0.5rem' }}>
                      {sshUser}@nexustunnel:~$ <span style={{ animation: 'blink 1s infinite' }}>_</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 3. IPSEC ESP MODULE */}
      {activeTab === 'ipsec' && (
        <div>
          <div className="deck-card" style={{ marginBottom: '1.5rem' }}>
            <div className="card-heading">
              <div className="card-title-group">
                <Layers size={20} color="#6366f1" />
                <div>
                  <div className="card-title">IPsec Encapsulating Security Payload (ESP) Datagram Inspector</div>
                  <div className="card-subtitle">Examine packet block structures under Transport Mode vs Tunnel Mode</div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button 
                  className={`btn-secondary ${ipsecMode === 'transport' ? 'active' : ''}`}
                  onClick={() => analyzeIpsec('transport')}
                  style={{ background: ipsecMode === 'transport' ? '#4f46e5' : undefined, color: '#fff' }}
                >
                  Transport Mode (Host-to-Host)
                </button>
                <button 
                  className={`btn-secondary ${ipsecMode === 'tunnel' ? 'active' : ''}`}
                  onClick={() => analyzeIpsec('tunnel')}
                  style={{ background: ipsecMode === 'tunnel' ? '#4f46e5' : undefined, color: '#fff' }}
                >
                  Tunnel Mode (Gateway VPN)
                </button>
              </div>
            </div>

            {ipsecAnalysis && (
              <p style={{ fontSize: '0.88rem', color: '#c7d2fe', lineHeight: 1.6 }}>
                {ipsecAnalysis.explanation}
              </p>
            )}
          </div>

          {/* Visual Packet Diagram */}
          {ipsecAnalysis?.elements && (
            <div className="deck-card">
              <div className="card-heading">
                <div className="card-title-group">
                  <FileCode2 size={18} color="#10b981" />
                  <div className="card-title">Color-Coded ESP Datagram Encapsulation</div>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                {ipsecAnalysis.elements.map((el, i) => (
                  <div 
                    key={i}
                    style={{
                      background: el.encrypted ? 'rgba(16, 185, 129, 0.1)' : el.authenticated ? 'rgba(245, 158, 11, 0.1)' : 'rgba(59, 130, 246, 0.1)',
                      border: `1px solid ${el.encrypted ? '#10b981' : el.authenticated ? '#f59e0b' : '#3b82f6'}`,
                      borderRadius: '10px',
                      padding: '1rem'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                      <span style={{ fontWeight: 800, fontSize: '0.9rem', color: '#ffffff' }}>{el.field}</span>
                      <span className={`tag-badge ${el.encrypted ? 'success' : el.authenticated ? 'warning' : 'info'}`}>
                        {el.status}
                      </span>
                    </div>
                    <div style={{ fontFamily: 'Fira Code', fontSize: '0.82rem', color: '#e2e8f0', marginBottom: '0.35rem' }}>
                      {el.content}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      {el.description}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
