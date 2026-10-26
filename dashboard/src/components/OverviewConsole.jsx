import React from 'react';
import { 
  ShieldCheck, 
  KeyRound, 
  Network, 
  Flame, 
  Cpu, 
  CheckCircle2, 
  ArrowUpRight, 
  Terminal, 
  Lock, 
  Server,
  Layers,
  Radio
} from 'lucide-react';

export default function OverviewConsole({ onNavigate, p1Online, p2Online, p3Online }) {
  return (
    <div className="overview-container">
      {/* Hero Operations Center Banner */}
      <div className="console-banner">
        <div className="banner-left">
          <div className="banner-badge">
            <Radio size={14} className="pulse-icon" />
            AEGIS//OPS • ACTIVE DEFENSE OPERATIONS DECK
          </div>
          <h1 className="banner-title">Cyber Defense & Applied Cryptography Operations Suite</h1>
          <p className="banner-desc">
            Unified mission control platform fulfilling all core requirements for <strong>ALM-2 (Active Learning Management Project 2)</strong>. 
            Integrates asymmetric PKI identity binding, transport-level protocol handshakes (TLS & SSH), IPsec ESP packet isolation, 
            rule-based firewall filtering, and 3-sigma Gaussian anomaly intrusion detection.
          </p>
        </div>
        <div className="banner-right">
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div className="telemetry-chip">
              <span className={`pulse-node ${p1Online ? 'online' : 'offline'}`} />
              P1: AegisCrypt (5101)
            </div>
            <div className="telemetry-chip">
              <span className={`pulse-node ${p2Online ? 'online' : 'offline'}`} />
              P2: NexusTunnel (5102)
            </div>
            <div className="telemetry-chip">
              <span className={`pulse-node ${p3Online ? 'online' : 'offline'}`} />
              P3: Citadel (5103)
            </div>
          </div>
        </div>
      </div>

      {/* 3 Core Project Mission Cards */}
      <div className="cards-grid">
        {/* Project 1 */}
        <div className="deck-card" style={{ borderTop: '3px solid #6366f1' }}>
          <div className="card-heading">
            <div className="card-title-group">
              <div style={{ background: 'rgba(99, 102, 241, 0.2)', padding: '0.5rem', borderRadius: '8px', color: '#a5b4fc' }}>
                <KeyRound size={22} />
              </div>
              <div>
                <div className="card-title">Project 1: AegisCrypt</div>
                <div className="card-subtitle">Asymmetric Ciphers & PKI Infrastructure</div>
              </div>
            </div>
            <span className={`tag-badge ${p1Online ? 'success' : 'danger'}`}>
              {p1Online ? 'ONLINE :5001' : 'OFFLINE'}
            </span>
          </div>

          <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Enterprise public-key infrastructure providing RSA-2048 identity enrollment, X.509 CA certificate issuance, 
            RSA-OAEP ciphers, RSA-PSS signatures, multi-step Diffie-Hellman key agreement, and Elgamal digital signatures with SHA-512.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', marginBottom: '1.5rem', fontSize: '0.82rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#c7d2fe' }}>
              <CheckCircle2 size={14} color="#10b981" /> RSA-2048 Key Lifecycle & X.509 CA Certs
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#c7d2fe' }}>
              <CheckCircle2 size={14} color="#10b981" /> RSA-OAEP Encryption & RSA-PSS Signatures
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#c7d2fe' }}>
              <CheckCircle2 size={14} color="#10b981" /> 4-Stage Diffie-Hellman Key Exchange Matrix
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#c7d2fe' }}>
              <CheckCircle2 size={14} color="#10b981" /> Elgamal Signature Scheme with SHA-512
            </div>
          </div>

          <button className="btn-primary" style={{ width: '100%' }} onClick={() => onNavigate('project1')}>
            Launch AegisCrypt Console <ArrowUpRight size={16} />
          </button>
        </div>

        {/* Project 2 */}
        <div className="deck-card" style={{ borderTop: '3px solid #8b5cf6' }}>
          <div className="card-heading">
            <div className="card-title-group">
              <div style={{ background: 'rgba(139, 92, 246, 0.2)', padding: '0.5rem', borderRadius: '8px', color: '#c4b5fd' }}>
                <Network size={22} />
              </div>
              <div>
                <div className="card-title">Project 2: NexusTunnel</div>
                <div className="card-subtitle">Transport Layer Protocols & IPsec</div>
              </div>
            </div>
            <span className={`tag-badge ${p2Online ? 'success' : 'danger'}`}>
              {p2Online ? 'ONLINE :5002' : 'OFFLINE'}
            </span>
          </div>

          <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Comprehensive simulation of authenticated cryptographic tunnels. Visualizes 5-step TLS/SSL handshakes with PRF key expansion, 
            SSH-2.0 Diffie-Hellman connection negotiation, and IPsec ESP datagram encapsulation.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', marginBottom: '1.5rem', fontSize: '0.82rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#ddd6fe' }}>
              <CheckCircle2 size={14} color="#10b981" /> 5-Step TLS/SSL Handshake & PRF Key Expansion
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#ddd6fe' }}>
              <CheckCircle2 size={14} color="#10b981" /> Live AES-128-GCM Tunnel Data Transmission
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#ddd6fe' }}>
              <CheckCircle2 size={14} color="#10b981" /> 5-Phase SSH-2.0 Protocol Negotiation & PTY Shell
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#ddd6fe' }}>
              <CheckCircle2 size={14} color="#10b981" /> IPsec ESP Packet Breakdown (Transport vs Tunnel)
            </div>
          </div>

          <button className="btn-primary" style={{ width: '100%', background: 'linear-gradient(135deg, #6d28d9, #8b5cf6)' }} onClick={() => onNavigate('project2')}>
            Launch NexusTunnel Console <ArrowUpRight size={16} />
          </button>
        </div>

        {/* Project 3 */}
        <div className="deck-card" style={{ borderTop: '3px solid #f59e0b' }}>
          <div className="card-heading">
            <div className="card-title-group">
              <div style={{ background: 'rgba(245, 158, 11, 0.2)', padding: '0.5rem', borderRadius: '8px', color: '#fde68a' }}>
                <ShieldCheck size={22} />
              </div>
              <div>
                <div className="card-title">Project 3: Citadel Defense</div>
                <div className="card-subtitle">Firewall Rules & Anomaly IDS</div>
              </div>
            </div>
            <span className={`tag-badge ${p3Online ? 'success' : 'danger'}`}>
              {p3Online ? 'ONLINE :5003' : 'OFFLINE'}
            </span>
          </div>

          <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Integrated perimeter protection engine combining priority packet filtering, Bastion Host isolation, 
            deterministic rule-based signature detection, and dynamic 3-Sigma Gaussian anomaly modeling with NumPy/Pandas.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', marginBottom: '1.5rem', fontSize: '0.82rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#fef3c7' }}>
              <CheckCircle2 size={14} color="#10b981" /> Granular Firewall Rule Manager & Live Packet Inspector
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#fef3c7' }}>
              <CheckCircle2 size={14} color="#10b981" /> Hardened Bastion Host Subnet Isolation (10.0.0.5)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#fef3c7' }}>
              <CheckCircle2 size={14} color="#10b981" /> Rule-based IDS: SSH Brute Force, Telnet, Port Scan
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#fef3c7' }}>
              <CheckCircle2 size={14} color="#10b981" /> NumPy/Pandas 3-Sigma Gaussian Anomaly Model
            </div>
          </div>

          <button className="btn-amber" style={{ width: '100%' }} onClick={() => onNavigate('project3')}>
            Launch Citadel Console <ArrowUpRight size={16} />
          </button>
        </div>
      </div>

      {/* Architecture Matrix Table */}
      <div className="deck-card">
        <div className="card-heading">
          <div className="card-title-group">
            <Layers size={20} color="#6366f1" />
            <div>
              <div className="card-title">ALM-2 Architectural Deliverables & Verification Matrix</div>
              <div className="card-subtitle">Direct mapping of curriculum criteria to verified implementations</div>
            </div>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="aegis-table">
            <thead>
              <tr>
                <th>Component</th>
                <th>Syllabus Topic Required</th>
                <th>Module Implementation</th>
                <th>Cryptographic Primitives</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Project 1</strong></td>
                <td>User Authentication & PKI Key Management</td>
                <td><code>/api/auth/*</code>, <code>/api/pki/*</code></td>
                <td>RSA-2048, X.509 v3, SQLite</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
              <tr>
                <td><strong>Project 1</strong></td>
                <td>Interactive RSA Encryption & Signing</td>
                <td><code>/api/rsa/*</code></td>
                <td>RSA-OAEP-SHA256, RSA-PSS</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
              <tr>
                <td><strong>Project 1</strong></td>
                <td>Diffie-Hellman Key Agreement</td>
                <td><code>/api/dh/*</code></td>
                <td>Modular Exponentiation, Discrete Log</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
              <tr>
                <td><strong>Project 1</strong></td>
                <td>Elgamal Signature & SHA-512 Hashing</td>
                <td><code>/api/elgamal/*</code></td>
                <td>SHA-512, Extended Euclidean Algorithm</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
              <tr>
                <td><strong>Project 2</strong></td>
                <td>TLS/SSL Handshake & Symmetric Tunnel</td>
                <td><code>/api/tls/*</code></td>
                <td>TLS 1.2/1.3 PRF, AES-128-GCM</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
              <tr>
                <td><strong>Project 2</strong></td>
                <td>SSH Connection & Server Authentication</td>
                <td><code>/api/ssh/*</code></td>
                <td>DH Group Exchange, Host Signature</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
              <tr>
                <td><strong>Project 2</strong></td>
                <td>IPsec ESP Packet Encapsulation</td>
                <td><code>/api/ipsec/*</code></td>
                <td>Transport vs Tunnel Mode, HMAC ICV</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
              <tr>
                <td><strong>Project 3</strong></td>
                <td>Firewall Rules & Bastion Architecture</td>
                <td><code>/api/firewall/*</code></td>
                <td>CIDR Subnet Matching, Default Deny</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
              <tr>
                <td><strong>Project 3</strong></td>
                <td>Signature & Statistical Anomaly IDS</td>
                <td><code>/api/ids/*</code></td>
                <td>NumPy/Pandas 3-Sigma Gaussian Model</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
              <tr>
                <td><strong>Project 3</strong></td>
                <td>Threat Encyclopedia</td>
                <td><code>/api/threats</code></td>
                <td>Viruses, Worms, Bastion Mitigations</td>
                <td><span className="tag-badge success">VERIFIED</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
