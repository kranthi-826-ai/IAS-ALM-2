import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Flame, 
  Plus, 
  Trash2, 
  RefreshCw, 
  AlertTriangle, 
  BookOpen, 
  Activity, 
  CheckCircle, 
  XCircle, 
  Radio, 
  Server, 
  Sliders
} from 'lucide-react';

const API_ROOT = '/p3';

export default function CitadelConsole() {
  const [activeTab, setActiveTab] = useState('firewall'); // firewall, ids, anomaly, encyclopedia

  // ---------------- Firewall State ----------------
  const [rules, setRules] = useState([]);
  const [bastionConfig, setBastionConfig] = useState(null);
  const [inspectSrc, setInspectSrc] = useState('192.168.1.45');
  const [inspectDst, setInspectDst] = useState('10.0.0.5');
  const [inspectProto, setInspectProto] = useState('TCP');
  const [inspectPort, setInspectPort] = useState(22);
  const [inspectResult, setInspectResult] = useState(null);
  const [fwLoading, setFwLoading] = useState(false);

  // New Rule Form State
  const [newRuleName, setNewRuleName] = useState('Custom Filter');
  const [newRuleSrc, setNewRuleSrc] = useState('ANY');
  const [newRuleDst, setNewRuleDst] = useState('ANY');
  const [newRuleProto, setNewRuleProto] = useState('TCP');
  const [newRulePort, setNewRulePort] = useState('');
  const [newRuleAction, setNewRuleAction] = useState('BLOCK');
  const [newRulePriority, setNewRulePriority] = useState(45);

  // ---------------- IDS State ----------------
  const [alerts, setAlerts] = useState([]);
  const [trafficSimLoading, setTrafficSimLoading] = useState(false);
  const [lastScenarioResult, setLastScenarioResult] = useState(null);

  // ---------------- Anomaly Metrics State ----------------
  const [metrics, setMetrics] = useState(null);

  // ---------------- Threat Encyclopedia State ----------------
  const [articles, setArticles] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  useEffect(() => {
    fetchFirewallRules();
    fetchAlerts();
    fetchMetrics();
    fetchThreats();
  }, []);

  // Firewall API Calls
  const fetchFirewallRules = async () => {
    setFwLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/firewall/rules`);
      if (res.ok) {
        const data = await res.json();
        setRules(data.rules || []);
        setBastionConfig(data.bastion || null);
      }
    } finally {
      setFwLoading(false);
    }
  };

  const handleAddRule = async () => {
    try {
      const res = await fetch(`${API_ROOT}/api/firewall/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newRuleName,
          direction: 'INBOUND',
          source_ip: newRuleSrc,
          dest_ip: newRuleDst,
          protocol: newRuleProto,
          port: newRulePort ? parseInt(newRulePort) : null,
          action: newRuleAction,
          priority: parseInt(newRulePriority)
        })
      });
      if (res.ok) {
        fetchFirewallRules();
        setNewRuleName('Custom Filter');
        setNewRulePort('');
      }
    } catch (e) {
      console.warn("Failed to create rule", e);
    }
  };

  const handleDeleteRule = async (ruleId) => {
    try {
      const res = await fetch(`${API_ROOT}/api/firewall/rules/${ruleId}`, { method: 'DELETE' });
      if (res.ok) fetchFirewallRules();
    } catch (e) {
      console.warn("Failed to delete rule", e);
    }
  };

  const handleInspectPacket = async () => {
    try {
      const res = await fetch(`${API_ROOT}/api/firewall/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_ip: inspectSrc,
          dest_ip: inspectDst,
          protocol: inspectProto,
          port: parseInt(inspectPort)
        })
      });
      if (res.ok) {
        const data = await res.json();
        setInspectResult(data);
      }
    } catch (e) {
      console.warn("Inspection failed", e);
    }
  };

  // IDS & Traffic Generation
  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_ROOT}/api/ids/alerts`);
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.alerts || []);
      }
    } catch (e) {
      console.warn("Alerts fetch failed", e);
    }
  };

  const clearAlerts = async () => {
    try {
      const res = await fetch(`${API_ROOT}/api/ids/alerts`, { method: 'DELETE' });
      if (res.ok) setAlerts([]);
    } catch (e) {
      console.warn("Clear alerts failed", e);
    }
  };

  const triggerTrafficScenario = async (scenario) => {
    setTrafficSimLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/ids/traffic/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenario })
      });
      if (res.ok) {
        const data = await res.json();
        setLastScenarioResult(data);
        fetchAlerts();
        fetchMetrics();
      }
    } finally {
      setTrafficSimLoading(false);
    }
  };

  const fetchMetrics = async () => {
    try {
      const res = await fetch(`${API_ROOT}/api/ids/metrics`);
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch (e) {
      console.warn("Metrics fetch failed", e);
    }
  };

  const fetchThreats = async () => {
    try {
      const res = await fetch(`${API_ROOT}/api/threats`);
      if (res.ok) {
        const data = await res.json();
        setArticles(data.encyclopedia || []);
      }
    } catch (e) {
      console.warn("Threats fetch failed", e);
    }
  };

  return (
    <div className="citadel-console">
      {/* Subnav */}
      <div className="subnav-tabs">
        <button 
          className={`subnav-pill ${activeTab === 'firewall' ? 'active' : ''}`}
          onClick={() => setActiveTab('firewall')}
        >
          <ShieldCheck size={16} /> Firewall Rule Policies & Bastion Host
        </button>
        <button 
          className={`subnav-pill ${activeTab === 'ids' ? 'active' : ''}`}
          onClick={() => setActiveTab('ids')}
        >
          <Flame size={16} /> Traffic Simulator & Signature IDS
        </button>
        <button 
          className={`subnav-pill ${activeTab === 'anomaly' ? 'active' : ''}`}
          onClick={() => { setActiveTab('anomaly'); fetchMetrics(); }}
        >
          <Activity size={16} /> 3-Sigma Gaussian Anomaly Model
        </button>
        <button 
          className={`subnav-pill ${activeTab === 'encyclopedia' ? 'active' : ''}`}
          onClick={() => setActiveTab('encyclopedia')}
        >
          <BookOpen size={16} /> Threat Intelligence Encyclopedia
        </button>
      </div>

      {/* 1. FIREWALL RULES & BASTION */}
      {activeTab === 'firewall' && (
        <div>
          {/* Bastion Host Configuration Strip */}
          {bastionConfig && (
            <div className="deck-card" style={{ marginBottom: '1.5rem', borderLeft: '4px solid #f59e0b' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <Server size={22} color="#f59e0b" />
                  <div>
                    <div style={{ fontWeight: 800, fontSize: '1rem', color: '#ffffff' }}>
                      Perimeter Bastion Host ({bastionConfig.name})
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      Isolated Ingress Point: <code>{bastionConfig.ip}</code> • Permitted Subnet: <code>{bastionConfig.allowed_management_subnet}</code>
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <span className="tag-badge success">MONITORED: PORT 22 (SSH)</span>
                  <span className="tag-badge success">MONITORED: PORT 443 (HTTPS)</span>
                </div>
              </div>
            </div>
          )}

          {/* Rules Table & Packet Inspector */}
          <div className="cards-grid">
            {/* Active Firewall Rules Table */}
            <div className="deck-card" style={{ gridColumn: 'span 2' }}>
              <div className="card-heading">
                <div className="card-title-group">
                  <ShieldCheck size={20} color="#f59e0b" />
                  <div>
                    <div className="card-title">Priority-Ordered Firewall Rule Base</div>
                    <div className="card-subtitle">Top-down evaluation; first matching rule takes precedence</div>
                  </div>
                </div>
                <button className="btn-secondary" onClick={fetchFirewallRules} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                  <RefreshCw size={13} /> Refresh Rules
                </button>
              </div>

              <div style={{ overflowX: 'auto' }}>
                <table className="aegis-table">
                  <thead>
                    <tr>
                      <th>Priority</th>
                      <th>Rule Description</th>
                      <th>Source IP</th>
                      <th>Dest IP</th>
                      <th>Protocol</th>
                      <th>Port</th>
                      <th>Action</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rules.map((r) => (
                      <tr key={r.id}>
                        <td><code>#{r.priority}</code></td>
                        <td><strong>{r.name}</strong></td>
                        <td><code>{r.source_ip}</code></td>
                        <td><code>{r.dest_ip}</code></td>
                        <td>{r.protocol}</td>
                        <td>{r.port ? r.port : 'ANY'}</td>
                        <td>
                          <span className={`tag-badge ${r.action === 'ALLOW' ? 'success' : 'danger'}`}>
                            {r.action}
                          </span>
                        </td>
                        <td>
                          <button 
                            className="btn-danger" 
                            onClick={() => handleDeleteRule(r.id)}
                            style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                          >
                            <Trash2 size={12} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Live Packet Inspector */}
            <div className="deck-card">
              <div className="card-heading">
                <div className="card-title-group">
                  <Sliders size={20} color="#6366f1" />
                  <div>
                    <div className="card-title">Live Packet Evaluation Tester</div>
                    <div className="card-subtitle">Simulate incoming packet against policy tree</div>
                  </div>
                </div>
              </div>

              <div className="field-group">
                <label className="field-label">Source IP Address</label>
                <input className="input-box" value={inspectSrc} onChange={(e) => setInspectSrc(e.target.value)} />
              </div>
              <div className="field-group">
                <label className="field-label">Destination IP Address</label>
                <input className="input-box" value={inspectDst} onChange={(e) => setInspectDst(e.target.value)} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div className="field-group">
                  <label className="field-label">Protocol</label>
                  <select className="select-box" value={inspectProto} onChange={(e) => setInspectProto(e.target.value)}>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                  </select>
                </div>
                <div className="field-group">
                  <label className="field-label">Port</label>
                  <input className="input-box" type="number" value={inspectPort} onChange={(e) => setInspectPort(e.target.value)} />
                </div>
              </div>

              <button className="btn-primary" style={{ width: '100%', marginTop: '0.5rem' }} onClick={handleInspectPacket}>
                Inspect Packet Traversal
              </button>

              {inspectResult && (
                <div style={{ marginTop: '1.25rem', padding: '1rem', borderRadius: '8px', background: inspectResult.decision === 'ALLOW' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)', border: `1px solid ${inspectResult.decision === 'ALLOW' ? '#10b981' : '#f43f5e'}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                    <span style={{ fontWeight: 800, fontSize: '0.95rem', color: inspectResult.decision === 'ALLOW' ? '#34d399' : '#fda4af' }}>
                      DECISION: {inspectResult.decision}
                    </span>
                    {inspectResult.is_bastion_targeted && (
                      <span className="tag-badge warning">BASTION TARGET</span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {inspectResult.reason}
                  </div>
                </div>
              )}
            </div>

            {/* Add Rule Form */}
            <div className="deck-card">
              <div className="card-heading">
                <div className="card-title-group">
                  <Plus size={20} color="#10b981" />
                  <div>
                    <div className="card-title">Add Firewall Security Policy</div>
                    <div className="card-subtitle">Define granular allow or drop actions</div>
                  </div>
                </div>
              </div>

              <div className="field-group">
                <label className="field-label">Policy Rule Name</label>
                <input className="input-box" value={newRuleName} onChange={(e) => setNewRuleName(e.target.value)} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                <div className="field-group">
                  <label className="field-label">Source IP (or ANY)</label>
                  <input className="input-box" value={newRuleSrc} onChange={(e) => setNewRuleSrc(e.target.value)} />
                </div>
                <div className="field-group">
                  <label className="field-label">Dest IP (or ANY)</label>
                  <input className="input-box" value={newRuleDst} onChange={(e) => setNewRuleDst(e.target.value)} />
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem' }}>
                <div className="field-group">
                  <label className="field-label">Protocol</label>
                  <select className="select-box" value={newRuleProto} onChange={(e) => setNewRuleProto(e.target.value)}>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ANY">ANY</option>
                  </select>
                </div>
                <div className="field-group">
                  <label className="field-label">Port</label>
                  <input className="input-box" placeholder="Any" value={newRulePort} onChange={(e) => setNewRulePort(e.target.value)} />
                </div>
                <div className="field-group">
                  <label className="field-label">Action</label>
                  <select className="select-box" value={newRuleAction} onChange={(e) => setNewRuleAction(e.target.value)}>
                    <option value="BLOCK">BLOCK</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>
              </div>

              <button className="btn-amber" style={{ width: '100%', marginTop: '0.5rem' }} onClick={handleAddRule}>
                <Plus size={16} /> Deploy Firewall Rule
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 2. ATTACK SIMULATOR & IDS ALERTS */}
      {activeTab === 'ids' && (
        <div>
          {/* Attack Trigger Buttons */}
          <div className="deck-card" style={{ marginBottom: '1.5rem' }}>
            <div className="card-heading">
              <div className="card-title-group">
                <Flame size={20} color="#f43f5e" />
                <div>
                  <div className="card-title">Network Attack Simulator & Traffic Generator</div>
                  <div className="card-subtitle">Inject live malicious payloads and volumetric anomalies into the sensor grid</div>
                </div>
              </div>
              <button className="btn-secondary" onClick={clearAlerts} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                Clear Alerts Feed
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.85rem' }}>
              <button className="btn-secondary" onClick={() => triggerTrafficScenario('normal')} disabled={trafficSimLoading}>
                Normal HTTP/HTTPS
              </button>
              <button className="btn-amber" onClick={() => triggerTrafficScenario('ssh_bruteforce')} disabled={trafficSimLoading}>
                ⚡ SSH Brute Force (5+ tries)
              </button>
              <button className="btn-amber" onClick={() => triggerTrafficScenario('telnet_insecure')} disabled={trafficSimLoading}>
                ⚡ Insecure Telnet (Port 23)
              </button>
              <button className="btn-amber" onClick={() => triggerTrafficScenario('port_scan')} disabled={trafficSimLoading}>
                ⚡ Multi-Port Recon Scan
              </button>
              <button 
                className="btn-primary" 
                style={{ background: 'linear-gradient(135deg, #e11d48, #f43f5e)' }} 
                onClick={() => triggerTrafficScenario('syn_flood')} 
                disabled={trafficSimLoading}
              >
                🚨 SYN Flood (3-Sigma Anomaly)
              </button>
            </div>
          </div>

          {/* Alerts Feed */}
          <div className="deck-card">
            <div className="card-heading">
              <div className="card-title-group">
                <AlertTriangle size={20} color="#f43f5e" />
                <div>
                  <div className="card-title">Real-Time Security Alerts Stream</div>
                  <div className="card-subtitle">Total alerts triggered: {alerts.length}</div>
                </div>
              </div>
              <button className="btn-secondary" onClick={fetchAlerts} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                <RefreshCw size={13} /> Refresh
              </button>
            </div>

            {alerts.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '420px', overflowY: 'auto' }}>
                {alerts.map((a) => (
                  <div 
                    key={a.id} 
                    style={{ 
                      background: a.severity === 'CRITICAL' ? 'rgba(244, 63, 94, 0.12)' : a.severity === 'HIGH' ? 'rgba(245, 158, 11, 0.12)' : 'rgba(99, 102, 241, 0.1)',
                      border: `1px solid ${a.severity === 'CRITICAL' ? '#f43f5e' : a.severity === 'HIGH' ? '#f59e0b' : '#6366f1'}`,
                      borderRadius: '8px',
                      padding: '0.85rem'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                      <span style={{ fontWeight: 800, fontSize: '0.88rem', color: '#ffffff' }}>
                        {a.rule_name}
                      </span>
                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <span className={`tag-badge ${a.severity === 'CRITICAL' ? 'danger' : a.severity === 'HIGH' ? 'warning' : 'info'}`}>
                          {a.severity}
                        </span>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'Fira Code' }}>
                          {a.timestamp}
                        </span>
                      </div>
                    </div>
                    <div style={{ fontSize: '0.82rem', color: '#e2e8f0', marginBottom: '0.25rem' }}>
                      {a.message}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Details: {a.details}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                No active threats detected. Trigger an attack scenario above to test the IDS detection engine.
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. STATISTICAL ANOMALY MODEL */}
      {activeTab === 'anomaly' && metrics && (
        <div>
          {/* Baseline Stats Card */}
          <div className="cards-grid">
            <div className="deck-card">
              <div className="card-subtitle">Dynamic Baseline Mean (μ)</div>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: '#a5b4fc', margin: '0.35rem 0' }}>
                {metrics.current_mean} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>pkts/s</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Computed via NumPy & Pandas</div>
            </div>

            <div className="deck-card">
              <div className="card-subtitle">Standard Deviation (σ)</div>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: '#c4b5fd', margin: '0.35rem 0' }}>
                ±{metrics.current_std} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>pkts/s</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Normal traffic dispersion buffer</div>
            </div>

            <div className="deck-card" style={{ borderTop: '3px solid #f43f5e' }}>
              <div className="card-subtitle">Critical 3-Sigma Threshold (μ + 3σ)</div>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f43f5e', margin: '0.35rem 0' }}>
                {metrics.threshold_3sigma} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>pkts/s</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#fda4af' }}>Rates exceeding threshold flag critical alerts</div>
            </div>
          </div>

          {/* SVG Telemetry Bar Chart */}
          <div className="deck-card" style={{ marginTop: '1.5rem' }}>
            <div className="card-heading">
              <div className="card-title-group">
                <Activity size={20} color="#6366f1" />
                <div>
                  <div className="card-title">Rolling Packet Rate Telemetry & Gaussian Deviation</div>
                  <div className="card-subtitle">Red bars indicate 3-sigma volumetric anomalies (e.g. SYN Flood surges)</div>
                </div>
              </div>
            </div>

            {/* SVG Visualizer */}
            <div style={{ background: '#070a14', padding: '1.5rem', borderRadius: '10px', border: '1px solid #1a233a' }}>
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: '6px', height: '160px', borderBottom: '1px solid #334155', paddingBottom: '4px' }}>
                {metrics.history?.slice(-40).map((h, idx) => {
                  const isAnomaly = h.rate > metrics.threshold_3sigma;
                  const barHeight = Math.min(100, Math.round((h.rate / 65) * 100));
                  return (
                    <div 
                      key={idx} 
                      style={{ 
                        flex: 1, 
                        height: `${barHeight}%`, 
                        background: isAnomaly ? 'linear-gradient(180deg, #f43f5e, #be123c)' : 'linear-gradient(180deg, #6366f1, #4338ca)',
                        borderRadius: '3px 3px 0 0',
                        transition: 'height 0.3s ease',
                        position: 'relative'
                      }}
                      title={`#${h.index}: ${h.rate} pkts/s ${isAnomaly ? '(ANOMALY)' : ''}`}
                    />
                  );
                })}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'Fira Code' }}>
                <span>Historical Telemetry Window (Past 40 intervals)</span>
                <span style={{ color: '#f43f5e' }}>Threshold: {metrics.threshold_3sigma} pkts/s</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 4. THREAT ENCYCLOPEDIA */}
      {activeTab === 'encyclopedia' && (
        <div>
          <div className="deck-card" style={{ marginBottom: '1.5rem' }}>
            <div className="card-heading">
              <div className="card-title-group">
                <BookOpen size={20} color="#f59e0b" />
                <div>
                  <div className="card-title">Cyber Threats & Malware Taxonomy Encyclopedia</div>
                  <div className="card-subtitle">Theoretical taxonomy of viral payloads, worm vectors, and bastion countermeasures</div>
                </div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem' }}>
              {articles.map((art) => (
                <div key={art.id} style={{ background: '#090d18', border: '1px solid #1c2742', borderRadius: '10px', padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                    <span className="tag-badge info">{art.category}</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{art.id}</span>
                  </div>
                  <h4 style={{ color: '#ffffff', fontSize: '1rem', fontWeight: 800, marginBottom: '0.4rem' }}>
                    {art.title}
                  </h4>
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                    {art.summary}
                  </p>
                  <div style={{ fontSize: '0.78rem', color: '#c7d2fe', marginBottom: '0.75rem' }}>
                    <strong>Propagation Mechanism:</strong> {art.mechanism}
                  </div>
                  <div>
                    <strong style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Countermeasures:</strong>
                    <ul style={{ paddingLeft: '1.2rem', fontSize: '0.75rem', color: '#34d399', marginTop: '0.25rem' }}>
                      {art.countermeasures?.map((c, i) => (
                        <li key={i}>{c}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
