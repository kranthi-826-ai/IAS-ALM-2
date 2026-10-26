import React, { useState, useEffect } from 'react';
import { 
  KeyRound, 
  Lock, 
  Unlock, 
  FileCheck2, 
  Download, 
  RefreshCw, 
  ShieldCheck, 
  ArrowRight, 
  Hash, 
  CheckCircle, 
  AlertTriangle,
  Send,
  Eye,
  Sliders
} from 'lucide-react';

const API_ROOT = '/p1';

export default function AegisCryptConsole() {
  const [activeSection, setActiveSection] = useState('pki'); // pki, rsa, dh, elgamal

  // ---------------- PKI & User Auth State ----------------
  const [userHandle, setUserHandle] = useState('v_analyst');
  const [secretPass, setSecretPass] = useState('VPass#2026!');
  const [currentUser, setCurrentUser] = useState(null);
  const [authMsg, setAuthMsg] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // ---------------- RSA State ----------------
  const [rsaInput, setRsaInput] = useState('AegisOps Secure Cryptographic Directive :: Confirmed');
  const [rsaCipherB64, setRsaCipherB64] = useState('');
  const [rsaDecryptedText, setRsaDecryptedText] = useState('');
  const [rsaSignatureB64, setRsaSignatureB64] = useState('');
  const [rsaVerifyStatus, setRsaVerifyStatus] = useState(null);
  const [pubKeyPem, setPubKeyPem] = useState('');
  const [privKeyPem, setPrivKeyPem] = useState('');
  const [rsaLoading, setRsaLoading] = useState(false);

  // ---------------- Diffie-Hellman State ----------------
  const [dhPrime, setDhPrime] = useState(353);
  const [dhGen, setDhGen] = useState(3);
  const [aliceExponent, setAliceExponent] = useState(97);
  const [bobExponent, setBobExponent] = useState(233);
  const [dhStepNum, setDhStepNum] = useState(1);
  const [dhStepData, setDhStepData] = useState(null);
  const [dhLoading, setDhLoading] = useState(false);

  // ---------------- Elgamal & SHA-512 State ----------------
  const [elgamalMessage, setElgamalMessage] = useState('Authorize financial transfer of $75,000 to defense account');
  const [elgamalHashData, setElgamalHashData] = useState(null);
  const [elgamalKeyData, setElgamalKeyData] = useState(null);
  const [elgamalSigData, setElgamalSigData] = useState(null);
  const [elgamalVerifyResult, setElgamalVerifyResult] = useState(null);
  const [elgamalLoading, setElgamalLoading] = useState(false);

  // Initialize keys on mount
  useEffect(() => {
    generateFreshRSA();
    generateElgamalKeys();
    fetchDHStep(1);
  }, []);

  // PKI Functions
  const handleRegister = async () => {
    setAuthLoading(true);
    setAuthMsg('');
    try {
      const res = await fetch(`${API_ROOT}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_handle: userHandle,
          password: secretPass,
          organization: 'AegisOps PKI Authority'
        })
      });
      const data = await res.json();
      if (res.ok) {
        setCurrentUser(data);
        setPubKeyPem(data.public_key_pem);
        setPrivKeyPem(data.private_key_pem);
        setAuthMsg('Identity enrolled & X.509 Certificate signed by CA.');
      } else {
        setAuthMsg(data.error || 'Registration failed');
      }
    } catch {
      setAuthMsg('Backend unreachable on port 5001');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogin = async () => {
    setAuthLoading(true);
    setAuthMsg('');
    try {
      const res = await fetch(`${API_ROOT}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_handle: userHandle, password: secretPass })
      });
      const data = await res.json();
      if (res.ok) {
        setCurrentUser(data);
        setPubKeyPem(data.public_key_pem);
        setPrivKeyPem(data.private_key_pem);
        setAuthMsg('Logged in. Active RSA-2048 keys and X.509 cert loaded.');
      } else {
        setAuthMsg(data.error || 'Authentication rejected');
      }
    } catch {
      setAuthMsg('Backend unreachable');
    } finally {
      setAuthLoading(false);
    }
  };

  // RSA Functions
  const generateFreshRSA = async () => {
    setRsaLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/rsa/generate`);
      if (res.ok) {
        const data = await res.json();
        setPubKeyPem(data.public_key_pem);
        setPrivKeyPem(data.private_key_pem);
      }
    } catch (e) {
      console.warn("Project 1 backend offline", e);
    } finally {
      setRsaLoading(false);
    }
  };

  const handleRsaEncrypt = async () => {
    if (!pubKeyPem) return;
    setRsaLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/rsa/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ public_key_pem: pubKeyPem, plaintext: rsaInput })
      });
      const data = await res.json();
      if (res.ok) {
        setRsaCipherB64(data.ciphertext_base64);
        setRsaDecryptedText('');
      }
    } finally {
      setRsaLoading(false);
    }
  };

  const handleRsaDecrypt = async () => {
    if (!privKeyPem || !rsaCipherB64) return;
    setRsaLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/rsa/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ private_key_pem: privKeyPem, ciphertext_base64: rsaCipherB64 })
      });
      const data = await res.json();
      if (res.ok) {
        setRsaDecryptedText(data.plaintext);
      }
    } finally {
      setRsaLoading(false);
    }
  };

  const handleRsaSign = async () => {
    if (!privKeyPem) return;
    setRsaLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/rsa/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ private_key_pem: privKeyPem, message: rsaInput })
      });
      const data = await res.json();
      if (res.ok) {
        setRsaSignatureB64(data.signature_base64);
        setRsaVerifyStatus(null);
      }
    } finally {
      setRsaLoading(false);
    }
  };

  const handleRsaVerify = async () => {
    if (!pubKeyPem || !rsaSignatureB64) return;
    setRsaLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/rsa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          public_key_pem: pubKeyPem,
          message: rsaInput,
          signature_base64: rsaSignatureB64
        })
      });
      const data = await res.json();
      setRsaVerifyStatus(data);
    } finally {
      setRsaLoading(false);
    }
  };

  // Diffie-Hellman Functions
  const fetchDHStep = async (step) => {
    setDhLoading(true);
    setDhStepNum(step);
    try {
      const res = await fetch(`${API_ROOT}/api/dh/calculate-step`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          step: step,
          p: dhPrime,
          g: dhGen,
          alice_private: aliceExponent,
          bob_private: bobExponent
        })
      });
      if (res.ok) {
        const data = await res.json();
        setDhStepData(data);
      }
    } finally {
      setDhLoading(false);
    }
  };

  const applyDHPreset = async (preset) => {
    const res = await fetch(`${API_ROOT}/api/dh/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: preset })
    });
    if (res.ok) {
      const data = await res.json();
      setDhPrime(parseInt(data.p));
      setDhGen(parseInt(data.g));
      setAliceExponent(data.alice_private_suggested);
      setBobExponent(data.bob_private_suggested);
      fetchDHStep(1);
    }
  };

  // Elgamal Functions
  const generateElgamalKeys = async () => {
    setElgamalLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/elgamal/keygen`);
      if (res.ok) {
        const data = await res.json();
        setElgamalKeyData(data);
      }
    } finally {
      setElgamalLoading(false);
    }
  };

  const handleComputeHash = async () => {
    setElgamalLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/elgamal/hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: elgamalMessage })
      });
      if (res.ok) {
        const data = await res.json();
        setElgamalHashData(data);
      }
    } finally {
      setElgamalLoading(false);
    }
  };

  const handleElgamalSign = async () => {
    if (!elgamalKeyData) return;
    setElgamalLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/elgamal/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: elgamalMessage,
          private_key_x: elgamalKeyData.private_key_x,
          p: elgamalKeyData.p,
          g: elgamalKeyData.g
        })
      });
      if (res.ok) {
        const data = await res.json();
        setElgamalSigData(data);
        setElgamalVerifyResult(null);
      }
    } finally {
      setElgamalLoading(false);
    }
  };

  const handleElgamalVerify = async () => {
    if (!elgamalKeyData || !elgamalSigData) return;
    setElgamalLoading(true);
    try {
      const res = await fetch(`${API_ROOT}/api/elgamal/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: elgamalMessage,
          signature_r: elgamalSigData.signature_r,
          signature_s: elgamalSigData.signature_s,
          public_key_y: elgamalKeyData.public_key_y,
          p: elgamalKeyData.p,
          g: elgamalKeyData.g
        })
      });
      if (res.ok) {
        const data = await res.json();
        setElgamalVerifyResult(data);
      }
    } finally {
      setElgamalLoading(false);
    }
  };

  return (
    <div className="aegiscrypt-console">
      {/* Sub-navigation tabs */}
      <div className="subnav-tabs">
        <button 
          className={`subnav-pill ${activeSection === 'pki' ? 'active' : ''}`}
          onClick={() => setActiveSection('pki')}
        >
          <FileCheck2 size={16} /> PKI & X.509 Certification
        </button>
        <button 
          className={`subnav-pill ${activeSection === 'rsa' ? 'active' : ''}`}
          onClick={() => setActiveSection('rsa')}
        >
          <Lock size={16} /> RSA-OAEP & RSA-PSS Workbench
        </button>
        <button 
          className={`subnav-pill ${activeSection === 'dh' ? 'active' : ''}`}
          onClick={() => setActiveSection('dh')}
        >
          <KeyRound size={16} /> Diffie-Hellman Key Agreement Matrix
        </button>
        <button 
          className={`subnav-pill ${activeSection === 'elgamal' ? 'active' : ''}`}
          onClick={() => setActiveSection('elgamal')}
        >
          <Hash size={16} /> Elgamal Signatures & SHA-512
        </button>
      </div>

      {/* 1. PKI SECTION */}
      {activeSection === 'pki' && (
        <div className="cards-grid">
          <div className="deck-card">
            <div className="card-heading">
              <div className="card-title-group">
                <ShieldCheck size={20} color="#6366f1" />
                <div>
                  <div className="card-title">Cryptographic Identity Enrollment</div>
                  <div className="card-subtitle">Generate RSA-2048 identity and issue CA X.509 Certificate</div>
                </div>
              </div>
            </div>

            <div className="field-group">
              <label className="field-label">User Handle / Entity Name</label>
              <input 
                className="input-box" 
                value={userHandle} 
                onChange={(e) => setUserHandle(e.target.value)} 
                placeholder="e.g. v_analyst"
              />
            </div>

            <div className="field-group">
              <label className="field-label">Master Passphrase</label>
              <input 
                type="password"
                className="input-box" 
                value={secretPass} 
                onChange={(e) => setSecretPass(e.target.value)} 
                placeholder="••••••••••••"
              />
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.25rem' }}>
              <button className="btn-primary" onClick={handleRegister} disabled={authLoading}>
                <KeyRound size={16} /> Enroll & Issue Cert
              </button>
              <button className="btn-secondary" onClick={handleLogin} disabled={authLoading}>
                Login & Fetch Cert
              </button>
            </div>

            {authMsg && (
              <div style={{ marginTop: '1rem', padding: '0.75rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.1)', border: '1px solid rgba(99, 102, 241, 0.3)', fontSize: '0.82rem', color: '#c7d2fe' }}>
                {authMsg}
              </div>
            )}
          </div>

          <div className="deck-card">
            <div className="card-heading">
              <div className="card-title-group">
                <FileCheck2 size={20} color="#10b981" />
                <div>
                  <div className="card-title">X.509 v3 Digital Certificate Inspector</div>
                  <div className="card-subtitle">Cryptographic identity token issued by AegisOps Root CA</div>
                </div>
              </div>
              {currentUser?.username && (
                <a 
                  href={`/p1/api/pki/download-cert/${currentUser.username}`}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-secondary"
                  style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}
                >
                  <Download size={14} /> Download .CRT
                </a>
              )}
            </div>

            {currentUser?.x509_certificate_pem ? (
              <div>
                <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
                  <span className="tag-badge success">CA: SIGNED</span>
                  <span className="tag-badge info">RSA-2048</span>
                  <span className="tag-badge info">SHA-256</span>
                </div>
                <pre className="code-display" style={{ maxHeight: '240px' }}>
                  {currentUser.x509_certificate_pem}
                </pre>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                Enroll an identity or login to view and download your signed X.509 Certificate.
              </div>
            )}
          </div>
        </div>
      )}

      {/* 2. RSA WORKBENCH */}
      {activeSection === 'rsa' && (
        <div>
          <div className="cards-grid">
            {/* Input & Control Panel */}
            <div className="deck-card">
              <div className="card-heading">
                <div className="card-title-group">
                  <Lock size={20} color="#6366f1" />
                  <div>
                    <div className="card-title">RSA-2048 Cryptographic Workbench</div>
                    <div className="card-subtitle">OAEP Encryption & PSS Signature Operations</div>
                  </div>
                </div>
                <button className="btn-secondary" onClick={generateFreshRSA} disabled={rsaLoading} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                  <RefreshCw size={13} /> Fresh RSA Pair
                </button>
              </div>

              <div className="field-group">
                <label className="field-label">Directive Plaintext Message</label>
                <textarea 
                  className="textarea-box"
                  value={rsaInput} 
                  onChange={(e) => setRsaInput(e.target.value)} 
                  rows={3}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginTop: '1rem' }}>
                <button className="btn-primary" onClick={handleRsaEncrypt} disabled={rsaLoading}>
                  <Lock size={15} /> RSA-OAEP Encrypt
                </button>
                <button className="btn-secondary" onClick={handleRsaDecrypt} disabled={rsaLoading || !rsaCipherB64}>
                  <Unlock size={15} /> RSA-OAEP Decrypt
                </button>
                <button className="btn-amber" onClick={handleRsaSign} disabled={rsaLoading}>
                  <ShieldCheck size={15} /> RSA-PSS Sign
                </button>
                <button className="btn-secondary" onClick={handleRsaVerify} disabled={rsaLoading || !rsaSignatureB64}>
                  <CheckCircle size={15} /> Verify PSS
                </button>
              </div>

              {rsaVerifyStatus && (
                <div style={{ marginTop: '1rem', padding: '0.75rem', borderRadius: '8px', background: rsaVerifyStatus.is_valid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)', border: `1px solid ${rsaVerifyStatus.is_valid ? '#10b981' : '#f43f5e'}` }}>
                  <div style={{ fontWeight: 700, fontSize: '0.85rem', color: rsaVerifyStatus.is_valid ? '#34d399' : '#fda4af' }}>
                    {rsaVerifyStatus.is_valid ? '✓ RSA-PSS Signature Validated' : '✗ Verification Failed'}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    {rsaVerifyStatus.message || rsaVerifyStatus.error}
                  </div>
                </div>
              )}
            </div>

            {/* Ciphertext & Signature Stream */}
            <div className="deck-card">
              <div className="card-heading">
                <div className="card-title-group">
                  <Hash size={20} color="#a855f7" />
                  <div>
                    <div className="card-title">Cryptographic Output Buffers</div>
                    <div className="card-subtitle">Encrypted ciphertext and signed digest payloads</div>
                  </div>
                </div>
              </div>

              <div className="field-group">
                <label className="field-label">Ciphertext (Base64 • RSA-OAEP-SHA256)</label>
                <pre className="code-display" style={{ maxHeight: '80px' }}>
                  {rsaCipherB64 || 'No ciphertext generated yet. Click "RSA-OAEP Encrypt".'}
                </pre>
              </div>

              {rsaDecryptedText && (
                <div className="field-group">
                  <label className="field-label">Decrypted Plaintext Output</label>
                  <div style={{ padding: '0.65rem 0.85rem', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', color: '#6ee7b7', fontSize: '0.85rem' }}>
                    {rsaDecryptedText}
                  </div>
                </div>
              )}

              <div className="field-group">
                <label className="field-label">Digital Signature (Base64 • RSA-PSS-SHA256)</label>
                <pre className="code-display" style={{ maxHeight: '80px' }}>
                  {rsaSignatureB64 || 'No signature created yet. Click "RSA-PSS Sign".'}
                </pre>
              </div>
            </div>
          </div>

          {/* PEM Key Inspector */}
          <div className="deck-card" style={{ marginTop: '1.5rem' }}>
            <div className="card-heading">
              <div className="card-title-group">
                <KeyRound size={18} color="#6366f1" />
                <div className="card-title">Active 2048-bit RSA PEM Keys</div>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label className="field-label">Public Key (SubjectPublicKeyInfo)</label>
                <pre className="code-display" style={{ maxHeight: '140px' }}>{pubKeyPem}</pre>
              </div>
              <div>
                <label className="field-label">Private Key (PKCS#8 Encrypted Storage)</label>
                <pre className="code-display" style={{ maxHeight: '140px' }}>{privKeyPem}</pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. DIFFIE-HELLMAN MATRIX */}
      {activeSection === 'dh' && (
        <div>
          {/* Controls & Parameter Presets */}
          <div className="deck-card" style={{ marginBottom: '1.5rem' }}>
            <div className="card-heading">
              <div className="card-title-group">
                <KeyRound size={20} color="#6366f1" />
                <div>
                  <div className="card-title">Diffie-Hellman Domain Parameters</div>
                  <div className="card-subtitle">Public prime p, primitive root generator g, and private exponents</div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn-secondary" onClick={() => applyDHPreset('small')} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                  Small Prime (353)
                </button>
                <button className="btn-secondary" onClick={() => applyDHPreset('medium')} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                  Medium Prime (7919)
                </button>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
              <div>
                <label className="field-label">Public Prime (p)</label>
                <input className="input-box" type="number" value={dhPrime} onChange={(e) => setDhPrime(parseInt(e.target.value))} />
              </div>
              <div>
                <label className="field-label">Generator Base (g)</label>
                <input className="input-box" type="number" value={dhGen} onChange={(e) => setDhGen(parseInt(e.target.value))} />
              </div>
              <div>
                <label className="field-label">Alice Private Secret (a)</label>
                <input className="input-box" type="number" value={aliceExponent} onChange={(e) => setAliceExponent(parseInt(e.target.value))} />
              </div>
              <div>
                <label className="field-label">Bob Private Secret (b)</label>
                <input className="input-box" type="number" value={bobExponent} onChange={(e) => setBobExponent(parseInt(e.target.value))} />
              </div>
            </div>
          </div>

          {/* Stepper Timeline */}
          <div className="steps-timeline">
            {[1, 2, 3, 4].map((s) => (
              <div 
                key={s} 
                className={`step-node ${dhStepNum === s ? 'active' : ''} ${dhStepNum > s ? 'completed' : ''}`}
                onClick={() => fetchDHStep(s)}
              >
                <div className="step-node-num">STAGE 0{s}</div>
                <div className="step-node-title">
                  {s === 1 && "Choose Private Secrets"}
                  {s === 2 && "Compute Public Keys"}
                  {s === 3 && "Untrusted Network Exchange"}
                  {s === 4 && "Derive Shared Secret"}
                </div>
              </div>
            ))}
          </div>

          {/* Step Detail View */}
          {dhStepData && (
            <div className="deck-card">
              <div className="card-heading">
                <div className="card-title-group">
                  <div className="card-title">Stage {dhStepData.step}: {dhStepData.title}</div>
                </div>
                <button className="btn-primary" onClick={() => fetchDHStep(dhStepNum < 4 ? dhStepNum + 1 : 1)} style={{ fontSize: '0.8rem', padding: '0.4rem 0.9rem' }}>
                  {dhStepNum < 4 ? "Advance Next Step" : "Reset Flow"} <ArrowRight size={14} />
                </button>
              </div>

              {/* Step 1 & 2: Alice and Bob Panels */}
              {(dhStepData.step === 1 || dhStepData.step === 2) && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                  <div style={{ background: 'rgba(99, 102, 241, 0.08)', border: '1px solid rgba(99, 102, 241, 0.25)', padding: '1.25rem', borderRadius: '10px' }}>
                    <div style={{ fontWeight: 700, color: '#a5b4fc', marginBottom: '0.5rem' }}>Alice's Terminal</div>
                    <div style={{ fontSize: '0.88rem', color: '#e2e8f0', marginBottom: '0.5rem' }}>
                      Private Key: <code>a = {dhStepData.alice?.private_key}</code>
                    </div>
                    {dhStepData.alice?.public_key && (
                      <div style={{ fontSize: '0.88rem', color: '#34d399' }}>
                        Formula: <code>{dhStepData.alice.formula}</code>
                      </div>
                    )}
                  </div>

                  <div style={{ background: 'rgba(139, 92, 246, 0.08)', border: '1px solid rgba(139, 92, 246, 0.25)', padding: '1.25rem', borderRadius: '10px' }}>
                    <div style={{ fontWeight: 700, color: '#c4b5fd', marginBottom: '0.5rem' }}>Bob's Terminal</div>
                    <div style={{ fontSize: '0.88rem', color: '#e2e8f0', marginBottom: '0.5rem' }}>
                      Private Key: <code>b = {dhStepData.bob?.private_key}</code>
                    </div>
                    {dhStepData.bob?.public_key && (
                      <div style={{ fontSize: '0.88rem', color: '#34d399' }}>
                        Formula: <code>{dhStepData.bob.formula}</code>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Step 3: Network Interception */}
              {dhStepData.step === 3 && (
                <div style={{ background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.25)', padding: '1.25rem', borderRadius: '10px' }}>
                  <div style={{ fontWeight: 700, color: '#fbbf24', marginBottom: '0.5rem' }}>
                    Network Traffic Exposed to Eavesdropper (Eve)
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.85rem' }}>
                    <div>
                      <div style={{ color: '#94a3b8' }}>Transmitted Public Packets:</div>
                      <div style={{ marginTop: '0.3rem', color: '#e2e8f0' }}>{dhStepData.channel_transmission.alice_to_bob}</div>
                      <div style={{ marginTop: '0.3rem', color: '#e2e8f0' }}>{dhStepData.channel_transmission.bob_to_alice}</div>
                    </div>
                    <div>
                      <div style={{ color: '#94a3b8' }}>Captured by Eve:</div>
                      <pre className="code-display" style={{ marginTop: '0.3rem', maxHeight: '70px' }}>
                        {JSON.stringify(dhStepData.channel_transmission.eavesdropper_sees)}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* Step 4: Shared Secret Match */}
              {dhStepData.step === 4 && (
                <div style={{ background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '1.5rem', borderRadius: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                    <CheckCircle size={22} color="#10b981" />
                    <div style={{ fontWeight: 800, fontSize: '1.1rem', color: '#34d399' }}>
                      Shared Symmetric Secret Successfully Established!
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                    <div style={{ background: '#090d18', padding: '1rem', borderRadius: '8px' }}>
                      <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>Alice's Independent Computation:</div>
                      <div style={{ fontFamily: 'Fira Code', color: '#34d399', fontSize: '0.95rem', marginTop: '0.2rem' }}>
                        {dhStepData.alice_computation.formula}
                      </div>
                      <div style={{ fontWeight: 700, color: '#ffffff', marginTop: '0.5rem' }}>
                        Secret Key = {dhStepData.alice_computation.shared_secret}
                      </div>
                    </div>
                    <div style={{ background: '#090d18', padding: '1rem', borderRadius: '8px' }}>
                      <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>Bob's Independent Computation:</div>
                      <div style={{ fontFamily: 'Fira Code', color: '#34d399', fontSize: '0.95rem', marginTop: '0.2rem' }}>
                        {dhStepData.bob_computation.formula}
                      </div>
                      <div style={{ fontWeight: 700, color: '#ffffff', marginTop: '0.5rem' }}>
                        Secret Key = {dhStepData.bob_computation.shared_secret}
                      </div>
                    </div>
                  </div>
                  <p style={{ fontSize: '0.84rem', color: '#94a3b8' }}>{dhStepData.explanation}</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 4. ELGAMAL & SHA-512 */}
      {activeSection === 'elgamal' && (
        <div className="cards-grid">
          <div className="deck-card">
            <div className="card-heading">
              <div className="card-title-group">
                <Hash size={20} color="#f59e0b" />
                <div>
                  <div className="card-title">Elgamal Digital Signature & SHA-512</div>
                  <div className="card-subtitle">Discrete logarithm digital signature with 512-bit hashing</div>
                </div>
              </div>
              <button className="btn-secondary" onClick={generateElgamalKeys} disabled={elgamalLoading} style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                <RefreshCw size={13} /> Fresh Domain
              </button>
            </div>

            <div className="field-group">
              <label className="field-label">Message Payload</label>
              <textarea 
                className="textarea-box" 
                value={elgamalMessage} 
                onChange={(e) => setElgamalMessage(e.target.value)} 
                rows={2}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem', marginTop: '1rem' }}>
              <button className="btn-secondary" onClick={handleComputeHash} disabled={elgamalLoading}>
                <Hash size={14} /> SHA-512 Hash
              </button>
              <button className="btn-amber" onClick={handleElgamalSign} disabled={elgamalLoading}>
                <Lock size={14} /> Elgamal Sign
              </button>
              <button className="btn-primary" onClick={handleElgamalVerify} disabled={elgamalLoading || !elgamalSigData}>
                <CheckCircle size={14} /> Verify
              </button>
            </div>

            {/* Verification Result */}
            {elgamalVerifyResult && (
              <div style={{ marginTop: '1.25rem', padding: '1rem', borderRadius: '8px', background: elgamalVerifyResult.is_valid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)', border: `1px solid ${elgamalVerifyResult.is_valid ? '#10b981' : '#f43f5e'}` }}>
                <div style={{ fontWeight: 800, color: elgamalVerifyResult.is_valid ? '#34d399' : '#fda4af' }}>
                  {elgamalVerifyResult.is_valid ? '✓ Elgamal Signature Validated!' : '✗ Signature Invalid'}
                </div>
                <div style={{ fontFamily: 'Fira Code', fontSize: '0.78rem', color: '#e2e8f0', marginTop: '0.5rem' }}>
                  LHS: {elgamalVerifyResult.v1_left_hand_side}
                </div>
                <div style={{ fontFamily: 'Fira Code', fontSize: '0.78rem', color: '#e2e8f0', marginTop: '0.2rem' }}>
                  RHS: {elgamalVerifyResult.v2_right_hand_side}
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.4rem' }}>
                  Condition: {elgamalVerifyResult.comparison}
                </div>
              </div>
            )}
          </div>

          {/* Mathematical Telemetry Display */}
          <div className="deck-card">
            <div className="card-heading">
              <div className="card-title-group">
                <FileCheck2 size={20} color="#6366f1" />
                <div>
                  <div className="card-title">Mathematical Parameters & Signatures</div>
                  <div className="card-subtitle">Discrete log finite field GF(p) and signature elements (r, s)</div>
                </div>
              </div>
            </div>

            {elgamalKeyData && (
              <div style={{ marginBottom: '1rem' }}>
                <label className="field-label">Domain Parameters</label>
                <div style={{ background: '#090d18', padding: '0.65rem', borderRadius: '8px', fontFamily: 'Fira Code', fontSize: '0.78rem', color: '#a5b4fc' }}>
                  p = {elgamalKeyData.p} | g = {elgamalKeyData.g} | Public Key y = {elgamalKeyData.public_key_y}
                </div>
              </div>
            )}

            {elgamalHashData && (
              <div className="field-group">
                <label className="field-label">SHA-512 Digest (512-bit hex)</label>
                <pre className="code-display" style={{ maxHeight: '75px' }}>
                  {elgamalHashData.sha512_hex}
                </pre>
              </div>
            )}

            {elgamalSigData && (
              <div className="field-group">
                <label className="field-label">Signature Pair (r, s) & Ephemeral Key k</label>
                <div style={{ background: '#090d18', padding: '0.75rem', borderRadius: '8px', fontFamily: 'Fira Code', fontSize: '0.8rem', color: '#fbbf24' }}>
                  <div>r = {elgamalSigData.signature_r}</div>
                  <div style={{ marginTop: '0.25rem' }}>s = {elgamalSigData.signature_s}</div>
                  <div style={{ marginTop: '0.25rem', color: '#94a3b8', fontSize: '0.74rem' }}>
                    ephemeral k = {elgamalSigData.ephemeral_k}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
