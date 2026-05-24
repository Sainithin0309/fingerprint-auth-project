import { useState, useEffect, useCallback } from "react";
import { ethers } from "ethers";
import axios from "axios";
import { CONTRACTS, NETWORK, BACKEND_URL, RELAY_URL } from "./config";
import "./App.css";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatAddr(addr) {
  return addr ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : "";
}

function StatusDot({ ok }) {
  return <span className={`dot ${ok ? "dot-ok" : "dot-off"}`} />;
}

function Step({ n, label, active, done }) {
  return (
    <div className={`step ${active ? "step-active" : ""} ${done ? "step-done" : ""}`}>
      <div className="step-num">{done ? "✓" : n}</div>
      <span>{label}</span>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  // Wallet
  const [account, setAccount] = useState(null);
  const [provider, setProvider] = useState(null);
  const [network, setNetwork] = useState(null);
  const [onSepolia, setOnSepolia] = useState(false);

  // Flow state
  const [stage, setStage] = useState("idle"); // idle | registering | validating | otp | submitting | done | error
  const [log, setLog] = useState([]);
  const [txHash, setTxHash] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  // Form fields
  const [userId, setUserId] = useState("");
  const [credId, setCredId] = useState("");
  const [name, setName] = useState("");
  const [dob, setDob] = useState("");
  const [country, setCountry] = useState("");
  const [spo2, setSpo2] = useState("97");
  const [otp, setOtp] = useState("");
  const [zkpData, setZkpData] = useState(null);
  const [vcData, setVcData] = useState(null);

  // Services health
  const [health, setHealth] = useState({ backend: null, relay: null });

  // Tabs
  const [tab, setTab] = useState("auth"); // auth | register | vc | audit

  // ── Logging
  const addLog = useCallback((msg, type = "info") => {
    setLog(prev => [...prev, { msg, type, ts: new Date().toLocaleTimeString() }]);
  }, []);

  // ── Health check
  useEffect(() => {
    const check = async () => {
      try {
        const r = await axios.get(`${BACKEND_URL}/health`, { timeout: 8000 });
        setHealth(h => ({ ...h, backend: r.status === 200 }));
      } catch { setHealth(h => ({ ...h, backend: false })); }
      try {
        const r = await axios.get(`${RELAY_URL}/health`, { timeout: 8000 });
        setHealth(h => ({ ...h, relay: r.data?.coordinator === "online" }));
      } catch { setHealth(h => ({ ...h, relay: false })); }
    };
    check();
  }, []);

  // ── MetaMask connect
  const connectWallet = async () => {
    if (!window.ethereum) {
      setErrorMsg("MetaMask not detected. Please install MetaMask.");
      return;
    }
    try {
      const p = new ethers.providers.Web3Provider(window.ethereum);
      const accounts = await p.send("eth_requestAccounts", []);
      const net = await p.getNetwork();
      setProvider(p);
      setAccount(accounts[0]);
      setNetwork(net);
      setOnSepolia(net.chainId === 11155111);
      addLog(`Wallet connected: ${formatAddr(accounts[0])}`, "ok");
      if (net.chainId !== 11155111) addLog("⚠ Switch to Sepolia testnet for on-chain verification", "warn");
    } catch (e) {
      setErrorMsg("Wallet connection rejected.");
    }
  };

  const switchToSepolia = async () => {
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: NETWORK.chainId }]
      });
      const p = new ethers.providers.Web3Provider(window.ethereum);
      const net = await p.getNetwork();
      setNetwork(net);
      setOnSepolia(net.chainId === 11155111);
      addLog("Switched to Sepolia", "ok");
    } catch {
      addLog("Could not switch network automatically — switch manually in MetaMask", "warn");
    }
  };

  // ── Registration
  const handleRegister = async () => {
    if (!userId || !credId || !name || !dob || !country) {
      setErrorMsg("Fill all registration fields.");
      return;
    }
    setStage("registering");
    setErrorMsg(null);
    addLog("Submitting registration to PEUAP-W3 backend…");
    try {
      const res = await axios.post(`${BACKEND_URL}/register`, {
        user_id: userId, credential_id: credId,
        name, date_of_birth: dob, country
      });
      addLog(`Registration successful: ${res.data.status}`, "ok");
      setStage("idle");
      setTab("auth");
    } catch (e) {
      const msg = e.response?.data?.error || e.message;
      setErrorMsg(`Registration failed: ${msg}`);
      addLog(`Registration failed: ${msg}`, "err");
      setStage("idle");
    }
  };

  // ── Validate → get OTP
  const handleValidate = async () => {
    if (!userId || !credId) {
      setErrorMsg("Enter User ID and Credential ID.");
      return;
    }
    setStage("validating");
    setErrorMsg(null);
    setZkpData(null);
    addLog("Sending authentication request…");
    try {
      const res = await axios.post(`${BACKEND_URL}/validate`, {
        user_id: userId, credential_id: credId, spo2_value: parseInt(spo2)
      });
      addLog(`ZKP generated. OTP issued. Commitment: ${res.data.commitment?.slice(0, 16)}…`, "ok");
      addLog("Enter the OTP shown on the server response to retrieve your ZKP proof.", "info");
      // In a real device flow the OTP goes to user's device; here show it for demo
      if (res.data.otp) addLog(`[DEMO] OTP: ${res.data.otp}`, "warn");
      setStage("otp");
    } catch (e) {
      const msg = e.response?.data?.error || e.message;
      setErrorMsg(`Authentication failed: ${msg}`);
      addLog(`Authentication failed: ${msg}`, "err");
      setStage("idle");
    }
  };

  // ── Redeem OTP → get ZKP
  const handleGetZkp = async () => {
    if (!otp) { setErrorMsg("Enter OTP."); return; }
    setStage("submitting");
    setErrorMsg(null);
    addLog("Redeeming OTP and retrieving ZKP proof…");
    try {
      const res = await axios.post(`${BACKEND_URL}/get_zkp`, {
        user_id: userId, otp
      });
      setZkpData(res.data);
      addLog("ZKP proof retrieved. Ready for on-chain submission.", "ok");
      setStage("ready");
    } catch (e) {
      const msg = e.response?.data?.error || e.message;
      setErrorMsg(`OTP redemption failed: ${msg}`);
      addLog(`OTP failed: ${msg}`, "err");
      setStage("otp");
    }
  };

  // ── Submit ZKP on-chain
  const handleOnChain = async () => {
    if (!zkpData || !provider || !onSepolia) {
      setErrorMsg("Connect MetaMask to Sepolia first.");
      return;
    }
    setStage("submitting");
    setErrorMsg(null);
    addLog("Preparing Groth16 proof for on-chain submission…");

    try {
      const signer = provider.getSigner();
      const contract = new ethers.Contract(
        CONTRACTS.AuthenticatorContract.address,
        CONTRACTS.AuthenticatorContract.abi,
        signer
      );

      const op = zkpData.onchain_proof;
      if (!op) throw new Error("No onchain_proof in ZKP response. Check backend /get_zkp response.");

      const a = op.a.map(x => ethers.BigNumber.from(x));
      const b = [
        [ethers.BigNumber.from(op.b[0][1]), ethers.BigNumber.from(op.b[0][0])],
        [ethers.BigNumber.from(op.b[1][1]), ethers.BigNumber.from(op.b[1][0])]
      ];
      const c = op.c.map(x => ethers.BigNumber.from(x));
      const pub = op.publicSignals.map(x => ethers.BigNumber.from(x));

      addLog("Sending transaction to AuthenticatorContract.authenticate()…");
      addLog(`Contract: ${CONTRACTS.AuthenticatorContract.address}`, "info");

      const tx = await contract.authenticate(a, b, c, pub);
      addLog(`Transaction submitted: ${tx.hash}`, "ok");
      addLog("Waiting for Sepolia confirmation…");

      const receipt = await tx.wait();
      setTxHash(tx.hash);
      addLog(`✅ Confirmed in block ${receipt.blockNumber}. Groth16 proof VERIFIED on-chain.`, "ok");

      // Issue VC
      addLog("Issuing W3C Verifiable Credential…");
      const vcRes = await axios.post(`${BACKEND_URL}/vc/issue`, {
        user_id: userId,
        proof_hash: tx.hash,
        commitment: zkpData.commitment
      });
      setVcData(vcRes.data.credential);
      addLog(`VC issued. DID: ${vcRes.data.credential?.credentialSubject?.id}`, "ok");

      // Distribute to relay nodes
      addLog("Distributing identity to relay nodes (Shamir SSS)…");
      try {
        await axios.post(`${RELAY_URL}/distribute`, {
          session_id: `${userId}-${Date.now()}`,
          identity_payload: `${userId}:authenticated:${new Date().toISOString()}`,
          proof_hash: tx.hash
        });
        addLog("Identity distributed across 3 relay nodes (k=2-of-3).", "ok");
      } catch { addLog("Relay distribution skipped (cold start).", "warn"); }

      setStage("done");
    } catch (e) {
      const msg = e.reason || e.data?.message || e.message;
      setErrorMsg(`On-chain verification failed: ${msg}`);
      addLog(`Error: ${msg}`, "err");
      setStage("ready");
    }
  };

  // ─── Render ─────────────────────────────────────────────────────────────────

  const steps = [
    { label: "Connect Wallet", done: !!account },
    { label: "Authenticate", done: stage === "otp" || stage === "ready" || stage === "done" },
    { label: "Retrieve ZKP", done: stage === "ready" || stage === "done" },
    { label: "Verify On-Chain", done: stage === "done" }
  ];

  return (
    <div className="app">
      {/* Background grid */}
      <div className="bg-grid" />
      <div className="bg-glow" />

      {/* Header */}
      <header className="header">
        <div className="header-left">
          <div className="logo-mark">⬡</div>
          <div>
            <div className="logo-title">PEUAP-W3</div>
            <div className="logo-sub">Zero-Knowledge Biometric Authentication</div>
          </div>
        </div>
        <div className="header-right">
          <div className="health-row">
            <StatusDot ok={health.backend} />
            <span>Backend</span>
            <StatusDot ok={health.relay} />
            <span>Relay</span>
            <StatusDot ok={onSepolia} />
            <span>Sepolia</span>
          </div>
          {!account ? (
            <button className="btn btn-primary" onClick={connectWallet}>
              Connect Wallet
            </button>
          ) : (
            <div className="wallet-pill">
              <span className="wallet-addr">{formatAddr(account)}</span>
              {!onSepolia && (
                <button className="btn btn-warn btn-sm" onClick={switchToSepolia}>
                  Switch to Sepolia
                </button>
              )}
            </div>
          )}
        </div>
      </header>

      {/* Progress steps */}
      <div className="steps-row">
        {steps.map((s, i) => (
          <Step key={i} n={i + 1} label={s.label}
            done={s.done}
            active={i === steps.filter(x => x.done).length} />
        ))}
      </div>

      {/* Tabs */}
      <div className="tabs">
        {["auth", "register", "vc", "audit"].map(t => (
          <button key={t} className={`tab ${tab === t ? "tab-active" : ""}`}
            onClick={() => setTab(t)}>
            {{ auth: "🔐 Authenticate", register: "📝 Register", vc: "📜 Credential", audit: "🔍 Audit" }[t]}
          </button>
        ))}
      </div>

      {/* Main panel */}
      <div className="main">
        <div className="panel">

          {/* ── AUTH TAB ── */}
          {tab === "auth" && (
            <div className="tab-content">
              <h2 className="panel-title">Biometric Authentication</h2>
              <p className="panel-desc">Prove your identity without revealing your fingerprint data using Groth16 ZKP.</p>

              {errorMsg && <div className="alert alert-err">{errorMsg}</div>}

              {(stage === "idle" || stage === "validating") && (
                <div className="form-group">
                  <label>User ID</label>
                  <input className="input" placeholder="e.g. user123" value={userId}
                    onChange={e => setUserId(e.target.value)} />
                  <label>Credential ID <span className="label-hint">(fingerprint hash)</span></label>
                  <input className="input" placeholder="SHA-256 of fingerprint" value={credId}
                    onChange={e => setCredId(e.target.value)} />
                  <label>SpO₂ Value <span className="label-hint">(liveness — 85–100)</span></label>
                  <input className="input" type="number" min="85" max="100" value={spo2}
                    onChange={e => setSpo2(e.target.value)} />
                  <button className="btn btn-primary btn-full"
                    onClick={handleValidate}
                    disabled={stage === "validating"}>
                    {stage === "validating" ? "Generating ZKP…" : "Generate ZKP Proof"}
                  </button>
                </div>
              )}

              {stage === "otp" && (
                <div className="form-group">
                  <div className="alert alert-ok">ZKP generated. Enter your one-time password to retrieve the proof.</div>
                  <label>OTP <span className="label-hint">(6-digit, valid 5 min)</span></label>
                  <input className="input input-otp" placeholder="000000" maxLength={6}
                    value={otp} onChange={e => setOtp(e.target.value)} />
                  <button className="btn btn-primary btn-full" onClick={handleGetZkp}>
                    Retrieve ZKP Proof
                  </button>
                  <button className="btn btn-ghost btn-full" onClick={() => setStage("idle")}>
                    ← Back
                  </button>
                </div>
              )}

              {stage === "ready" && zkpData && (
                <div className="form-group">
                  <div className="alert alert-ok">
                    ZKP proof ready. Submit to Sepolia for on-chain Groth16 verification.
                  </div>
                  <div className="proof-box">
                    <div className="proof-label">Commitment (public)</div>
                    <div className="proof-val">{zkpData.commitment?.slice(0, 40)}…</div>
                    <div className="proof-label">Circuit</div>
                    <div className="proof-val">Groth16 / Poseidon / BN254</div>
                    <div className="proof-label">Public Signals</div>
                    <div className="proof-val">[commitment, nonce, hmac, 85, 100, 1]</div>
                  </div>
                  {!account ? (
                    <button className="btn btn-primary btn-full" onClick={connectWallet}>
                      Connect MetaMask to Submit
                    </button>
                  ) : !onSepolia ? (
                    <button className="btn btn-warn btn-full" onClick={switchToSepolia}>
                      Switch to Sepolia
                    </button>
                  ) : (
                    <button className="btn btn-primary btn-full" onClick={handleOnChain}
                      disabled={stage === "submitting"}>
                      {stage === "submitting" ? "Submitting…" : "Verify On-Chain →"}
                    </button>
                  )}
                  <button className="btn btn-ghost btn-full" onClick={() => setStage("idle")}>
                    ← Start Over
                  </button>
                </div>
              )}

              {stage === "done" && txHash && (
                <div className="form-group">
                  <div className="success-card">
                    <div className="success-icon">✓</div>
                    <div className="success-title">Authentication Complete</div>
                    <div className="success-sub">Groth16 proof verified on Ethereum Sepolia</div>
                  </div>
                  <div className="proof-box">
                    <div className="proof-label">Transaction Hash</div>
                    <div className="proof-val">{txHash.slice(0, 20)}…</div>
                    <div className="proof-label">Network</div>
                    <div className="proof-val">Ethereum Sepolia (chain 11155111)</div>
                    <div className="proof-label">Contract</div>
                    <div className="proof-val">AuthenticatorContract · {formatAddr(CONTRACTS.AuthenticatorContract.address)}</div>
                  </div>
                  <a className="btn btn-outline btn-full"
                    href={`https://sepolia.etherscan.io/tx/${txHash}`}
                    target="_blank" rel="noreferrer">
                    View on Sepolia Etherscan ↗
                  </a>
                  <button className="btn btn-ghost btn-full" onClick={() => {
                    setStage("idle"); setZkpData(null); setTxHash(null); setOtp(""); setTab("vc");
                  }}>
                    View Verifiable Credential →
                  </button>
                </div>
              )}
            </div>
          )}

          {/* ── REGISTER TAB ── */}
          {tab === "register" && (
            <div className="tab-content">
              <h2 className="panel-title">Register Biometric Identity</h2>
              <p className="panel-desc">Register your credential ID (fingerprint hash) with 3-layer onion encryption.</p>
              {errorMsg && <div className="alert alert-err">{errorMsg}</div>}
              <div className="form-group">
                <label>User ID</label>
                <input className="input" placeholder="Unique identifier" value={userId}
                  onChange={e => setUserId(e.target.value)} />
                <label>Full Name</label>
                <input className="input" placeholder="Your name" value={name}
                  onChange={e => setName(e.target.value)} />
                <label>Date of Birth</label>
                <input className="input" type="date" value={dob}
                  onChange={e => setDob(e.target.value)} />
                <label>Country</label>
                <input className="input" placeholder="IN, US, GB …" value={country}
                  onChange={e => setCountry(e.target.value)} />
                <label>Credential ID <span className="label-hint">(SHA-256 fingerprint hash)</span></label>
                <input className="input" placeholder="0x..." value={credId}
                  onChange={e => setCredId(e.target.value)} />
                <div className="hint-box">
                  <b>Note:</b> All fields are encrypted with 3-layer Fernet onion encryption before storage.
                  Your biometric data is never stored in plaintext.
                </div>
                <button className="btn btn-primary btn-full" onClick={handleRegister}
                  disabled={stage === "registering"}>
                  {stage === "registering" ? "Registering…" : "Register Identity"}
                </button>
              </div>
            </div>
          )}

          {/* ── VC TAB ── */}
          {tab === "vc" && (
            <div className="tab-content">
              <h2 className="panel-title">Verifiable Credential</h2>
              <p className="panel-desc">W3C VC 2.0 — Ed25519 signed, Bitstring Status List revocable.</p>
              {vcData ? (
                <div className="vc-card">
                  <div className="vc-header">
                    <span className="vc-badge">PEUAPBiometricCredential</span>
                    <span className="vc-valid">Valid</span>
                  </div>
                  <div className="vc-row"><span>Issuer DID</span><span className="mono">{vcData.issuer?.slice(0, 30)}…</span></div>
                  <div className="vc-row"><span>Subject DID</span><span className="mono">{vcData.credentialSubject?.id?.slice(0, 30)}…</span></div>
                  <div className="vc-row"><span>Method</span><span className="mono">{vcData.credentialSubject?.authenticationMethod}</span></div>
                  <div className="vc-row"><span>Assurance</span><span className="mono">{vcData.credentialSubject?.assuranceLevel}</span></div>
                  <div className="vc-row"><span>Proof Type</span><span className="mono">{vcData.proof?.type}</span></div>
                  <div className="vc-row"><span>Issued</span><span className="mono">{vcData.issuanceDate?.slice(0, 10)}</span></div>
                  <div className="vc-row"><span>Expires</span><span className="mono">{vcData.expirationDate?.slice(0, 10)}</span></div>
                  <div className="vc-row"><span>Status Index</span><span className="mono">{vcData.credentialStatus?.statusListIndex}</span></div>
                  <div className="vc-commitment">
                    <div className="proof-label">Biometric Commitment</div>
                    <div className="proof-val">{vcData.credentialSubject?.biometricCommitment?.slice(0, 30)}…</div>
                  </div>
                  <a className="btn btn-outline btn-full"
                    href={`${BACKEND_URL}/vc/status-list`} target="_blank" rel="noreferrer">
                    View Status List ↗
                  </a>
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-icon">📜</div>
                  <p>Complete authentication first to receive your Verifiable Credential.</p>
                  <button className="btn btn-primary" onClick={() => setTab("auth")}>
                    Go to Authentication
                  </button>
                </div>
              )}
            </div>
          )}

          {/* ── AUDIT TAB ── */}
          {tab === "audit" && (
            <div className="tab-content">
              <h2 className="panel-title">On-Chain Audit</h2>
              <p className="panel-desc">Immutable audit trail on Ethereum Sepolia — no PII stored.</p>
              <div className="audit-grid">
                {[
                  { label: "BiometricVerifier", addr: CONTRACTS.BiometricVerifier.address, desc: "Groth16 on-chain verifier" },
                  { label: "IdentifierStorage", addr: CONTRACTS.IdentifierStorage.address, desc: "VC commitment registry" },
                  { label: "AuditTrail", addr: CONTRACTS.AuditTrail.address, desc: "k-of-n audit log" },
                  { label: "AuthenticatorContract", addr: CONTRACTS.AuthenticatorContract.address, desc: "Main entry point" }
                ].map(c => (
                  <div className="audit-card" key={c.label}>
                    <div className="audit-label">{c.label}</div>
                    <div className="audit-desc">{c.desc}</div>
                    <div className="audit-addr">{c.addr}</div>
                    <a className="btn btn-outline btn-sm btn-full"
                      href={`https://sepolia.etherscan.io/address/${c.addr}`}
                      target="_blank" rel="noreferrer">
                      Etherscan ↗
                    </a>
                  </div>
                ))}
              </div>
              <div className="hint-box" style={{ marginTop: "1.5rem" }}>
                <b>Privacy guarantee:</b> All on-chain data is pseudonymous. No names, dates of birth,
                or biometric data are stored on Ethereum. Only Poseidon commitments and ZKP proof hashes.
              </div>
              {txHash && (
                <div className="proof-box" style={{ marginTop: "1rem" }}>
                  <div className="proof-label">Your last transaction</div>
                  <div className="proof-val">{txHash}</div>
                  <a className="btn btn-outline btn-sm"
                    href={`https://sepolia.etherscan.io/tx/${txHash}`}
                    target="_blank" rel="noreferrer" style={{ marginTop: "0.5rem", display: "inline-block" }}>
                    View ↗
                  </a>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Activity log */}
        <div className="log-panel">
          <div className="log-title">Activity Log</div>
          <div className="log-body">
            {log.length === 0 && <div className="log-empty">Waiting for activity…</div>}
            {log.map((l, i) => (
              <div key={i} className={`log-line log-${l.type}`}>
                <span className="log-ts">{l.ts}</span>
                <span>{l.msg}</span>
              </div>
            ))}
          </div>
          {log.length > 0 && (
            <button className="btn btn-ghost btn-sm" onClick={() => setLog([])}>Clear</button>
          )}
        </div>
      </div>

      {/* Footer */}
      <footer className="footer">
        <span>PEUAP-W3 · Alliance University PhD Research</span>
        <span>·</span>
        <a href="https://github.com/Sainithin0309/fingerprint-auth-project" target="_blank" rel="noreferrer">GitHub ↗</a>
        <span>·</span>
        <a href="https://sepolia.etherscan.io/address/0x720b8EC75b7551b8663a2C8906eBB9D7625d49b7" target="_blank" rel="noreferrer">Etherscan ↗</a>
        <span>·</span>
        <a href={`${BACKEND_URL}/did/issuer`} target="_blank" rel="noreferrer">DID Document ↗</a>
      </footer>
    </div>
  );
}
