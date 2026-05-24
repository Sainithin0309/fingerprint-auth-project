import { useEffect, useState } from 'react';
import { ethers } from 'ethers';
import './App.css';
import verifierArtifact from './abi/Groth16Verifier.json';

const CONTRACT_ADDRESS = process.env.REACT_APP_CONTRACT_ADDRESS;
const HMAC_SECRET      = process.env.REACT_APP_HMAC_SECRET;

const users = {
  Sai123:   { name: 'Sainithin',       access: 'Full Access'    },
  Venky123: { name: 'Venkatesh',       access: 'Limited Access' },
  Adarsh:   { name: 'Adarsh S V Nair', access: 'Admin'         },
};

function validateProofStructure(proof) {
  return (
    Array.isArray(proof.a) &&
    Array.isArray(proof.b) &&
    Array.isArray(proof.c) &&
    Array.isArray(proof.publicSignals) &&
    proof.a.length === 2 &&
    proof.b.length === 2 &&
    proof.b[0].length === 2 &&
    proof.b[1].length === 2 &&
    proof.c.length === 2 &&
    proof.publicSignals.length === 6
  );
}

async function verifyHMAC(payload, timestamp, receivedHMAC) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(HMAC_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  return crypto.subtle.verify(
    'HMAC',
    key,
    Uint8Array.from(atob(receivedHMAC), c => c.charCodeAt(0)),
    encoder.encode(JSON.stringify(payload) + timestamp)
  );
}

function App() {
  const [proof, setProof]                 = useState(null);
  const [publicSignals, setPublicSignals] = useState(null);
  const [userId, setUserId]               = useState('');
  const [status, setStatus]               = useState('Waiting for ZKP via extension...');
  const [isVerified, setIsVerified]       = useState(false);
  const [txHash, setTxHash]               = useState('');

  useEffect(() => {
    if (window.location.protocol !== 'https:') {
      setStatus('⚠️ Please use HTTPS for secure Web3 interactions.');
    }

    const handleZkpMessage = async (event) => {
      const { type, payload, timestamp, hmac } = event.data || {};
      if (type !== 'ZKP_DATA') return;

      if (!payload?.onchain_proof || !payload?.user_id || !timestamp || !hmac) {
        setStatus('❌ Incomplete ZKP payload from extension.');
        return;
      }

      if (Math.abs(Date.now() - timestamp) > 30000) {
        setStatus('❌ Message timestamp too old or invalid.');
        return;
      }

      const isValid = await verifyHMAC(payload, timestamp, hmac);
      if (!isValid) {
        setStatus('❌ HMAC verification failed.');
        return;
      }

      const { onchain_proof, user_id } = payload;

      if (!users[user_id]) {
        setStatus(`❌ User ID "${user_id}" not recognized.`);
        return;
      }

      if (!validateProofStructure(onchain_proof)) {
        setStatus('❌ Invalid ZKP structure. Expected 6 public signals.');
        return;
      }

      setProof({ a: onchain_proof.a, b: onchain_proof.b, c: onchain_proof.c });
      setPublicSignals(onchain_proof.publicSignals);
      setUserId(user_id);
      setStatus('✅ ZKP received. Click "Verify On-Chain" to authenticate.');
    };

    window.addEventListener('message', handleZkpMessage);
    return () => window.removeEventListener('message', handleZkpMessage);
  }, []);

  const verifyProof = async () => {
    if (!window.ethereum) {
      return setStatus('❌ MetaMask not detected.');
    }
    try {
      setStatus('⏳ Connecting to MetaMask...');
      const provider = new ethers.providers.Web3Provider(window.ethereum);
      await provider.send('eth_requestAccounts', []);
      const signer = provider.getSigner();

      const network = await provider.getNetwork();
      if (network.chainId !== 11155111) {
        setStatus('❌ Please switch MetaMask to Sepolia testnet.');
        return;
      }

      setStatus('⏳ Submitting proof to Sepolia...');
      const contract = new ethers.Contract(CONTRACT_ADDRESS, verifierArtifact.abi, signer);
      const result = await contract.verifyProof(proof.a, proof.b, proof.c, publicSignals);

      if (result) {
        setStatus(`✅ Verified! Welcome ${users[userId].name} — ${users[userId].access} 🎬`);
        setIsVerified(true);
      } else {
        setStatus('❌ ZKP verification failed on-chain.');
      }
    } catch (error) {
      console.error(error);
      if (error?.transaction?.hash) setTxHash(error.transaction.hash);
      setStatus('❌ ' + (error.reason || error.message || 'Verification failed'));
    }
  };

  return (
    <div className="App">
      <h1>PEUAP-W3 🔐</h1>
      <p style={{ fontSize: '0.85rem', color: '#888', marginTop: '-10px', marginBottom: '20px' }}>
        Privacy-Enhanced &amp; User-Centric Authentication for Web 3.0
      </p>

      <div className="info-box">
        <p><strong>User ID:</strong> {userId || <em>Not received yet</em>}</p>
        <p><strong>Network:</strong> Ethereum Sepolia Testnet</p>
        <p>
          <strong>Contract:</strong>{' '}
          <a href={`https://sepolia.etherscan.io/address/${CONTRACT_ADDRESS}`} target="_blank" rel="noreferrer">
            {CONTRACT_ADDRESS?.slice(0,8)}...{CONTRACT_ADDRESS?.slice(-6)}
          </a>
        </p>
      </div>

      <div className="status-box"><p>{status}</p></div>

      {txHash && (
        <p style={{ fontSize: '0.8rem', margin: '8px 0' }}>
          Tx: <a href={`https://sepolia.etherscan.io/tx/${txHash}`} target="_blank" rel="noreferrer">{txHash.slice(0,12)}...</a>
        </p>
      )}

      {proof && publicSignals && users[userId] && !isVerified && (
        <button onClick={verifyProof} className="verify-btn">🔗 Verify On-Chain (Sepolia)</button>
      )}

      {!proof && !isVerified && (
        <div className="instructions">
          <p>How to authenticate:</p>
          <ol>
            <li>Register on the <a href="https://fingerprint-auth-using-zkp.onrender.com" target="_blank" rel="noreferrer">backend</a></li>
            <li>Validate fingerprint to get OTP</li>
            <li>Open the <strong>WEB3.0 Authenticator</strong> extension</li>
            <li>Enter User ID + OTP → Fetch ZKP → Pass to Web3</li>
            <li>This page receives the proof automatically</li>
          </ol>
        </div>
      )}

      {isVerified && (
        <div className="success-box">
          <h2>🎉 Authentication Successful</h2>
          <p>Biometric ZKP verified on Ethereum Sepolia</p>
          <p>No biometric data was revealed to the blockchain.</p>
        </div>
      )}
    </div>
  );
}

export default App;
