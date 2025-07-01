import { useEffect, useState } from 'react';
import { ethers } from 'ethers';
import './App.css';
import verifierArtifact from './abi/Groth16Verifier.json';

const CONTRACT_ADDRESS = '0x9457BE3F595c8504e4105a6306b92d65F6CaeEE9'; // ✅ Sepolia contract address

// ✅ Access control
const users = {
  Sai123: { name: 'Sainithin', access: 'Full access' },
  Venky123: { name: 'Venkatesh', access: 'Limited access' },
};

// ✅ Sanitize & validate ZKP param
function sanitizeJsonInput(str) {
  try {
    const parsed = JSON.parse(decodeURIComponent(str));
    if (
      typeof parsed === 'object' &&
      parsed.a &&
      parsed.b &&
      parsed.c &&
      parsed.publicSignals
    ) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

// ✅ Validate ZKP structure before using
function validateProofStructure(proof) {
  return (
    Array.isArray(proof.a) &&
    Array.isArray(proof.b) &&
    Array.isArray(proof.c) &&
    proof.a.length === 2 &&
    proof.b.length === 2 &&
    proof.b[0].length === 2 &&
    proof.b[1].length === 2 &&
    proof.c.length === 2
  );
}

function App() {
  const [proof, setProof] = useState(null);
  const [publicSignals, setPublicSignals] = useState(null);
  const [userId, setUserId] = useState('');
  const [status, setStatus] = useState('Waiting for ZKP and User ID in URL...');
  const [isVerified, setIsVerified] = useState(false);

  // ✅ Check HTTPS usage (important for MetaMask)
  useEffect(() => {
    if (window.location.protocol !== 'https:') {
      setStatus('⚠️ Please use HTTPS for secure Web3 interactions.');
    }
  }, []);

  // ✅ Load ZKP + user ID from URL
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const zkpParam = params.get('zkp');
    const userParam = params.get('userid')?.replace(/[^a-zA-Z0-9]/g, '').trim();

    if (userParam) {
      setUserId(userParam);
      if (!users[userParam]) {
        setStatus('❌ User ID not authorized.');
        return;
      }
    }

    if (zkpParam) {
      const decodedZkp = sanitizeJsonInput(zkpParam);
      if (decodedZkp) {
        setProof({
          a: decodedZkp.a,
          b: decodedZkp.b,
          c: decodedZkp.c,
        });
        setPublicSignals(decodedZkp.publicSignals);
        setStatus('✅ ZKP and User ID loaded from URL.');
      } else {
        setStatus('❌ Invalid or tampered ZKP.');
      }
    } else {
      setStatus('❌ ZKP not found in URL.');
    }
  }, []);

  const verifyProof = async () => {
    if (!window.ethereum) {
      return setStatus('❌ MetaMask not detected.');
    }

    if (!validateProofStructure(proof)) {
      return setStatus('❌ Invalid ZKP structure.');
    }

    try {
      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();
      const contract = new ethers.Contract(CONTRACT_ADDRESS, verifierArtifact.abi, signer);

      const { a, b, c } = proof;
      const inputs = publicSignals;

      const result = await contract.verifyProof(a, b, c, inputs);
      if (result) {
        const user = users[userId];
        setStatus(`✅ ZKP verified successfully! Welcome ${user.name}. You have ${user.access}. Enjoy decentralized streaming!`);
        setIsVerified(true);
      } else {
        setStatus('❌ ZKP invalid.');
      }
    } catch (error) {
      console.error(error);
      setStatus('❌ Verification failed.');
    }
  };

  return (
    <div className="App">
      <h1>Web3flix</h1>
      <p><strong>User ID:</strong> {userId || 'Not provided'}</p>
      <p><strong>Status:</strong> {status}</p>
      {proof && publicSignals && users[userId] && !isVerified ? (
        <button onClick={verifyProof}>Verify Proof</button>
      ) : !isVerified ? (
        <p>Waiting for valid URL parameters...</p>
      ) : null}
    </div>
  );
}

export default App;
