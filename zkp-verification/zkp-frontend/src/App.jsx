import { useEffect, useState } from 'react';
import { ethers } from 'ethers';
import './App.css';
import verifierArtifact from './abi/Groth16Verifier.json';

const CONTRACT_ADDRESS = '0x9457BE3F595c8504e4105a6306b92d65F6CaeEE9'; // Sepolia deployed contract

const users = {
  Sai123: { name: 'Sainithin', access: 'Full access' },
  Venky123: { name: 'Venkatesh', access: 'Limited access' },
};

function validateProofStructure(proof) {
  return (
    Array.isArray(proof.a) &&
    Array.isArray(proof.b) &&
    Array.isArray(proof.c) &&
    proof.a.length === 2 &&
    proof.b.length === 2 &&
    Array.isArray(proof.b[0]) &&
    Array.isArray(proof.b[1]) &&
    proof.b[0].length === 2 &&
    proof.b[1].length === 2 &&
    proof.c.length === 2
  );
}

function App() {
  const [proof, setProof] = useState(null);
  const [publicSignals, setPublicSignals] = useState(null);
  const [userId, setUserId] = useState('');
  const [status, setStatus] = useState('Waiting for ZKP via extension...');
  const [isVerified, setIsVerified] = useState(false);

  useEffect(() => {
    if (window.location.protocol !== 'https:') {
      setStatus('⚠️ Please use HTTPS for secure Web3 interactions.');
    }

    const handleZkpMessage = (event) => {
      if (event.data?.type === 'ZKP_DATA') {
        const { onchain_proof, user_id } = event.data.payload || {};

        if (!onchain_proof || !user_id) {
          setStatus('❌ Incomplete ZKP data from extension.');
          return;
        }

        if (!users[user_id]) {
          setStatus('❌ User ID not authorized.');
          return;
        }

        if (!validateProofStructure(onchain_proof)) {
          setStatus('❌ Invalid ZKP structure received.');
          return;
        }

        setProof({
          a: onchain_proof.a,
          b: onchain_proof.b,
          c: onchain_proof.c,
        });
        setPublicSignals(onchain_proof.publicSignals);
        setUserId(user_id);
        setStatus('✅ ZKP and User ID received securely from extension.');
      }
    };

    window.addEventListener('message', handleZkpMessage);
    return () => window.removeEventListener('message', handleZkpMessage);
  }, []);

  const verifyProof = async () => {
    if (!window.ethereum) {
      return setStatus('❌ MetaMask not detected.');
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
        setStatus(`✅ ZKP verified! Welcome ${user.name} (${user.access}) 🎬`);
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
      <p><strong>User ID:</strong> {userId || 'Not provided yet'}</p>
      <p><strong>Status:</strong> {status}</p>
      {proof && publicSignals && users[userId] && !isVerified ? (
        <button onClick={verifyProof}>Verify Proof</button>
      ) : !isVerified ? (
        <p>Waiting for ZKP...</p>
      ) : null}
    </div>
  );
}

export default App;
