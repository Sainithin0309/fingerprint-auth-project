import { useEffect, useState } from 'react';
import { ethers } from 'ethers';
import './App.css';
import verifierArtifact from '../../artifacts/contracts/Verifier.sol/Groth16Verifier.json';

const CONTRACT_ADDRESS = '0x5FbDB2315678afecb367f032d93F642f64180aa3'; // Replace with your deployed contract address

// Define users with access permissions
const users = {
  Sai123: { name: 'Sainithin', access: 'Full access' },
  Venky123: { name: 'Venkatesh', access: 'Limited access' },
};

function App() {
  const [proof, setProof] = useState(null);
  const [publicSignals, setPublicSignals] = useState(null);
  const [userId, setUserId] = useState('');
  const [status, setStatus] = useState('Waiting for ZKP and User ID in URL...');
  const [isVerified, setIsVerified] = useState(false); // New state for verification status

  // Read ZKP and User ID from URL on page load
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    try {
      const zkpParam = params.get('zkp');
      const userParam = params.get('userid');

      if (userParam) {
        setUserId(userParam);
        if (!users[userParam]) {
          setStatus('❌ User ID not authorized.');
          return;
        }
      }

      if (zkpParam) {
        const decodedZkp = JSON.parse(decodeURIComponent(zkpParam));

        if (
          decodedZkp.a &&
          decodedZkp.b &&
          decodedZkp.c &&
          decodedZkp.publicSignals
        ) {
          setProof({
            a: decodedZkp.a,
            b: decodedZkp.b,
            c: decodedZkp.c,
          });
          setPublicSignals(decodedZkp.publicSignals);
          setStatus('Recieved ZKP and User ID loaded from URL.');
        } else {
          setStatus('❌ Invalid ZKP structure.');
        }
      } else {
        setStatus('❌ ZKP not found in URL.');
      }
    } catch (e) {
      console.error(e);
      setStatus('❌ Failed to parse ZKP or User ID from URL.');
    }
  }, []);

  const verifyProof = async () => {
    if (!window.ethereum) {
      return setStatus('❌ MetaMask not detected.');
    }

    try {
      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();
      const contract = new ethers.Contract(
        CONTRACT_ADDRESS,
        verifierArtifact.abi,
        signer
      );

      const { a, b, c } = proof;
      const inputs = publicSignals;

      const result = await contract.verifyProof(a, b, c, inputs);
      if (result) {
        const user = users[userId];
        setStatus(`✅ ZKP verified sucessfully! Welcome ${user.name}. You have ${user.access}. Enjoy decentralized streaming!`);
        setIsVerified(true); // Set verification status to true
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
