let fetchedZKP = null;

const HMAC_SECRET = 'SJ4VX1xDC2Ha9IZeDq2auS2afr9DufKUrzwAb4=';
const BACKEND_URL = 'https://fingerprint-auth-using-zkp.onrender.com';
// Update this to your deployed React dApp URL on Render/Vercel
const DAPP_URL = 'https://peuap-w3-dapp1.onrender.com/';

function sanitizeInput(value) {
  return value.replace(/[^\w\-]/g, '');
}

function setResult(msg, isError = false) {
  const el = document.getElementById('result');
  el.textContent = msg;
  el.style.color = isError ? '#ff6e6e' : '#b3b3ff';
}

function setLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (loading) {
    btn.disabled = true;
    btn.style.opacity = '0.6';
  } else {
    btn.disabled = false;
    btn.style.opacity = '1';
  }
}

// Generate HMAC signature with timestamp
async function generateHMAC(data, timestamp) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(HMAC_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(JSON.stringify(data) + timestamp)
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// Fetch ZKP from backend
document.getElementById('fetchBtn').addEventListener('click', async () => {
  const user_id = sanitizeInput(document.getElementById('user_id').value.trim());
  const otp     = sanitizeInput(document.getElementById('otp').value.trim());

  if (!user_id || !otp) {
    setResult('Please enter both User ID and OTP.', true);
    return;
  }

  setLoading('fetchBtn', true);
  setResult('⏳ Fetching ZKP from backend...');

  try {
    const response = await fetch(`${BACKEND_URL}/get_zkp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id, otp })
    });

    const data = await response.json();

    if (data.status === 'success') {
      fetchedZKP = data.zkp;

      // Validate the new circuit's proof structure (6 public signals)
      const proof = data.zkp?.onchain_proof;
      if (!proof || !Array.isArray(proof.publicSignals)) {
        setResult('❌ Invalid proof structure received.', true);
        fetchedZKP = null;
        return;
      }

      // Show commitment and circuit version as confirmation
      const circuit = data.zkp?.circuit || 'unknown';
      const commitment = data.zkp?.commitment?.slice(0, 12) + '...' || 'N/A';
      setResult(
        `✅ ZKP fetched!\nCircuit: ${circuit}\nCommitment: ${commitment}\nPublic signals: ${proof.publicSignals.length}\n\nClick "Pass to Web3" to authenticate.`
      );
    } else {
      setResult('❌ ' + (data.message || 'Failed to fetch ZKP'), true);
      fetchedZKP = null;
    }
  } catch (err) {
    setResult('❌ Network error: ' + err.message, true);
    fetchedZKP = null;
  } finally {
    setLoading('fetchBtn', false);
  }
});

// Pass ZKP to Web3 dApp
document.getElementById('passToWeb3Btn').addEventListener('click', async () => {
  if (!fetchedZKP) {
    setResult('❌ Please fetch the ZKP first!', true);
    return;
  }

  const user_id = sanitizeInput(document.getElementById('user_id').value.trim());
  if (!user_id) {
    setResult('❌ User ID is required!', true);
    return;
  }

  setLoading('passToWeb3Btn', true);
  setResult('⏳ Opening Web3 dApp...');

  try {
    const payload = {
      onchain_proof: fetchedZKP.onchain_proof,
      user_id
    };

    const timestamp = Date.now();
    const hmac = await generateHMAC(payload, timestamp);

    // Open dApp in a new tab and inject the ZKP via postMessage
    chrome.tabs.create({ url: DAPP_URL }, (tab) => {
      // Wait for the page to load then inject the message
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (payload, timestamp, hmac) => {
          // Retry posting until the React app is ready
          let attempts = 0;
          const maxAttempts = 20;
          const interval = setInterval(() => {
            attempts++;
            window.postMessage({ type: 'ZKP_DATA', payload, timestamp, hmac }, '*');
            if (attempts >= maxAttempts) clearInterval(interval);
          }, 500);

          // Also post on load event as fallback
          window.addEventListener('load', () => {
            window.postMessage({ type: 'ZKP_DATA', payload, timestamp, hmac }, '*');
          });
        },
        args: [payload, timestamp, hmac]
      });
    });

    setResult('✅ Web3 dApp opened. Switch to the new tab to complete verification.');
  } catch (err) {
    setResult('❌ Error: ' + err.message, true);
  } finally {
    setLoading('passToWeb3Btn', false);
  }
});
