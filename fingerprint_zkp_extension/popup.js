let fetchedZKP = null;

const HMAC_SECRET = 'SJ4VX1xDC2Ha9IZeDq2auS2afr9DufKUrzwAb4=';

function sanitizeInput(value) {
  return value.replace(/[^\w\-]/g, '');
}

// 🔐 Generate HMAC signature with timestamp
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

document.getElementById('fetchBtn').addEventListener('click', async () => {
  const user_id = sanitizeInput(document.getElementById('user_id').value);
  const otp = sanitizeInput(document.getElementById('otp').value);
  const resultEl = document.getElementById('result');

  try {
    const response = await fetch('https://fingerprint-auth-using-zkp.onrender.com/get_zkp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id, otp })
    });

    const data = await response.json();
    if (data.status === 'success') {
      fetchedZKP = data.zkp;
      resultEl.textContent = JSON.stringify(data.zkp, null, 2);
    } else {
      resultEl.textContent = data.message || 'Failed to fetch ZKP';
    }
  } catch (err) {
    resultEl.textContent = 'Error: ' + err.message;
  }
});

document.getElementById('passToWeb3Btn').addEventListener('click', async () => {
  if (!fetchedZKP) {
    alert('Please fetch the ZKP first!');
    return;
  }

  const user_id = sanitizeInput(document.getElementById('user_id').value);
  if (!user_id) {
    alert('User ID is required!');
    return;
  }

  const payload = {
    onchain_proof: fetchedZKP.onchain_proof,
    user_id
  };

  const timestamp = Date.now();
  const hmac = await generateHMAC(payload, timestamp);

  // Open Web3Flix in a new tab
  chrome.tabs.create({ url: 'https://web3flix-netflix-on-blockchain.onrender.com/' }, (tab) => {
    // Use chrome.scripting.executeScript to inject postMessage directly
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (payload, timestamp, hmac) => {
        window.addEventListener('load', () => {
          window.postMessage({
            type: 'ZKP_DATA',
            payload,
            timestamp,
            hmac
          }, '*');
        });
      },
      args: [payload, timestamp, hmac]
    });
  });
});
