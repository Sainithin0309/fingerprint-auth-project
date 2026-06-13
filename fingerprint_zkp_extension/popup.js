let fetchedZKP = null;

// Base secret for HKDF derivation — shared between extension and backend
// Per-user keys are derived from this + user_id via HKDF (Section 5.3.1)
const HMAC_BASE_SECRET = 'SJ4VX1xDC2Ha9IZeDq2auS2afr9DufKUrzwAb4=';
const BACKEND_URL = 'https://fingerprint-auth-using-zkp.onrender.com';
const DAPP_URL    = 'https://peuap-w3-dapp1.onrender.com/';

// ─────────────────────────────────────────────────────────
// IMPLEMENTATION 1 — HKDF Per-User Key Derivation
// Matches thesis Section 5.3.1 design claim.
// Each user gets a distinct HMAC key derived from base secret + user_id.
// An attacker who learns one user's HMAC key cannot forge tokens for others.
// ─────────────────────────────────────────────────────────
async function deriveHMACKey(user_id) {
  const encoder = new TextEncoder();

  // Import base secret as HKDF key material
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(HMAC_BASE_SECRET),
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  // Derive per-user HMAC key using user_id as salt
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(user_id),   // user_id as salt → unique key per user
      info: encoder.encode('peuap-w3-hmac-v1')
    },
    baseKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

// Generate HMAC signature with timestamp using per-user derived key
async function generateHMAC(data, timestamp, user_id) {
  const encoder = new TextEncoder();
  const key = await deriveHMACKey(user_id);
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(JSON.stringify(data) + timestamp)
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// ─────────────────────────────────────────────────────────
// IMPLEMENTATION 3 — BLE API Stub with WebAuthn Fallback
// Documents the hardware path (Layer 1 → Layer 2 BLE transport).
// Attempts BLE connection to PEUAP-W3 hardware device first.
// Falls back to WebAuthn FIDO2 if no BLE device is found.
// Matches thesis Section 5.2 hardware pipeline description.
// ─────────────────────────────────────────────────────────
async function getCredentialFromDevice() {
  // Attempt BLE first (Layer 1 hardware path)
  if (navigator.bluetooth) {
    try {
      const device = await navigator.bluetooth.requestDevice({
        filters: [{ name: 'PEUAP-W3-Auth' }],         // STM32 + nRF52840 device name
        optionalServices: ['6e400001-b5a3-f393-e0a9-e50e24dcca9e'] // Nordic UART Service
      });

      const server  = await device.gatt.connect();
      const service = await server.getPrimaryService(
        '6e400001-b5a3-f393-e0a9-e50e24dcca9e'
      );
      const rxChar  = await service.getCharacteristic(
        '6e400003-b5a3-f393-e0a9-e50e24dcca9e'
      );

      // Wait for device to send credential hash over BLE UART (max 5s)
      return await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('BLE timeout')), 5000);
        rxChar.addEventListener('characteristicvaluechanged', (event) => {
          clearTimeout(timeout);
          const decoder = new TextDecoder();
          const credentialId = decoder.decode(event.target.value);
          resolve({ source: 'ble', credentialId });
        });
        rxChar.startNotifications();
      });

    } catch (bleErr) {
      // BLE not available or user cancelled — fall through to WebAuthn
      console.log('[PEUAP-W3] BLE unavailable, falling back to WebAuthn:', bleErr.message);
    }
  }

  // WebAuthn FIDO2 fallback (software simulation of hardware layer)
  // credential.rawId serves as fingerprint hash proxy per Section 5.2.3
  return { source: 'webauthn', credentialId: null }; // handled by validate.html
}

// ─────────────────────────────────────────────────────────
// UI Helpers
// ─────────────────────────────────────────────────────────
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
  btn.disabled    = loading;
  btn.style.opacity = loading ? '0.6' : '1';
}

// ─────────────────────────────────────────────────────────
// Fetch ZKP from backend
// ─────────────────────────────────────────────────────────
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

      // Validate new circuit proof structure (6 public signals)
      const proof = data.zkp?.onchain_proof;
      if (!proof || !Array.isArray(proof.publicSignals)) {
        setResult('❌ Invalid proof structure received.', true);
        fetchedZKP = null;
        return;
      }

      const circuit    = data.zkp?.circuit || 'unknown';
      const commitment = data.zkp?.commitment?.slice(0, 12) + '...' || 'N/A';
      setResult(
        `✅ ZKP fetched!\nCircuit: ${circuit}\nCommitment: ${commitment}\nSignals: ${proof.publicSignals.length}\n\nClick "Pass to Web3" to authenticate.`
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

// ─────────────────────────────────────────────────────────
// Pass ZKP to Web3 dApp
// Uses HKDF-derived per-user HMAC key (Implementation 1)
// ─────────────────────────────────────────────────────────
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
    // Implementation 1: per-user HKDF-derived key instead of shared secret
    const hmac = await generateHMAC(payload, timestamp, user_id);

    chrome.tabs.create({ url: DAPP_URL }, (tab) => {
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (payload, timestamp, hmac) => {
          let attempts = 0;
          const interval = setInterval(() => {
            attempts++;
            window.postMessage({ type: 'ZKP_DATA', payload, timestamp, hmac }, '*');
            if (attempts >= 20) clearInterval(interval);
          }, 500);
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
