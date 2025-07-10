let fetchedZKP = null;

function sanitizeInput(value) {
  return value.replace(/[^\w\-]/g, '');
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
      fetchedZKP = {
        user_id: user_id,
        onchain_proof: data.zkp.onchain_proof
      };
      resultEl.textContent = JSON.stringify(fetchedZKP, null, 2);

      chrome.tabs.create({ url: 'https://web3flix-netflix-on-blockchain.onrender.com' }, (tab) => {
        chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: (zkp) => {
            window.addEventListener('DOMContentLoaded', () => {
              window.postMessage({ type: 'ZKP_DATA', payload: zkp }, '*');
            });
          },
          args: [fetchedZKP]
        });
      });
    } else {
      resultEl.textContent = data.message || 'Failed to fetch ZKP';
    }
  } catch (err) {
    resultEl.textContent = 'Error: ' + err.message;
  }
});
