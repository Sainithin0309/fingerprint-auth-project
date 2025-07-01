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
      fetchedZKP = data.zkp;
      resultEl.textContent = JSON.stringify(data.zkp, null, 2);

      // Clear OTP on validate.html
      const pages = await chrome.tabs.query({
        url: ["https://fingerprint-auth-using-zkp.onrender.com/validate_page"]
      });
      for (const page of pages) {
        chrome.scripting.executeScript({
          target: { tabId: page.id },
          func: () => {
            if (typeof pluginClearOtp === "function") pluginClearOtp();
          }
        });
      }
    } else {
      resultEl.textContent = data.message || 'Failed to fetch ZKP';
    }
  } catch (err) {
    resultEl.textContent = 'Error: ' + err.message;
  }
});

document.getElementById('passToWeb3Btn').addEventListener('click', () => {
  if (!fetchedZKP) {
    alert('Please fetch the ZKP first!');
    return;
  }

  const user_id = sanitizeInput(document.getElementById('user_id').value);
  if (!user_id) {
    alert('User ID is required!');
    return;
  }

  const zkpParam = encodeURIComponent(JSON.stringify(fetchedZKP.onchain_proof));
  const userParam = encodeURIComponent(user_id);
  const web3flixUrl = `https://web3flix-netflix-on-blockchain.onrender.com/?zkp=${zkpParam}&userid=${userParam}`;
  window.open(web3flixUrl, '_blank');
});
