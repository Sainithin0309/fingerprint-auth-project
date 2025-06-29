let fetchedZKP = null;

document.getElementById('fetchBtn').addEventListener('click', async () => {
    const user_id = document.getElementById('user_id').value;
    const otp = document.getElementById('otp').value;
    const resultEl = document.getElementById('result');

    try {
        const response = await fetch('https://fingerprint-auth-using-zkp.onrender.com/get_zkp', {

            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id, otp })
        });
        const data = await response.json();
        if (data.status === 'success') {
            fetchedZKP = data.zkp; // Store for later
            resultEl.textContent = JSON.stringify(data.zkp, null, 2);

            // Remove OTP from the validate.html page if open
            // Try both localhost and 127.0.0.1 for compatibility
            const urls = [
                "https://fingerprint-auth-using-zkp.onrender.com/validate_page"
            ];
            for (const url of urls) {
                const pages = await chrome.tabs.query({ url });
                for (const page of pages) {
                    chrome.scripting.executeScript({
                        target: { tabId: page.id },
                        func: () => {
                            if (typeof pluginClearOtp === "function") pluginClearOtp();
                        }
                    });
                }
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
    const user_id = document.getElementById('user_id').value;
    if (!user_id) {
        alert('User ID is required!');
        return;
    }
    // Extract only the onchain_proof from the fetched ZKP
    const onchainProof = fetchedZKP.onchain_proof;
    // Encode onchainProof and user_id as URL parameters
    const zkpParam = encodeURIComponent(JSON.stringify(onchainProof));
    const userParam = encodeURIComponent(user_id);
    // Change the URL below to your actual Web3Flix server address and port
const web3flixUrl = `https://fingerprint-auth-project-aaw1lu5t9.vercel.app/?zkp=${zkpParam}&userid=${userParam}`;
    window.open(web3flixUrl, '_blank');
});