console.log('✅ content.js injected into Web3Flix');

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ZKP_DATA') {
    console.log('📩 content.js forwarding ZKP to window');
    window.postMessage(message, '*');
    sendResponse({ status: 'Forwarded to page' });
  }
});
