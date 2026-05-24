const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
const NODE_ID = "relay-node-1";
const NODE_SECRET = process.env.NODE_SECRET || "relay1_secret_peuap_2025";

// In-memory share store (keyed by session_id)
const shareStore = {};

// Health check
app.get("/health", (req, res) => {
  res.json({ node: NODE_ID, status: "online", shares: Object.keys(shareStore).length });
});

// Store a Shamir share for this node
app.post("/store-share", (req, res) => {
  const { session_id, share, proof_hash, timestamp } = req.body;
  if (!session_id || !share) {
    return res.status(400).json({ error: "session_id and share required" });
  }
  shareStore[session_id] = {
    share,
    proof_hash,
    timestamp: timestamp || Date.now(),
    node: NODE_ID
  };
  console.log(`[${NODE_ID}] Stored share for session ${session_id}`);
  res.json({ status: "stored", node: NODE_ID, session_id });
});

// Return this node's share (only to coordinator with correct HMAC)
app.post("/retrieve-share", (req, res) => {
  const { session_id, coordinator_hmac } = req.body;
  if (!session_id) return res.status(400).json({ error: "session_id required" });

  // Verify coordinator HMAC
  const expected = crypto
    .createHmac("sha256", NODE_SECRET)
    .update(session_id)
    .digest("hex");

  if (coordinator_hmac !== expected) {
    console.log(`[${NODE_ID}] HMAC mismatch for session ${session_id}`);
    return res.status(403).json({ error: "unauthorized" });
  }

  const entry = shareStore[session_id];
  if (!entry) return res.status(404).json({ error: "share not found" });

  // Delete after retrieval (ephemeral — like your ZKP design)
  delete shareStore[session_id];
  console.log(`[${NODE_ID}] Retrieved and deleted share for session ${session_id}`);
  res.json({ node: NODE_ID, share: entry.share, proof_hash: entry.proof_hash });
});

// Delete share (on auth failure or timeout)
app.delete("/share/:session_id", (req, res) => {
  const { session_id } = req.params;
  if (shareStore[session_id]) {
    delete shareStore[session_id];
    console.log(`[${NODE_ID}] Deleted share for session ${session_id}`);
  }
  res.json({ status: "deleted", node: NODE_ID });
});

app.listen(PORT, () => {
  console.log(`${NODE_ID} running on port ${PORT}`);
});
