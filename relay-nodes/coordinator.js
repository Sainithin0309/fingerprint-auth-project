const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const axios = require("axios");
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Node URLs — set via env vars for Render deployment
const NODES = [
  { id: "node1", url: process.env.NODE1_URL || "http://localhost:3001", secret: process.env.NODE1_SECRET || "relay1_secret_peuap_2025" },
  { id: "node2", url: process.env.NODE2_URL || "http://localhost:3002", secret: process.env.NODE2_SECRET || "relay2_secret_peuap_2025" },
  { id: "node3", url: process.env.NODE3_URL || "http://localhost:3003", secret: process.env.NODE3_SECRET || "relay3_secret_peuap_2025" },
];
const K = 2; // Minimum shares needed to reconstruct

// ── Shamir Secret Sharing (XOR-based 2-of-3 for prototype) ──
// In production, replace with the 'shamirs-secret-sharing' npm package
// for full polynomial GF(256) Shamir shares.

function splitSecret(secret) {
  const buf = Buffer.from(secret, "utf8");
  const s1 = crypto.randomBytes(buf.length);
  const s2 = crypto.randomBytes(buf.length);
  const s3 = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    s3[i] = buf[i] ^ s1[i] ^ s2[i];
  }
  return [s1.toString("hex"), s2.toString("hex"), s3.toString("hex")];
}

function reconstructSecret(shares) {
  const bufs = shares.map(s => Buffer.from(s, "hex"));
  const result = Buffer.alloc(bufs[0].length);
  for (let i = 0; i < bufs[0].length; i++) {
    result[i] = bufs[0][i] ^ bufs[1][i] ^ bufs[2][i];
  }
  return result.toString("utf8");
}

// Health — checks all 3 nodes
app.get("/health", async (req, res) => {
  const statuses = await Promise.allSettled(
    NODES.map(n => axios.get(`${n.url}/health`, { timeout: 3000 }))
  );
  const nodeStatus = statuses.map((s, i) => ({
    node: NODES[i].id,
    online: s.status === "fulfilled"
  }));
  res.json({ coordinator: "online", nodes: nodeStatus, k_of_n: `${K}-of-${NODES.length}` });
});

// Distribute identity payload as Shamir shares across all 3 nodes
app.post("/distribute", async (req, res) => {
  const { session_id, identity_payload, proof_hash } = req.body;
  if (!session_id || !identity_payload) {
    return res.status(400).json({ error: "session_id and identity_payload required" });
  }

  try {
    const shares = splitSecret(identity_payload);
    const results = await Promise.allSettled(
      NODES.map((node, i) =>
        axios.post(`${node.url}/store-share`, {
          session_id,
          share: shares[i],
          proof_hash,
          timestamp: Date.now()
        }, { timeout: 5000 })
      )
    );

    const successful = results.filter(r => r.status === "fulfilled").length;
    if (successful < K) {
      return res.status(503).json({ error: `Only ${successful}/${NODES.length} nodes available` });
    }

    console.log(`[coordinator] Distributed ${NODES.length} shares for session ${session_id}`);
    res.json({ status: "distributed", session_id, nodes_stored: successful });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Reconstruct identity — requires auditor key (k-of-n de-anonymisation)
app.post("/reconstruct", async (req, res) => {
  const { session_id, auditor_key } = req.body;

  const expectedKey = process.env.AUDITOR_KEY || "auditor_peuap_2025";
  if (auditor_key !== expectedKey) {
    return res.status(403).json({ error: "unauthorized auditor key" });
  }

  try {
    const retrievals = await Promise.allSettled(
      NODES.map(node => {
        const hmac = crypto
          .createHmac("sha256", node.secret)
          .update(session_id)
          .digest("hex");
        return axios.post(`${node.url}/retrieve-share`, {
          session_id,
          coordinator_hmac: hmac
        }, { timeout: 5000 });
      })
    );

    const goodShares = retrievals
      .filter(r => r.status === "fulfilled")
      .map(r => r.value.data.share);

    if (goodShares.length < NODES.length) {
      return res.status(503).json({
        error: `Only ${goodShares.length} shares retrieved, need ${NODES.length}`
      });
    }

    const identity = reconstructSecret(goodShares);
    console.log(`[coordinator] Reconstructed identity for session ${session_id}`);
    res.json({ status: "reconstructed", session_id, identity });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Relay coordinator running on port ${PORT}`);
});
