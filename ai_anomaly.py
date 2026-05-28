"""
ai_anomaly.py — Behavioural Anomaly Detection for PEUAP-W3
Contribution C5: Isolation Forest trained on auth_events table

Sits in /validate route after credential match, before ZKP generation.
Blocks suspicious authentication attempts without exposing user identity.

Features used:
  1. attempt_frequency   — how many attempts in the last hour
  2. time_of_day         — current hour (0-23)
  3. consecutive_failures — failures before this attempt
  4. days_since_success  — days since last successful auth
"""

import time
import numpy as np

# Lazy import — only load sklearn when first needed
_model = None
_is_trained = False

def _get_model():
    global _model
    if _model is None:
        from sklearn.ensemble import IsolationForest
        # contamination=0.05 means we expect ~5% of traffic to be anomalous
        _model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
    return _model


def extract_features(user_id: str, conn, cur) -> list:
    """
    Extract 4 behavioural features from auth_events table for a user.
    Returns a feature vector [attempt_freq, hour, consec_fails, days_since_success]
    """
    now = int(time.time())
    one_hour_ago = now - 3600
    thirty_days_ago = now - (30 * 86400)

    try:
        # Feature 1: attempt frequency in last hour
        cur.execute("""
            SELECT COUNT(*) FROM auth_events
            WHERE user_id = %s AND created_at > %s
        """, (user_id, one_hour_ago))
        row = cur.fetchone()
        attempt_freq = float(row[0]) if row else 0.0

        # Feature 2: current hour of day (0-23)
        import datetime
        hour_of_day = float(datetime.datetime.utcnow().hour)

        # Feature 3: consecutive failures before this attempt
        cur.execute("""
            SELECT success FROM auth_events
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 10
        """, (user_id,))
        rows = cur.fetchall()
        consecutive_failures = 0.0
        for row in rows:
            if not row[0]:  # success = False
                consecutive_failures += 1
            else:
                break  # stop at first success

        # Feature 4: days since last successful auth
        cur.execute("""
            SELECT created_at FROM auth_events
            WHERE user_id = %s AND success = TRUE AND event_type = 'validate_success'
            ORDER BY created_at DESC
            LIMIT 1
        """, (user_id,))
        row = cur.fetchone()
        if row:
            days_since_success = (now - row[0]) / 86400.0
        else:
            # Never authenticated before — moderate risk
            days_since_success = 7.0

        return [attempt_freq, hour_of_day, consecutive_failures, days_since_success]

    except Exception as e:
        print(f"[AI] Feature extraction error (non-critical): {e}")
        # Return neutral features on error — don't block on AI failure
        return [1.0, 12.0, 0.0, 1.0]


def get_synthetic_training_data() -> np.ndarray:
    """
    Generate synthetic training data representing normal authentication patterns.
    Used to pre-train the model before real data accumulates.

    Normal patterns:
      - 1-3 attempts per hour
      - Business hours (8-20) weighted heavily
      - 0-1 consecutive failures
      - 0-7 days since last success

    Anomalous patterns (5% contamination built into model):
      - 10+ attempts per hour (brute force)
      - Off-hours (0-6am)
      - 5+ consecutive failures then success
      - 30+ days gap (stolen dormant credential)
    """
    np.random.seed(42)
    n = 500

    # Normal samples (480)
    normal = np.column_stack([
        np.random.poisson(1.5, n),                    # attempt_freq: mostly 1-3
        np.random.normal(13, 3, n).clip(8, 20),       # hour: business hours
        np.random.poisson(0.3, n).clip(0, 2),         # consec_fails: 0-2
        np.random.exponential(1.5, n).clip(0, 7),     # days_since: 0-7
    ])

    return normal


def train_model(conn, cur) -> bool:
    """
    Train the Isolation Forest on auth_events data.
    Falls back to synthetic data if fewer than 20 real events exist.
    Returns True if training succeeded.
    """
    global _is_trained

    try:
        model = _get_model()

        # Try to get real training data first
        cur.execute("""
            SELECT user_id, created_at, success FROM auth_events
            ORDER BY created_at DESC
            LIMIT 1000
        """)
        rows = cur.fetchall()

        if len(rows) >= 20:
            # Build feature matrix from real data
            # Simplified: use attempt counts and time patterns
            features = []
            for i, row in enumerate(rows):
                user_id, created_at, success = row
                # Count attempts in surrounding window
                window_start = created_at - 3600
                nearby = sum(1 for r in rows if r[1] and window_start <= r[1] <= created_at + 1)
                hour = (created_at % 86400) // 3600 if created_at else 12
                features.append([float(nearby), float(hour), 0.0, 1.0])

            X = np.array(features)
            print(f"[AI] Training on {len(X)} real auth events")
        else:
            # Use synthetic data
            X = get_synthetic_training_data()
            print(f"[AI] Training on synthetic data ({len(X)} samples) — real data accumulating")

        model.fit(X)
        _is_trained = True
        print("[AI] Isolation Forest trained successfully")
        return True

    except Exception as e:
        print(f"[AI] Training error (non-critical): {e}")
        return False


def check_anomaly(user_id: str, conn, cur) -> dict:
    """
    Main function called from /validate route.

    Returns:
        {
          "blocked": bool,
          "score": float (0.0-1.0, higher = more anomalous),
          "reason": str
        }

    Never raises — on any error, returns {"blocked": False} to avoid
    blocking legitimate users due to AI failures.
    """
    try:
        global _is_trained

        # Train model if not yet trained
        if not _is_trained:
            train_model(conn, cur)

        # If still not trained (error), allow through
        if not _is_trained:
            return {"blocked": False, "score": 0.0, "reason": "model_unavailable"}

        model = _get_model()

        # Extract features for this user
        features = extract_features(user_id, conn, cur)
        X = np.array([features])

        # Isolation Forest: -1 = anomaly, 1 = normal
        prediction = model.predict(X)[0]
        raw_score = model.score_samples(X)[0]  # more negative = more anomalous

        # Normalise score to 0-1 (0 = normal, 1 = anomalous)
        # Typical range: -0.5 (anomaly) to 0.1 (normal)
        normalised = max(0.0, min(1.0, (-raw_score - 0.1) / 0.6))

        THRESHOLD = 0.80

        if normalised > THRESHOLD:
            attempt_freq, hour, consec_fails, days_since = features
            reasons = []
            if attempt_freq > 8:
                reasons.append(f"high attempt frequency ({int(attempt_freq)}/hr)")
            if hour < 5 or hour > 23:
                reasons.append(f"unusual time ({int(hour):02d}:00 UTC)")
            if consec_fails >= 4:
                reasons.append(f"{int(consec_fails)} consecutive failures")
            if days_since > 25:
                reasons.append(f"dormant credential ({int(days_since)} days)")

            reason = ", ".join(reasons) if reasons else "anomalous pattern detected"

            print(f"[AI] BLOCKED user={user_id} score={normalised:.2f} reason={reason}")
            return {
                "blocked": True,
                "score": round(normalised, 3),
                "reason": reason
            }

        print(f"[AI] ALLOWED user={user_id} score={normalised:.2f}")
        return {
            "blocked": False,
            "score": round(normalised, 3),
            "reason": "normal"
        }

    except Exception as e:
        # Never block on AI error — fail open (allow) with log
        print(f"[AI] Anomaly check error (allowing through): {e}")
        return {"blocked": False, "score": 0.0, "reason": f"error: {e}"}
