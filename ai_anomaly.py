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

FIX LOG (Step 1 — cold-start bug correction):
  - Old: new/first-time users received days_since_success = 7.0, the
    extreme tail of the training distribution (exponential(1.5) clipped
    to [0,7]) — causing nearly every brand-new legitimate user to be
    scored as anomalous.
  - New: new users receive a neutral days_since_success value (1.5, the
    distribution's mean) instead of its edge.
  - Old: the "real data" training branch in train_model() hardcoded
    consecutive_failures=0.0 and days_since=1.0 for every row,
    discarding real signal once 20+ events accumulated.
  - New: real training data computes all 4 features properly per row,
    matching what extract_features() computes at inference time.
"""

import time
import datetime
import numpy as np

_model = None
_is_trained = False

NEUTRAL_DAYS_SINCE_SUCCESS = 1.5


def _get_model():
    global _model
    if _model is None:
        from sklearn.ensemble import IsolationForest
        _model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
    return _model


def extract_features(user_id: str, conn, cur) -> list:
    now = int(time.time())
    one_hour_ago = now - 3600

    try:
        cur.execute("""
            SELECT COUNT(*) FROM auth_events
            WHERE user_id = %s AND created_at > %s
        """, (user_id, one_hour_ago))
        row = cur.fetchone()
        attempt_freq = float(row[0]) if row else 0.0

        hour_of_day = float(datetime.datetime.utcnow().hour)

        cur.execute("""
            SELECT success FROM auth_events
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 10
        """, (user_id,))
        rows = cur.fetchall()
        consecutive_failures = 0.0
        for row in rows:
            if not row[0]:
                consecutive_failures += 1
            else:
                break

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
            days_since_success = NEUTRAL_DAYS_SINCE_SUCCESS

        return [attempt_freq, hour_of_day, consecutive_failures, days_since_success]

    except Exception as e:
        print(f"[AI] Feature extraction error (non-critical): {e}")
        return [1.0, 12.0, 0.0, NEUTRAL_DAYS_SINCE_SUCCESS]


def get_synthetic_training_data() -> np.ndarray:
    np.random.seed(42)
    n = 500
    normal = np.column_stack([
        np.random.poisson(1.5, n),
        np.random.normal(13, 3, n).clip(8, 20),
        np.random.poisson(0.3, n).clip(0, 2),
        np.random.exponential(1.5, n).clip(0, 7),
    ])
    return normal


def _compute_features_for_row(user_id, created_at, success, all_rows):
    """Replicates extract_features() logic for a historical training row."""
    one_hour_before = created_at - 3600

    attempt_freq = sum(
        1 for r in all_rows
        if r[0] == user_id and one_hour_before <= r[1] <= created_at
    )

    hour = (created_at % 86400) // 3600 if created_at else 12

    user_rows_before = sorted(
        [r for r in all_rows if r[0] == user_id and r[1] <= created_at],
        key=lambda r: r[1], reverse=True
    )
    consecutive_failures = 0.0
    for r in user_rows_before:
        if not r[2]:
            consecutive_failures += 1
        else:
            break

    prior_successes = [
        r[1] for r in all_rows
        if r[0] == user_id and r[2] and r[1] < created_at
    ]
    if prior_successes:
        days_since = (created_at - max(prior_successes)) / 86400.0
    else:
        days_since = NEUTRAL_DAYS_SINCE_SUCCESS

    return [float(attempt_freq), float(hour), consecutive_failures, days_since]


def train_model(conn, cur) -> bool:
    global _is_trained

    try:
        model = _get_model()

        cur.execute("""
            SELECT user_id, created_at, success FROM auth_events
            ORDER BY created_at DESC
            LIMIT 1000
        """)
        rows = cur.fetchall()

        if len(rows) >= 20:
            features = [
                _compute_features_for_row(user_id, created_at, success, rows)
                for user_id, created_at, success in rows
            ]
            X = np.array(features)
            print(f"[AI] Training on {len(X)} real auth events (corrected feature extraction)")
        else:
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
    try:
        global _is_trained

        if not _is_trained:
            train_model(conn, cur)

        if not _is_trained:
            return {"blocked": False, "score": 0.0, "reason": "model_unavailable"}

        model = _get_model()

        features = extract_features(user_id, conn, cur)
        is_new_user = (features[3] == NEUTRAL_DAYS_SINCE_SUCCESS)

        X = np.array([features])

        prediction = model.predict(X)[0]
        raw_score = model.score_samples(X)[0]

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

            print(f"[AI] BLOCKED user={user_id} score={normalised:.2f} "
                  f"reason={reason} new_user={is_new_user}")
            return {
                "blocked": True,
                "score": round(normalised, 3),
                "reason": reason
            }

        print(f"[AI] ALLOWED user={user_id} score={normalised:.2f} new_user={is_new_user}")
        return {
            "blocked": False,
            "score": round(normalised, 3),
            "reason": "normal"
        }

    except Exception as e:
        print(f"[AI] Anomaly check error (allowing through): {e}")
        return {"blocked": False, "score": 0.0, "reason": f"error: {e}"}
