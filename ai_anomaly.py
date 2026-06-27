"""
ai_anomaly.py — Behavioural Anomaly Detection for PEUAP-W3
Contribution C5: Random Forest (offline-trained) + Rule-Based Safeguard

SIMPLE DESIGN:
  1. Random Forest — trained offline in Colab on labeled synthetic data,
     loaded as a pre-trained file. Makes the primary decision.
  2. Rule-based detector — fixed, deterministic safety net (unchanged
     from before). Catches anything the model might miss.

Decision: BLOCK if EITHER the model OR the rules say block.
"""

import time
import datetime
import numpy as np
import joblib
import os
from rule_based import evaluate_rules

_model = None

MODEL_PATH = os.path.join(os.path.dirname(__file__), "random_forest_model.pkl")
NEUTRAL_DAYS_SINCE_SUCCESS = 1.5
THRESHOLD = 0.5  # matches what you validated in Colab


def _get_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
        print(f"[AI] Loaded pre-trained Random Forest model from {MODEL_PATH}")
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


def check_anomaly(user_id: str, conn, cur) -> dict:
    """
    Main hybrid decision function called from /validate.
    Combines the pre-trained Random Forest model with fixed rules.
    """
    try:
        features = extract_features(user_id, conn, cur)
        is_new_user = (features[3] == NEUTRAL_DAYS_SINCE_SUCCESS)

        # ---- Model: Random Forest (pre-trained, loaded from file) ----
        model = _get_model()
        X = np.array([features])
        proba = model.predict_proba(X)[0, 1]  # probability of being anomalous

        model_blocked = proba >= THRESHOLD

        # ---- Rule-based safeguard (unchanged) ----
        rule_result = evaluate_rules(features, is_new_user)

        # ---- Final decision: block if EITHER says block ----
        final_blocked = model_blocked or rule_result["blocked"]
        final_score = max(proba, rule_result["score"])

        reasons = []
        if model_blocked:
            reasons.append(f"AI model flagged anomalous (score={proba:.2f})")
        if rule_result["blocked"]:
            reasons.append(f"Rule violation: {rule_result['reason']}")
        reason = "; ".join(reasons) if reasons else "normal"

        print(f"[AI] user={user_id} model_score={proba:.3f} "
              f"rule_blocked={rule_result['blocked']} new_user={is_new_user} "
              f"=> {'BLOCKED' if final_blocked else 'ALLOWED'}")

        return {
            "blocked": final_blocked,
            "score": round(float(final_score), 3),
            "reason": reason
        }

    except Exception as e:
        print(f"[AI] Anomaly check error (allowing through): {e}")
        return {"blocked": False, "score": 0.0, "reason": f"error: {e}"}