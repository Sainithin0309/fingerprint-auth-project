"""
ai_anomaly.py — Hybrid Behavioural Anomaly Detection for PEUAP-W3
Contribution C5: Isolation Forest + Rule-Based Detector (ensemble)

Combines two independent models:
  1. Isolation Forest (unsupervised, learns from accumulated data)
  2. Rule-based detector (fixed, deterministic, data-independent)

Ensemble logic: if EITHER model blocks, the request is blocked.
This means the rule-based model acts as a safeguard — even if the
Isolation Forest's training data becomes skewed or contaminated,
the fixed rules still catch genuine attack patterns and still
protect first-time users from false positives.
"""

import time
import datetime
import numpy as np
from rule_based import evaluate_rules, RULE_THRESHOLDS

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
            print(f"[AI] Isolation Forest training on {len(X)} real auth events")
        else:
            X = get_synthetic_training_data()
            print(f"[AI] Isolation Forest training on synthetic data ({len(X)} samples)")

        model.fit(X)
        _is_trained = True
        print("[AI] Isolation Forest trained successfully")
        return True

    except Exception as e:
        print(f"[AI] Training error (non-critical): {e}")
        return False


def check_anomaly(user_id: str, conn, cur) -> dict:
    """
    HYBRID decision: combines Isolation Forest (statistical) with
    rule_based_detector (deterministic) results.

    Decision logic: BLOCK if EITHER model blocks. This ensures the
    fixed rule-based safeguards always apply, regardless of whether
    the statistical model's training data is clean or contaminated.
    """
    try:
        global _is_trained

        features = extract_features(user_id, conn, cur)
        is_new_user = (features[3] == NEUTRAL_DAYS_SINCE_SUCCESS)

        # ---- Model 1: Isolation Forest ----
        if not _is_trained:
            train_model(conn, cur)

        if_result = {"blocked": False, "score": 0.0, "reason": "model_unavailable"}
        if _is_trained:
            model = _get_model()
            X = np.array([features])
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
                if_result = {"blocked": True, "score": round(normalised, 3), "reason": reason}
            else:
                if_result = {"blocked": False, "score": round(normalised, 3), "reason": "normal"}

        # ---- Model 2: Rule-Based Detector ----
        rule_result = evaluate_rules(features, is_new_user)

        # ---- Ensemble Decision: block if EITHER model blocks ----
        final_blocked = if_result["blocked"] or rule_result["blocked"]

        if final_blocked:
            reasons_combined = []
            if if_result["blocked"]:
                reasons_combined.append(f"[IsolationForest] {if_result['reason']}")
            if rule_result["blocked"]:
                reasons_combined.append(f"[RuleBased] {rule_result['reason']}")
            combined_reason = "; ".join(reasons_combined)

            print(f"[AI-Hybrid] BLOCKED user={user_id} "
                  f"if_score={if_result['score']:.2f} rule_triggered={rule_result['blocked']} "
                  f"new_user={is_new_user}")
            return {
                "blocked": True,
                "score": max(if_result["score"], rule_result["score"]),
                "reason": combined_reason,
                "isolation_forest": if_result,
                "rule_based": rule_result
            }

        print(f"[AI-Hybrid] ALLOWED user={user_id} "
              f"if_score={if_result['score']:.2f} new_user={is_new_user}")
        return {
            "blocked": False,
            "score": max(if_result["score"], rule_result["score"]),
            "reason": "normal",
            "isolation_forest": if_result,
            "rule_based": rule_result
        }

    except Exception as e:
        print(f"[AI-Hybrid] Anomaly check error (allowing through): {e}")
        return {"blocked": False, "score": 0.0, "reason": f"error: {e}"}