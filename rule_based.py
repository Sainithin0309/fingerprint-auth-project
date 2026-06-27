"""
rule_based_detector.py — Deterministic Rule-Based Anomaly Detector
Second model in PEUAP-W3's hybrid behavioural AI layer (Contribution C5)

Unlike the Isolation Forest, this model's logic is FIXED and does not
depend on training data quality. It encodes explicit, explainable
security rules that always apply, regardless of what's in auth_events.

This acts as a safeguard against training-data drift or contamination
affecting the unsupervised model's judgment.
"""

# Fixed, non-data-dependent thresholds — these do NOT change based on
# what's in the database, unlike the Isolation Forest's learned behavior
RULE_THRESHOLDS = {
    "max_attempts_per_hour": 10,        # hard ceiling regardless of history
    "max_consecutive_failures": 5,      # hard ceiling regardless of history
    "min_hour_utc": 0,                  # no time-of-day hard rule by default
    "max_hour_utc": 24,
    "new_user_grace": True,             # explicit safeguard for first-time users
}


def evaluate_rules(features: list, is_new_user: bool) -> dict:
    """
    Evaluates fixed security rules against the same 4 features used
    by the Isolation Forest: [attempt_freq, hour, consec_fails, days_since].

    Returns:
        {
          "blocked": bool,
          "score": float (0.0-1.0, rule-based confidence),
          "reason": str,
          "triggered_rules": list
        }

    This function's behavior is fully deterministic and auditable —
    the same inputs always produce the same output, regardless of
    any model training state.
    """
    attempt_freq, hour, consec_fails, days_since = features
    triggered = []

    # RULE 1: First-time users are explicitly protected from being
    # blocked solely for having no history. This is the safeguard
    # that directly prevents the cold-start over-blocking scenario.
    if is_new_user and RULE_THRESHOLDS["new_user_grace"]:
        # A new user can still be blocked by OTHER rules (e.g. if they
        # are somehow already showing high frequency), but lack of
        # history alone is never sufficient grounds for blocking here.
        pass

    # RULE 2: Hard ceiling on attempt frequency — brute force protection
    if attempt_freq > RULE_THRESHOLDS["max_attempts_per_hour"]:
        triggered.append(f"attempt_frequency={attempt_freq:.0f} exceeds hard limit "
                          f"{RULE_THRESHOLDS['max_attempts_per_hour']}/hr")

    # RULE 3: Hard ceiling on consecutive failures — credential stuffing protection
    if consec_fails >= RULE_THRESHOLDS["max_consecutive_failures"]:
        triggered.append(f"consecutive_failures={consec_fails:.0f} reaches hard limit "
                          f"{RULE_THRESHOLDS['max_consecutive_failures']}")

    blocked = len(triggered) > 0
    # Rule-based confidence: binary in nature, but expressed as a score
    # for compatibility with the ensemble combination logic
    score = 1.0 if blocked else 0.0

    reason = "; ".join(triggered) if triggered else "no rule violations"

    return {
        "blocked": blocked,
        "score": score,
        "reason": reason,
        "triggered_rules": triggered
    }