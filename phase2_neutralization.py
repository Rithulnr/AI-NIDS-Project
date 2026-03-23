def neutralize(entity_id, future_risk):
    """
    entity_id : IP / Flow ID / Connection ID
    future_risk : predicted risk score (0–1)
    """

    if future_risk < 0.20:
        action = "ALLOW"

    elif future_risk < 0.40:
        action = "MONITOR"

    elif future_risk < 0.60:
        action = "RATE_LIMIT"

    elif future_risk < 0.80:
        action = "THROTTLE + DEEP_INSPECTION"

    else:
        action = "TEMPORARY_ISOLATION"

    return action
