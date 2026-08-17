from collections import defaultdict

session_risk_state: dict[str, float] = defaultdict(float)
rate_limit_state: dict[str, list[float]] = defaultdict(list)
