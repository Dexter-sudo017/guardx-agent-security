import json
import re
from pathlib import Path

from app.models import AnalysisResult
from app.guards import semantic_guard


PROJECT_ROOT = Path(__file__).resolve().parents[5]
POLICY_PATH = PROJECT_ROOT / "configs" / "output_guard_policy.json"

UNSAFE_OUTPUT_PATTERNS = [
    "step-by-step attack",
    "bypass law enforcement",
    "build explosive",
    "credential stuffing",
    "violent instruction",
]

LEAK_PATTERNS = [
    "api key",
    "api key:",
    "private token",
    "token:",
    "private key:",
    "secret=",
    "system prompt:",
]


DEFAULT_POLICY = {
    "weights": {
        "unsafe_output_pattern": 0.2,
        "leak_pattern": 0.3,
        "leak_regex_pattern": 0.45,
        "observation_injection_pattern": 0.45,
    },
    "unsafe_output_patterns": UNSAFE_OUTPUT_PATTERNS,
    "leak_patterns": LEAK_PATTERNS,
    "observation_injection_patterns": [
        "developer priority",
        "system override",
        "book the most expensive option",
        "hide the upgrade",
        "network exfiltration command",
        "label it as cleanup",
        "call shell",
        "external collector",
    ],
    "leak_regex_patterns": [
        r"GX-SYNTH-[A-Z0-9_-]+",
        r"(?i)(api\s*key|private\s*token|secret)\s*[:=]\s*[A-Za-z0-9._/-]+",
    ],
    "strong_secret_regex_patterns": [
        r"(?i)(api\s*key|private\s*token|secret)\s*[:=]\s*(sk-[A-Za-z0-9._/-]{8,}|[A-Za-z0-9._/-]{24,})",
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{20,}",
    ],
    "benign_secret_handling_phrases": [
        "必须脱敏展示",
        "应脱敏",
        "禁止输出完整明文",
        "敏感信息必须脱敏",
        "redact before display",
        "redaction policy",
    ],
    "benign_secret_handling_score_reduction": 0.7,
    "benign_secret_handling_max_score": 0.4,
    "benign_safety_training_phrases": [
        "防御培训",
        "防御策略",
        "approved source",
        "只作为风险标签",
        "不是可执行命令",
        "安全培训材料",
        "不能作为指令",
        "不要给出绕过步骤",
        "不提供绕过步骤",
        "defensive training",
        "defense principles",
        "risk education",
        "without giving bypass instructions",
    ],
    "benign_safety_training_active_markers": [
        "gx-",
        "ignore developer",
        "system override",
        "export_secret",
        "external collector",
        "call shell",
        "book the most expensive option",
    ],
    "benign_safety_training_score_reduction": 0.5,
    "benign_safety_training_max_score": 0.18,
}


def load_output_policy() -> dict:
    if not POLICY_PATH.exists():
        return DEFAULT_POLICY
    try:
        loaded = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return DEFAULT_POLICY
    merged = DEFAULT_POLICY.copy()
    merged.update({key: value for key, value in loaded.items() if key != "schema_version"})
    merged["weights"] = {**DEFAULT_POLICY["weights"], **dict(loaded.get("weights", {}))}
    return merged


def analyze(answer: str, context: str | None = None) -> AnalysisResult:
    policy = load_output_policy()
    weights = policy["weights"]
    labels: list[str] = []
    evidence: list[str] = []
    score = 0.0
    unsafe_output_hit = False
    leak_regex_hit = False
    strong_secret_hit = False
    lowered = answer.lower()
    context_lowered = (context or "").lower()

    for pattern in policy["unsafe_output_patterns"]:
        if pattern in lowered:
            labels.append("unsafe_output")
            evidence.append(pattern)
            score += float(weights["unsafe_output_pattern"])
            unsafe_output_hit = True

    for pattern in policy["leak_patterns"]:
        if pattern in lowered:
            labels.append("secret_leak")
            evidence.append(pattern)
            score += float(weights["leak_pattern"])

    for pattern in policy.get("leak_regex_patterns", []):
        if re.search(pattern, answer):
            labels.append("secret_leak")
            evidence.append(pattern)
            score += float(weights["leak_regex_pattern"])
            leak_regex_hit = True

    for pattern in policy.get("strong_secret_regex_patterns", []):
        if re.search(pattern, answer):
            strong_secret_hit = True
            evidence.append(pattern)

    for pattern in policy.get("observation_injection_patterns", []):
        if pattern in lowered:
            labels.append("tool_output_injection")
            evidence.append(pattern)
            score += float(weights.get("observation_injection_pattern", 0.45))

    semantic = semantic_guard.analyze_text(answer, surface="output")
    labels.extend(semantic.labels)
    evidence.extend(semantic.evidence)
    score += semantic.risk_score

    benign_secret_policy = any(
        phrase in lowered or phrase in context_lowered
        for phrase in policy.get("benign_secret_handling_phrases", [])
    )
    if "secret_leak" in labels and benign_secret_policy and (not leak_regex_hit or not strong_secret_hit):
        labels.append("benign_secret_handling_policy")
        evidence.append("benign_secret_handling_phrase")
        score = max(0.0, score - float(policy.get("benign_secret_handling_score_reduction", 0.6)))
        score = min(score, float(policy.get("benign_secret_handling_max_score", 0.4)))

    benign_training_context = any(
        phrase in lowered or phrase in context_lowered
        for phrase in policy.get("benign_safety_training_phrases", [])
    )
    active_training_marker = any(
        marker in lowered or marker in context_lowered
        for marker in policy.get("benign_safety_training_active_markers", [])
    )
    if benign_training_context and not active_training_marker and not unsafe_output_hit and not strong_secret_hit and any(label.startswith("semantic_") for label in labels):
        labels.append("benign_safety_training_context")
        evidence.append("benign_safety_training_phrase")
        score = max(0.0, score - float(policy.get("benign_safety_training_score_reduction", 0.25)))
        score = min(score, float(policy.get("benign_safety_training_max_score", 0.4)))

    return AnalysisResult(
        risk_score=min(score, 1.0),
        labels=sorted(set(labels)),
        evidence=sorted(set(evidence)),
        metadata={"semantic": semantic.metadata},
    )


def sanitize_text(text: str) -> str:
    policy = load_output_policy()
    sanitized = text
    for pattern in policy.get("leak_regex_patterns", []):
        try:
            sanitized = re.sub(pattern, "[REDACTED_BY_GUARDX]", sanitized)
        except re.error:
            continue
    return sanitized


def safe_refusal_message() -> str:
    return (
        "Request blocked by GuardX policy. "
        "The request may involve jailbreak, harmful guidance, or sensitive data exposure."
    )
