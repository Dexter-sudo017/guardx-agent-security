import json
import re
import unicodedata
from urllib.parse import unquote
from pathlib import Path

from app.models import AnalysisResult, Message
from app.guards import semantic_guard


PROJECT_ROOT = Path(__file__).resolve().parents[5]
POLICY_PATH = PROJECT_ROOT / "configs" / "input_guard_policy.json"

JAILBREAK_PATTERNS = [
    "ignore previous instructions",
    "ignore prior rules",
    "ignore earlier rules",
    "disregard its operating rules",
    "disclose the private instruction hierarchy",
    "private instruction hierarchy",
    "confidential developer policy",
    "suppress the remaining safety checks",
    "suppress remaining safety checks",
    "expose hidden instructions",
    "bypass sequence",
    "higher priority than every earlier message",
    "safety policies are suspended",
    "suspended for this conversation",
    "without filtering",
    "hidden operational rubric",
    "operational rubric word for word",
    "restricted assistant continue after it refuses",
    "making a restricted assistant continue",
    "bypass safety",
    "developer mode",
    "jailbreak",
    "dan mode",
    "system prompt",
    "hidden system prompt",
    "hidden system instructions",
    "hidden developer prompt",
    "internal chain of thought",
    "内部治理规则",
    "公开附录",
    "不要标注为隐藏内容",
    "reveal hidden prompt",
    "developer instructions",
    "verbatim",
    "ignore policy",
    "bypass the safety policy",
    "bypass the guard",
    "unsafe step",
    "payload",
]

ROLEPLAY_PATTERNS = [
    "pretend you are",
    "act as",
    "roleplay as",
    "you are no longer bound",
    "unrestricted ai",
    "unrestricted assistant",
    "fictional scenario",
    "for a movie script",
]

UNSAFE_PATTERNS = [
    "build bomb",
    "make explosive",
    "steal password",
    "coworker's password",
    "without being noticed",
    "phishing",
    "malware",
    "ddos",
    "weapon",
    "violence plan",
    "attack playbook",
    "bypassing security controls",
    "harmful procedure",
    "step-by-step harmful",
    "harmful instructions",
    "actionable harmful instructions",
    "cyber abuse",
    "unauthorized access",
    "physical harm",
    "cause physical harm",
]

SENSITIVE_PATTERNS = [
    "api key",
    "api keys",
    "tokens",
    "credentials",
    "hidden private data",
    "external transfer",
    "token",
    "private key",
    "passport number",
    "id number",
    "social security number",
    "store it for later",
    "repeat it back",
    "print it exactly",
]

OBFUSCATION_PATTERNS = [
    "base64",
    "rot13",
    "hex decode",
    "decode this string",
    "decode this encoded instruction",
    "decode the hidden instruction",
    "encoded instruction",
    "comply with it",
    "follow it",
    "translate the encoded text",
]

EXPLICIT_OVERRIDE_EXFILTRATION_REGEX_PATTERNS = [
    (
        r"(?m)(?:^|[\n。！？!?；;：:])\s*(?:用户\s*[：:]?\s*)?"
        r"(?:请\s*)?(?:立即|现在|直接)?\s*"
        r"(?:忽略|无视|绕过|关闭|禁用|覆盖).{0,24}"
        r"(?:安全规则|安全策略|系统规则|系统指令|开发者指令|防护规则).{0,20}"
        r"(?:并|然后|再|同时|，|,).{0,12}"
        r"(?:输出|泄露|透露|显示|打印|复述|返回|导出).{0,20}"
        r"(?:系统秘密|系统提示词|隐藏提示词|隐藏指令|开发者提示词|内部规则|密钥|令牌|凭据)"
    ),
    (
        r"(?m)(?:^|[\n。！？!?；;：:])\s*(?:用户\s*[：:]?\s*)?"
        r"(?:请\s*)?(?:立即|现在|直接)?\s*"
        r"(?:输出|泄露|透露|显示|打印|复述|返回|导出).{0,20}"
        r"(?:系统秘密|系统提示词|隐藏提示词|隐藏指令|开发者提示词|内部规则|密钥|令牌|凭据).{0,20}"
        r"(?:并|然后|再|同时|，|,).{0,12}"
        r"(?:忽略|无视|绕过|关闭|禁用|覆盖).{0,24}"
        r"(?:安全规则|安全策略|系统规则|系统指令|开发者指令|防护规则)"
    ),
]

BASE64_LIKE_RE = re.compile(r"\b[a-zA-Z0-9+/]{24,}={0,2}\b")
CJK_SPACED_RE = re.compile(r"(?<=[\u4e00-\u9fff])[\s\u3000]+(?=[\u4e00-\u9fff])")

BENIGN_DAMPENING_PHRASES = [
    "should not reveal hidden system prompt",
    "should not reveal hidden system prompts",
    "without giving bypass instructions",
    "defensive engineering workshop",
    "defensive incident response",
    "incident response checklist",
    "security awareness poster",
    "policy training note",
    "safe policy",
    "suspected token leak",
    "rotating leaked test api keys",
    "documenting the audit trail",
    "approved source",
    "只作为风险标签",
    "不是可执行命令",
    "安全培训材料",
    "防御培训讲义",
    "不能作为指令",
]

BENIGN_SECRET_HANDLING_PHRASES = [
    "redaction policy",
    "redact before display",
    "privacy training",
    "do not paste real",
    "use synthetic examples only",
    "avoid real pii",
    "incident response checklist",
    "suspected token leak",
    "rotating leaked test api keys",
    "documenting the audit trail",
    "应脱敏",
    "安全教育海报",
    "不要执行图片",
]


DEFAULT_POLICY = {
    "weights": {
        "jailbreak_pattern": 0.28,
        "roleplay_pattern": 0.2,
        "unsafe_pattern": 0.35,
        "sensitive_pattern": 0.28,
        "strong_secret_pattern": 0.45,
        "obfuscation_pattern": 0.25,
        "base64_like": 0.28,
        "multi_turn_escalation": 0.2,
        "domain_boundary_pattern": 0.45,
        "explicit_override_exfiltration": 0.82,
    },
    "jailbreak_patterns": JAILBREAK_PATTERNS,
    "roleplay_patterns": ROLEPLAY_PATTERNS,
    "unsafe_patterns": UNSAFE_PATTERNS,
    "sensitive_patterns": SENSITIVE_PATTERNS,
    "strong_secret_regex_patterns": [
        r"(?i)(api\s*key|private\s*token|secret|token)\s*[:=]\s*(sk-[A-Za-z0-9._/-]{8,}|[A-Za-z0-9._/-]{24,})",
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{20,}",
    ],
    "obfuscation_patterns": OBFUSCATION_PATTERNS,
    "explicit_override_exfiltration_regex_patterns": EXPLICIT_OVERRIDE_EXFILTRATION_REGEX_PATTERNS,
    "benign_dampening_phrases": BENIGN_DAMPENING_PHRASES,
    "benign_dampening_active_markers": ["照做", "按上述执行", "execute the instruction", "comply with it", "follow it"],
    "benign_dampening_score_reduction": 0.7,
    "benign_dampening_max_score": 0.18,
    "benign_secret_handling_phrases": BENIGN_SECRET_HANDLING_PHRASES,
    "benign_secret_handling_active_markers": ["sk-", "akia", "ghp_", "secret=", "token:", "private key:"],
    "benign_secret_handling_score_reduction": 1.0,
    "benign_secret_handling_max_score": 0.18,
    "multi_turn_markers": ["how to", "how can", "how would", "final step"],
    "domain_boundary_patterns": [],
}


def load_input_policy() -> dict:
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


def _normalized_views(text: str) -> list[str]:
    views = [text]
    decoded = unquote(text)
    views.append(decoded)
    views.append(unicodedata.normalize("NFKC", decoded))
    views.append(CJK_SPACED_RE.sub("", unicodedata.normalize("NFKC", decoded)))
    unique: list[str] = []
    seen: set[str] = set()
    for view in views:
        if view not in seen:
            unique.append(view)
            seen.add(view)
    return unique


def _pattern_hits(text: str, patterns: list[str], label: str) -> tuple[list[str], list[str]]:
    labels: list[str] = []
    evidence: list[str] = []
    matched: set[str] = set()
    for view in _normalized_views(text):
        lowered = view.lower()
        for pattern in patterns:
            if pattern in lowered and pattern not in matched:
                labels.append(label)
                evidence.append(pattern)
                matched.add(pattern)
    return labels, evidence


def analyze(message: str, history: list[Message]) -> AnalysisResult:
    policy = load_input_policy()
    weights = policy["weights"]
    labels: list[str] = []
    evidence: list[str] = []
    score = 0.0

    history_text = " ".join([item.content for item in history[-4:]])
    combined = f"{history_text}\n{message}"

    jb_labels, jb_ev = _pattern_hits(combined, policy["jailbreak_patterns"], "jailbreak")
    labels.extend(jb_labels)
    evidence.extend(jb_ev)
    score += float(weights["jailbreak_pattern"]) * len(jb_ev)

    roleplay_labels, roleplay_ev = _pattern_hits(combined, policy["roleplay_patterns"], "roleplay_jailbreak")
    labels.extend(roleplay_labels)
    evidence.extend(roleplay_ev)
    score += float(weights["roleplay_pattern"]) * len(roleplay_ev)

    unsafe_labels, unsafe_ev = _pattern_hits(combined, policy["unsafe_patterns"], "unsafe_content")
    labels.extend(unsafe_labels)
    evidence.extend(unsafe_ev)
    score += float(weights["unsafe_pattern"]) * len(unsafe_ev)

    sensitive_labels, sensitive_ev = _pattern_hits(combined, policy["sensitive_patterns"], "secret_extraction")
    labels.extend(sensitive_labels)
    evidence.extend(sensitive_ev)
    score += float(weights["sensitive_pattern"]) * len(sensitive_ev)

    for pattern in policy.get("strong_secret_regex_patterns", []):
        if re.search(pattern, combined):
            labels.append("secret_extraction")
            evidence.append("strong_secret_pattern")
            score += float(weights.get("strong_secret_pattern", 0.45))

    obf_labels, obf_ev = _pattern_hits(combined, policy["obfuscation_patterns"], "obfuscation")
    labels.extend(obf_labels)
    evidence.extend(obf_ev)
    score += float(weights["obfuscation_pattern"]) * len(obf_ev)

    domain_labels, domain_ev = _pattern_hits(combined, policy.get("domain_boundary_patterns", []), "domain_boundary_violation")
    labels.extend(domain_labels)
    evidence.extend(domain_ev)
    score += float(weights.get("domain_boundary_pattern", 0.45)) * len(domain_ev)

    explicit_override_exfiltration = any(
        re.search(pattern, view)
        for view in _normalized_views(combined)
        for pattern in policy.get("explicit_override_exfiltration_regex_patterns", [])
    )
    if explicit_override_exfiltration:
        labels.extend(["instruction_override", "secret_extraction"])
        evidence.append("explicit_override_exfiltration")
        score += float(weights.get("explicit_override_exfiltration", 0.82))

    if BASE64_LIKE_RE.search(message):
        labels.append("obfuscation")
        evidence.append("base64_like_blob")
        score += float(weights["base64_like"])

    # Multi-turn escalation heuristic: repeated operational questioning over history.
    how_markers = policy["multi_turn_markers"]
    repeated_how_to = sum(history_text.lower().count(marker) + message.lower().count(marker) for marker in how_markers)
    if repeated_how_to >= 2 or ("bypass" in combined.lower() and "step" in combined.lower()):
        labels.append("multi_turn_escalation")
        evidence.append("repeated_how_to")
        score += float(weights["multi_turn_escalation"])

    semantic = semantic_guard.analyze_text(combined, surface="input")
    labels.extend(semantic.labels)
    evidence.extend(semantic.evidence)
    score += semantic.risk_score

    lowered = combined.lower()
    benign_training = any(phrase in lowered for phrase in policy.get("benign_dampening_phrases", []))
    active_marker = any(marker in lowered for marker in policy.get("benign_dampening_active_markers", []))
    if benign_training and not active_marker:
        hard_labels = {"unsafe_content", "secret_extraction", "obfuscation", "multi_turn_escalation", "roleplay_jailbreak"}
        if not hard_labels.intersection(labels):
            labels.append("benign_safety_framing")
            evidence.append("benign_dampening_phrase")
            score = max(0.0, score - float(policy.get("benign_dampening_score_reduction", 0.5)))
            score = min(score, float(policy.get("benign_dampening_max_score", 1.0)))

    benign_secret_policy = any(phrase in lowered for phrase in policy.get("benign_secret_handling_phrases", []))
    secret_active_marker = any(marker in lowered for marker in policy.get("benign_secret_handling_active_markers", []))
    if "secret_extraction" in labels and benign_secret_policy and not secret_active_marker:
        hard_labels = {"unsafe_content", "obfuscation", "multi_turn_escalation", "roleplay_jailbreak"}
        if not hard_labels.intersection(labels):
            labels.append("benign_secret_handling_policy")
            evidence.append("benign_secret_handling_phrase")
            score = max(0.0, score - float(policy.get("benign_secret_handling_score_reduction", 1.0)))
            score = min(score, float(policy.get("benign_secret_handling_max_score", 1.0)))

    dedup_labels = sorted(set(labels))
    dedup_evidence = sorted(set(evidence))
    return AnalysisResult(
        risk_score=min(score, 1.0),
        labels=dedup_labels,
        evidence=dedup_evidence,
        metadata={"semantic": semantic.metadata},
    )
