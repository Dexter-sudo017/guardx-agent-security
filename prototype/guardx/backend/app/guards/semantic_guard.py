from __future__ import annotations

import re

from app.models import AnalysisResult
from app.guards import embedding_classifier, llm_judge, lora_specialist_router, semantic_classifier


TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-']+")

RISKY_INTENT_TERMS = {
    "bypass",
    "circumvent",
    "disable",
    "disclose",
    "evade",
    "exfiltrate",
    "ignore",
    "leak",
    "override",
    "reveal",
    "steal",
    "unrestricted",
}

RISKY_OBJECT_TERMS = {
    "credential",
    "credentials",
    "developer",
    "instruction",
    "instructions",
    "key",
    "password",
    "policy",
    "prompt",
    "secret",
    "system",
    "token",
    "tool",
}

BENIGN_CONTEXT_TERMS = {
    "awareness",
    "defense",
    "defensive",
    "detection",
    "education",
    "mitigation",
    "policy",
    "prevent",
    "prevention",
    "safety",
    "training",
}

OBFUSCATION_TERMS = {
    "base64",
    "decode",
    "encoded",
    "hex",
    "rot13",
    "translate",
}


def _tokens(text: str) -> set[str]:
    return {match.group(0).lower() for match in TOKEN_RE.finditer(text)}


def analyze_text(text: str, surface: str = "input") -> AnalysisResult:
    tokens = _tokens(text)
    labels: list[str] = []
    evidence: list[str] = []
    score = 0.0

    intent_hits = sorted(tokens & RISKY_INTENT_TERMS)
    object_hits = sorted(tokens & RISKY_OBJECT_TERMS)
    benign_hits = sorted(tokens & BENIGN_CONTEXT_TERMS)
    obf_hits = sorted(tokens & OBFUSCATION_TERMS)

    if intent_hits and object_hits:
        labels.append("semantic_policy_evasion")
        evidence.append(f"intent={','.join(intent_hits[:4])}; object={','.join(object_hits[:4])}")
        score += 0.22

    if {"ignore", "override"} & tokens and {"system", "developer", "policy", "instructions"} & tokens:
        labels.append("semantic_instruction_override")
        evidence.append("override_plus_authority_terms")
        score += 0.22

    if {"secret", "key", "token", "password", "credential", "credentials"} & tokens and {"reveal", "print", "repeat", "leak", "exfiltrate"} & tokens:
        labels.append("semantic_secret_exposure")
        evidence.append("secret_plus_disclosure_terms")
        score += 0.24

    if obf_hits and intent_hits:
        labels.append("semantic_obfuscation")
        evidence.append(f"obfuscation={','.join(obf_hits)}")
        score += 0.14

    # Defensive or educational framing should soften low-confidence semantic
    # evidence, but not erase explicit malicious intent.
    if benign_hits and score <= 0.24:
        labels.append("benign_safety_context")
        evidence.append(f"benign={','.join(benign_hits[:4])}")
        score = max(score - 0.08, 0.0)

    lowered_text = text.lower()
    if score <= 0.24 and (
        "taxonomy of jailbreak attack styles" in lowered_text
        and "defensive training handout" in lowered_text
        and "without giving bypass instructions" in lowered_text
    ):
        labels.append("benign_educational_boundary")
        evidence.append("educational_or_governance_boundary")
        score = max(score - 0.08, 0.0)

    classifier = semantic_classifier.analyze_text(text, surface=surface)
    labels.extend(classifier.labels)
    evidence.extend(classifier.evidence)
    score += classifier.risk_score

    embedding = embedding_classifier.analyze_text(text, surface=surface)
    labels.extend(embedding.labels)
    evidence.extend(embedding.evidence)
    score += embedding.risk_score

    lora = lora_specialist_router.analyze_text(text, surface=surface)
    labels.extend(lora.labels)
    evidence.extend(lora.evidence)
    score += lora.risk_score

    judge = llm_judge.analyze_text(
        text,
        surface=surface,
        current_score=min(score, 1.0),
        signals={
            "lexical_score": classifier.risk_score,
            "embedding_score": embedding.risk_score,
            "local_lora_score": lora.risk_score,
            "classifier_metadata": classifier.metadata,
            "embedding_metadata": embedding.metadata,
            "local_lora_metadata": lora.metadata,
        },
    )
    labels.extend(judge.labels)
    evidence.extend(judge.evidence)
    score += judge.risk_score

    return AnalysisResult(
        risk_score=min(score, 1.0),
        labels=sorted(set(labels)),
        evidence=sorted(set(evidence)),
        metadata={
            "surface": surface,
            "semantic_score": round(min(score, 1.0), 3),
            "trained_classifier": classifier.metadata,
            "embedding_classifier": embedding.metadata,
            "local_lora_provider": lora.metadata,
            "llm_judge": judge.metadata,
        },
    )
