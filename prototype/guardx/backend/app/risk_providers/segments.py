from typing import Any

from app.contracts import RiskSegment, TrustBoundary


def canonical_surface(surface: str | None) -> str:
    raw = (surface or "chat").strip().lower()
    if raw in {"default", "chat", "user"}:
        return "chat"
    if raw in {"rag", "retrieval", "retrieved_context"}:
        return "rag"
    if raw in {"agent", "agent_tool", "tool", "action", "tool_call"}:
        return "agent_tool"
    if raw in {
        "bash",
        "shell",
        "command",
        "ipython",
        "file",
        "file_read",
        "file_write",
        "file_edit",
        "browser",
        "http",
        "network",
        "mcp",
        "plugin",
        "db",
        "database",
        "sql",
    }:
        return "agent_tool"
    if raw in {"vlm", "vlm_ocr", "ocr", "vision"}:
        return "vlm"
    if raw in {"eval", "evaluation", "benchmark"}:
        return "eval"
    return raw


def trust_boundary(
    *,
    source: str,
    trust_level: str,
    executable: bool = False,
    can_instruct_model: bool = False,
) -> TrustBoundary:
    return TrustBoundary(
        source=source,
        trust_level=trust_level,
        executable=executable,
        can_instruct_model=can_instruct_model,
    )


def build_chat_segments(message: str, *, surface: str = "chat") -> list[RiskSegment]:
    return [
        RiskSegment(
            segment_id=f"{canonical_surface(surface)}:user:0",
            text=message,
            trust_boundary=trust_boundary(
                source="user",
                trust_level="bounded",
                executable=False,
                can_instruct_model=True,
            ),
        )
    ]


def build_rag_segments(message: str, context_chunks: list[str]) -> list[RiskSegment]:
    segments = build_chat_segments(message, surface="rag")
    for index, chunk in enumerate(context_chunks):
        segments.append(
            RiskSegment(
                segment_id=f"rag:retrieved_context:{index}",
                text=str(chunk),
                trust_boundary=trust_boundary(
                    source="retrieved_context",
                    trust_level="untrusted",
                    executable=False,
                    can_instruct_model=False,
                ),
            )
        )
    return segments


def build_vlm_segments(
    message: str,
    *,
    ocr_text: str = "",
    vlm_answer: str | None = None,
    visual_caption: str | None = None,
    visual_signals: list[Any] | None = None,
) -> list[RiskSegment]:
    segments = build_chat_segments(message, surface="vlm")
    if ocr_text:
        segments.append(
            RiskSegment(
                segment_id="vlm:ocr:0",
                text=ocr_text,
                trust_boundary=trust_boundary(source="ocr", trust_level="untrusted"),
            )
        )
    if vlm_answer:
        segments.append(
            RiskSegment(
                segment_id="vlm:tool_output:0",
                text=vlm_answer,
                trust_boundary=trust_boundary(source="tool_output", trust_level="untrusted"),
            )
        )
    if visual_caption:
        segments.append(
            RiskSegment(
                segment_id="vlm:tool_output:1",
                text=visual_caption,
                trust_boundary=trust_boundary(source="tool_output", trust_level="untrusted"),
            )
        )
    if visual_signals:
        segments.append(
            RiskSegment(
                segment_id="vlm:tool_output:signals",
                text=", ".join(str(item) for item in visual_signals[:12]),
                trust_boundary=trust_boundary(source="tool_output", trust_level="untrusted"),
            )
        )
    return segments
