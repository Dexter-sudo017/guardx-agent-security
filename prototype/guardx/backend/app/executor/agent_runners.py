from __future__ import annotations

import json
import os
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

from app.executor.runtime_models import ToolExecutionOutcome


class EnterpriseKnowledgeSearchRunner:
    project_root = Path(__file__).resolve().parents[5]
    knowledge_path = project_root / "sandbox" / "demo" / "enterprise-knowledge.txt"

    def run(self, *, execution_key: str, tool_name: str, args: dict[str, Any]) -> ToolExecutionOutcome:
        if tool_name != "enterprise_search_safe":
            raise ValueError("enterprise knowledge runner received an unsupported tool")
        query = str(args.get("query") or "").strip().lower()
        if not query:
            raise ValueError("knowledge query is required")
        top_k = max(1, min(int(args.get("top_k") or 3), 5))
        lines = [line.strip() for line in self.knowledge_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        tokens = set(re.findall(r"[a-z0-9]+|[\u4e00-\u9fff]", query))
        ranked = sorted(lines, key=lambda line: -sum(token in line.lower() for token in tokens))[:top_k]
        return ToolExecutionOutcome(
            output_ref=f"{execution_key}:enterprise_search",
            observation="\n".join(ranked),
            metadata={"tool_name": tool_name, "execution_mode": "local_enterprise_search_read_only", "knowledge_sha256": sha256(self.knowledge_path.read_bytes()).hexdigest(), "read_only": True, "result_count": len(ranked)},
        )

    def rollback(self, *, execution_key: str, tool_name: str, args: dict[str, Any], error: str) -> ToolExecutionOutcome:
        return ToolExecutionOutcome(output_ref=f"{execution_key}:rollback_not_required", observation="Read-only knowledge search has no rollback action.", metadata={"tool_name": tool_name, "error": error, "read_only": True})


class ControlledReviewTicketRunner:
    @staticmethod
    def _root() -> Path:
        return Path(os.environ.get("GUARDX_AGENT_TICKET_ROOT", r"E:\GuardX\runtime\agent-tickets")).resolve()

    @staticmethod
    def _target(root: Path, execution_key: str) -> Path:
        safe_key = re.sub(r"[^a-zA-Z0-9_-]", "-", execution_key)[:96]
        target = (root / f"{safe_key}.json").resolve()
        if not target.is_relative_to(root):
            raise PermissionError("ticket path escaped the controlled root")
        return target

    def run(self, *, execution_key: str, tool_name: str, args: dict[str, Any]) -> ToolExecutionOutcome:
        if tool_name != "create_review_ticket_safe":
            raise ValueError("controlled ticket runner received an unsupported tool")
        root = self._root()
        root.mkdir(parents=True, exist_ok=True)
        target = self._target(root, execution_key)
        record = {key: str(args.get(key) or "")[:limit] for key, limit in {"title": 160, "summary": 1200, "requested_by": 120, "approval_id": 120}.items()}
        record["execution_key"] = execution_key
        encoded = json.dumps(record, ensure_ascii=False, indent=2).encode("utf-8")
        target.write_bytes(encoded)
        return ToolExecutionOutcome(output_ref=f"{execution_key}:review_ticket", observation=f"Review ticket created: {target.name}", metadata={"tool_name": tool_name, "execution_mode": "controlled_local_side_effect", "ticket_file": target.name, "content_sha256": sha256(encoded).hexdigest(), "side_effect": True})

    def rollback(self, *, execution_key: str, tool_name: str, args: dict[str, Any], error: str) -> ToolExecutionOutcome:
        target = self._target(self._root(), execution_key)
        removed = target.is_file()
        if removed:
            target.unlink()
        return ToolExecutionOutcome(output_ref=f"{execution_key}:ticket_rollback", observation="Controlled ticket rollback completed.", metadata={"tool_name": tool_name, "error": error, "removed": removed})
