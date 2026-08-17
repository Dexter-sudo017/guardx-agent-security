from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parents[2]
DEFAULT_GRAPH = PROJECT_ROOT / "evidence" / "agentdojo_injecagent_official_task_graph_mapping.json"
DEFAULT_HARNESS_ROOT = PROJECT_ROOT / "evaluation" / "runs" / "agentdojo_injecagent_task_state"
DEFAULT_OUT = PROJECT_ROOT / "evidence" / "agentdojo_injecagent_task_graph_replay_alignment.json"
DEFAULT_LATEST = BACKEND_ROOT / "data" / "experiment_runs" / "latest_agentdojo_injecagent_task_graph_replay_alignment.json"
DEFAULT_REPORT = PROJECT_ROOT / "team" / "zzh" / "experiments" / f"agentdojo_injecagent_task_graph_replay_alignment_{date.today().isoformat()}.md"


def _project_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _latest_harness_summary(root: Path) -> Path:
    candidates = [path for path in root.glob("*/summary.json") if path.is_file()]
    if not candidates:
        raise FileNotFoundError(f"No task-state harness summary found under {root}")
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _decision_rows(summary: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in summary.get("rows", []):
        if not isinstance(row, dict) or row.get("step_type") != "decide":
            continue
        grouped.setdefault(str(row.get("case_id")), []).append(row)
    return grouped


def _action_nodes(graph: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = [node for node in graph.get("nodes", []) if isinstance(node, dict) and node.get("node_type") == "tool_action"]
    return sorted(nodes, key=lambda item: str(item.get("node_id") or ""))


def _align_graph(graph: dict[str, Any], decisions_by_case: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    case_id = str(graph.get("case_id"))
    nodes = _action_nodes(graph)
    decisions = decisions_by_case.get(case_id, [])
    rows: list[dict[str, Any]] = []
    for index, node in enumerate(nodes):
        decision = decisions[index] if index < len(decisions) else {}
        expected_allowed = bool(node.get("expected_allowed"))
        actual_allowed = decision.get("allowed")
        decision_passed = bool(decision.get("passed")) if decision else False
        node_matches_decision = bool(decision) and decision.get("expected_allowed") == expected_allowed
        rows.append(
            {
                "case_id": case_id,
                "benchmark_family": graph.get("benchmark_family"),
                "expected_label": graph.get("expected_label"),
                "node_id": node.get("node_id"),
                "surface": node.get("surface"),
                "action_hash": node.get("action_hash"),
                "expected_allowed": expected_allowed,
                "actual_allowed": actual_allowed,
                "decision_mode": decision.get("mode"),
                "decision_reason": decision.get("reason"),
                "defense_actions": decision.get("defense_actions") or [],
                "decision_passed": decision_passed,
                "node_matches_decision": node_matches_decision,
                "alignment_passed": decision_passed and node_matches_decision,
            }
        )
    return {
        "case_id": case_id,
        "benchmark_family": graph.get("benchmark_family"),
        "expected_label": graph.get("expected_label"),
        "action_node_count": len(nodes),
        "decision_count": len(decisions),
        "aligned_action_count": sum(1 for row in rows if row["alignment_passed"]),
        "all_actions_aligned": bool(nodes) and all(row["alignment_passed"] for row in rows) and len(nodes) == len(decisions),
        "private_asset_count": graph.get("private_asset_count"),
        "public_asset_count": graph.get("public_asset_count"),
        "expected_security_outcome": graph.get("expected_security_outcome"),
        "expected_utility_outcome": graph.get("expected_utility_outcome"),
        "actions": rows,
    }


def build_alignment(graph_path: Path, harness_summary_path: Path) -> dict[str, Any]:
    graph_payload = _load_json(graph_path)
    harness_summary = _load_json(harness_summary_path)
    decisions_by_case = _decision_rows(harness_summary)
    cases = [_align_graph(graph, decisions_by_case) for graph in graph_payload.get("graphs", []) if isinstance(graph, dict)]
    action_rows = [row for case in cases for row in case["actions"]]
    risky_security_rows = [
        row
        for row in action_rows
        if row.get("expected_label") == "risky" and row.get("expected_allowed") is False
    ]
    utility_rows = [row for row in action_rows if row.get("expected_allowed") is True]
    benign_rows = [row for row in action_rows if row.get("expected_label") == "benign"]
    summary = {
        "case_count": len(cases),
        "action_node_count": len(action_rows),
        "aligned_action_count": sum(1 for row in action_rows if row["alignment_passed"]),
        "all_case_graphs_aligned": bool(cases) and all(case["all_actions_aligned"] for case in cases),
        "alignment_pass_rate": round(sum(1 for row in action_rows if row["alignment_passed"]) / max(1, len(action_rows)), 6),
        "security_block_rate": round(
            sum(1 for row in risky_security_rows if row.get("actual_allowed") is False) / max(1, len(risky_security_rows)),
            6,
        ),
        "utility_allow_rate": round(
            sum(1 for row in utility_rows if row.get("actual_allowed") is True) / max(1, len(utility_rows)),
            6,
        ),
        "benign_block_rate": round(
            sum(1 for row in benign_rows if row.get("actual_allowed") is False) / max(1, len(benign_rows)),
            6,
        ),
        "family_counts": dict(Counter(str(case.get("benchmark_family")) for case in cases)),
        "decision_mode_counts": dict(Counter(str(row.get("decision_mode")) for row in action_rows)),
        "defense_action_counts": dict(
            Counter(str(action) for row in action_rows for action in (row.get("defense_actions") or []))
        ),
    }
    return {
        "schema_version": "guardx-agentdojo-injecagent-task-graph-replay-alignment-v1",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "graph_mapping": _project_path(graph_path),
        "task_state_harness_summary": _project_path(harness_summary_path),
        "claim_boundary": "Task graph to GuardX replay/decision alignment; not official AgentDojo/InjecAgent leaderboard.",
        "raw_prompt_policy": "safe_abstraction_hash_only_no_raw_high_risk_prompt",
        "summary": summary,
        "cases": cases,
    }


def _markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# AgentDojo / InjecAgent Task Graph Replay Alignment",
        "",
        f"- Updated: `{date.today().isoformat()}`",
        f"- Graph mapping: `{payload['graph_mapping']}`",
        f"- Harness summary: `{payload['task_state_harness_summary']}`",
        f"- Claim boundary: {payload['claim_boundary']}",
        f"- Raw prompt policy: `{payload['raw_prompt_policy']}`",
        "",
        "| metric | value |",
        "| --- | ---: |",
        f"| Cases | {summary['case_count']} |",
        f"| Action nodes | {summary['action_node_count']} |",
        f"| Aligned actions | {summary['aligned_action_count']} |",
        f"| Alignment pass rate | {summary['alignment_pass_rate']} |",
        f"| Security block rate | {summary['security_block_rate']} |",
        f"| Utility allow rate | {summary['utility_allow_rate']} |",
        f"| Benign block rate | {summary['benign_block_rate']} |",
        "",
        "## Per-case Alignment",
        "",
        "| case | family | label | action nodes | decisions | aligned | private assets | security outcome | utility outcome |",
        "| --- | --- | --- | ---: | ---: | --- | ---: | --- | --- |",
    ]
    for case in payload["cases"]:
        lines.append(
            f"| {case['case_id']} | {case.get('benchmark_family')} | {case.get('expected_label')} | "
            f"{case['action_node_count']} | {case['decision_count']} | {case['all_actions_aligned']} | "
            f"{case.get('private_asset_count')} | {case.get('expected_security_outcome')} | {case.get('expected_utility_outcome')} |"
        )
    lines.extend(
        [
            "",
            "## Why This Matters",
            "",
            "- The earlier task graph evidence shows the benchmark-like task structure; this alignment proves each proposed action node is actually consumed by GuardX action guard and mapped to an allow/block decision.",
            "- The evidence connects official-style fields: user goal, tool state, untrusted observation, proposed tool action, GuardX precheck, DefenseAction, and utility/security outcomes.",
            "- The remaining gap is still upstream official task ids and official utility/security scorers. This remains local task-graph replay evidence, not leaderboard output.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Align AgentDojo/InjecAgent task graph nodes with GuardX replay/decision rows.")
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--harness-summary", type=Path, default=None)
    parser.add_argument("--harness-root", type=Path, default=DEFAULT_HARNESS_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--latest", type=Path, default=DEFAULT_LATEST)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    harness_summary = args.harness_summary or _latest_harness_summary(args.harness_root)
    payload = build_alignment(args.graph, harness_summary)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    args.latest.parent.mkdir(parents=True, exist_ok=True)
    args.latest.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(_markdown(payload), encoding="utf-8")
    print(
        json.dumps(
            {
                "out": _project_path(args.out),
                "latest": _project_path(args.latest),
                "report": _project_path(args.report),
                "alignment_pass_rate": payload["summary"]["alignment_pass_rate"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if payload["summary"]["all_case_graphs_aligned"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
