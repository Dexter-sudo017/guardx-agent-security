from app.models import ToolDecision


def _decision(allowed: bool, reason: str, mode: str, rule_id: str, **kwargs) -> ToolDecision:
    return ToolDecision(allowed=allowed, reason=reason, mode=mode, rule_id=rule_id, **kwargs)


def review_enterprise_search(args: dict) -> ToolDecision:
    query = str(args.get("query") or "").strip()
    if not query or len(query) > 600:
        return _decision(False, "Enterprise search query is missing or exceeds the limit.", "deny", "enterprise_search.invalid_query")
    return _decision(True, "Read-only enterprise knowledge search allowed.", "read_only", "enterprise_search.allowed", sanitized_args=args)


def review_create_review_ticket(args: dict) -> ToolDecision:
    required = ("title", "summary", "requested_by", "approval_id")
    missing = [key for key in required if not str(args.get(key) or "").strip()]
    if missing:
        return _decision(False, "Review ticket fields are incomplete.", "deny", "review_ticket.missing_fields", evidence=missing)
    approval_id = str(args.get("approval_id") or "")
    if not approval_id.startswith("APPROVED-"):
        return _decision(False, "Review ticket is outside the explicit approval scope.", "deny", "review_ticket.approval_required", evidence=[approval_id])
    return _decision(True, "Controlled review-ticket creation allowed by explicit approval.", "controlled_side_effect", "review_ticket.approved", sanitized_args={key: value for key, value in args.items() if key in required}, evidence=[approval_id], constraints={"local_only": True, "rollback_supported": True})
