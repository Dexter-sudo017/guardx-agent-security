from __future__ import annotations

from typing import Any

from app.approval import ApprovalStore
from app.capabilities import CapabilityStore
from app.continuation import DefaultContinuationHook, DeterministicContinuationHook
from app.contracts import AuthorizationFinding, ContextualAuthorizationRequest
from app.executor_secure.registry import SecureRunnerRegistry
from app.executor_secure.runtime import SecureExecutor
from app.executor_secure.capability_mapping import CAPABILITY_RUNNERS
from app.guards.contextual_authorization_provider import ContextualAuthorizationProvider
from app.integration.core_v2_bridge import (
    CoreV2CapabilityVerifierAdapter,
    CoreV2ExecutorContractBridge,
    CoreV2PolicyAttestationVerifier,
)
from app.integration.evidence import InMemoryExecutorEvidenceSink
from app.integration.executor_service import ExecutorIntegrationService
from app.policy.runtime import PolicyMode, configured_policy_mode, evaluate_authorization


class AuthorizationRuntime:
    """Orchestrates authorization before the frozen executor service contract."""

    def __init__(
        self,
        registry: SecureRunnerRegistry,
        executor: SecureExecutor,
        approvals: ApprovalStore,
        authorization_provider: ContextualAuthorizationProvider | None = None,
        capability_store: CapabilityStore | None = None,
        policy_mode: PolicyMode | None = None,
        continuation_hook: DeterministicContinuationHook | None = None,
        executor_bridge: CoreV2ExecutorContractBridge | None = None,
    ) -> None:
        self.registry = registry
        self.executor = executor
        self.approvals = approvals
        self.authorization_provider = authorization_provider
        self.capability_store = capability_store or CapabilityStore(store_id="runtime_empty_store")
        self.policy_mode = policy_mode or configured_policy_mode()
        self.continuation_hook = continuation_hook or DefaultContinuationHook()
        if executor_bridge is None:
            policy_verifier = CoreV2PolicyAttestationVerifier()
            capability_verifier = CoreV2CapabilityVerifierAdapter(self.capability_store)
            executor_service = ExecutorIntegrationService(
                execution_scope_id=next(
                    runner.sandbox.execution_id
                    for runner in registry.runners.values()
                    if hasattr(runner, "sandbox")
                ),
                registry=registry,
                executor=executor,
                approvals=approvals,
                policy_verifier=policy_verifier,
                capability_verifier=capability_verifier,
                evidence_sink=InMemoryExecutorEvidenceSink(),
            )
            executor_bridge = CoreV2ExecutorContractBridge(
                executor_service,
                policy_verifier,
                capability_verifier,
            )
        self.executor_bridge = executor_bridge
        self._approval_contexts: dict[str, tuple[ContextualAuthorizationRequest, dict[str, Any], str, str]] = {}

    @staticmethod
    def _runner_id(capability: str) -> str:
        try:
            return CAPABILITY_RUNNERS[capability]
        except KeyError as exc:
            raise ValueError(f"capability has no real runner mapping: {capability}") from exc

    def _model_finding(self, request: ContextualAuthorizationRequest) -> AuthorizationFinding | None:
        if self.authorization_provider is None:
            return None
        return self.authorization_provider.analyze_fail_safe(request)

    def _evaluate(
        self,
        request: ContextualAuthorizationRequest,
        *,
        model_finding: AuthorizationFinding | None,
    ):
        return evaluate_authorization(
            request,
            mode=self.policy_mode,
            capability_store=self.capability_store,
            model_finding=model_finding,
        )

    def run(
        self,
        *,
        execution_id: str,
        session_id: str,
        request: ContextualAuthorizationRequest,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        runner_id = self._runner_id(request.requested_capability)
        runner = self.registry.get(runner_id)
        if execution_id != self.executor_bridge.service.execution_scope_id:
            raise PermissionError("execution_id is not bound to the configured executor service scope")
        precheck = runner.normalize_and_precheck(args)
        normalized_args = precheck.normalized_args if precheck.allowed else dict(args)

        declared_args = request.proposed_action.get("arguments")
        arguments_match = declared_args is None or declared_args == normalized_args
        bound_action = dict(request.proposed_action)
        bound_action["arguments"] = dict(normalized_args)
        bound_destination = request.destination or normalized_args.get("destination") or normalized_args.get("url")
        evaluation_request = request.model_copy(
            update={
                "proposed_action": bound_action,
                "destination": str(bound_destination) if bound_destination else None,
                "action_alignment": False if not arguments_match else request.action_alignment,
            }
        )
        model_finding = self._model_finding(evaluation_request)
        decision = self._evaluate(evaluation_request, model_finding=model_finding)
        if not arguments_match:
            decision.finding.evidence["runtime_argument_binding_failure"] = True
        continuation = self.continuation_hook.plan(evaluation_request, decision.finding)
        decision.continuation = continuation.model_dump(mode="json") | {"hook_invoked": True}
        tool = str(evaluation_request.proposed_action.get("tool") or runner_id)
        target = runner.approval_target(normalized_args) if precheck.allowed else "invalid://runner-precheck"
        executor_request = self.executor_bridge.build_request(
            session_id=session_id,
            context=evaluation_request,
            decision=decision,
            continuation=continuation.model_dump(mode="json"),
            tool=tool,
            target=target,
            arguments=normalized_args,
        )
        contract_response = self.executor_bridge.execute(executor_request)
        side_effect_count = int(contract_response.get("side_effect_summary", {}).get("side_effect_count", 0))
        result: dict[str, Any] = {
            "execution_id": contract_response["execution_id"],
            "execution_scope_id": execution_id,
            "session_id": session_id,
            "authorization": decision.model_dump(mode="json"),
            "model_finding": model_finding.model_dump(mode="json") if model_finding else None,
            "continuation": continuation.model_dump(mode="json"),
            "executor_contract": contract_response,
            "runner_invoked": bool(contract_response["executed"]),
            "side_effect_count": side_effect_count,
        }
        if not precheck.allowed or not runner.capability_precheck(evaluation_request.requested_capability, normalized_args):
            result |= {
                "runner_precheck": "deny",
                "runner_precheck_reason": precheck.reason if not precheck.allowed else "capability binding mismatch",
            }
        if contract_response.get("approval_id"):
            approval_id = str(contract_response["approval_id"])
            self._approval_contexts[approval_id] = (evaluation_request, normalized_args, tool, target)
            result |= {"approval_id": approval_id, "approval_status": "PAUSED"}
        if contract_response["execution_state"] in {"EXECUTED", "RESUMED"}:
            result["execution_result"] = contract_response
        return result

    def resume(
        self,
        approval_id: str,
        *,
        session_id: str,
        capability: str,
        tool: str,
        target: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        record = self.approvals.get(approval_id)
        if record.status not in {"APPROVED", "RESUMED"}:
            raise ValueError(f"approval must be APPROVED before resume, observed {record.status}")
        try:
            request, original_args, original_tool, original_target = self._approval_contexts[approval_id]
        except KeyError as exc:
            raise PermissionError("approval context is unavailable; fail closed pending durable request-store integration") from exc
        if request.requested_capability != record.capability or record.runner_id != self._runner_id(record.capability):
            raise ValueError("approval capability or runner binding mismatch")
        runner = self.registry.get(record.runner_id)
        precheck = runner.normalize_and_precheck(args)
        if not precheck.allowed or not runner.capability_precheck(capability, precheck.normalized_args):
            raise PermissionError("resumed call failed runner precheck")
        observed_target = runner.approval_target(precheck.normalized_args)
        if observed_target != target:
            raise PermissionError("caller target does not match normalized runner target")
        if precheck.normalized_args != original_args or tool != original_tool or target != original_target:
            raise PermissionError("approval target, tool, or arguments changed after pause")

        approved_request = request.model_copy(update={"approval_state": "approved"})
        reauthorization = self._evaluate(approved_request, model_finding=None)
        if reauthorization.enforcement not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS", "REQUIRE_APPROVAL"}:
            raise PermissionError(f"approval resume failed reauthorization: {reauthorization.enforcement}")
        # R4-D compatibility: once a scoped approval is verified, continuation
        # observes the effective authorized action. The executor contract keeps
        # REQUIRE_APPROVAL so its frozen service consumes the grant atomically.
        continuation_finding = reauthorization.finding.model_copy(update={"decision": "ALLOW"})
        continuation = self.continuation_hook.plan(approved_request, continuation_finding)
        if continuation.control_flow not in {"CONTINUE", "COMPLETED"}:
            raise PermissionError(f"approval resume continuation is not executable: {continuation.control_flow}")

        executor_request = self.executor_bridge.build_request(
            session_id=session_id,
            context=approved_request,
            decision=reauthorization,
            continuation=continuation.model_dump(mode="json"),
            tool=tool,
            target=target,
            arguments=precheck.normalized_args,
            approval_reference=approval_id,
        )
        contract_response = self.executor_bridge.execute(executor_request)
        if contract_response["execution_state"] != "RESUMED":
            raise PermissionError(f"approval resume rejected by executor service: {contract_response['error_code']}")
        return contract_response

    def reject(self, approval_id: str, *, rejected_by: str, trusted_origin: str) -> dict[str, Any]:
        return self.approvals.reject(
            approval_id,
            rejected_by=rejected_by,
            trusted_origin=trusted_origin,
        ).as_dict()
