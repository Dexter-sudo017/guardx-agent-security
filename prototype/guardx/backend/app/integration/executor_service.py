from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.approval import ApprovalRecord, ApprovalStore
from app.contracts.executor_integration import (
    ApprovalInspectResponse,
    ApprovalRequestCreate,
    ApprovalValidationResponse,
    ExecutorServiceRequest,
    ExecutorServiceResponse,
    SessionExecutionTraceResponse,
)
from app.executor_secure.models import SecureExecutionResult
from app.executor_secure.capability_mapping import CAPABILITY_RUNNERS
from app.executor_secure.registry import SecureRunnerRegistry
from app.executor_secure.runner_base import SecureRunner
from app.executor_secure.runtime import SecureExecutor
from app.integration.approval_signer import ApprovalGrantPolicy, ApprovalSignerBackend
from app.integration.capability import CapabilityVerifier
from app.integration.decision_adapter import DecisionDisposition, map_core_decision
from app.integration.evidence import ExecutorEvidenceSink
from app.integration.policy_verification import PolicyDecisionVerifier


FROZEN_EXECUTOR_COMMIT = "58f8cba93d7b632a46687ce81160f604a5cfa378"
_CONSTRAINT_KEYS = frozenset({"argument_equals", "allowed_targets", "max_content_bytes", "allowed_methods"})


def _canonical_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class ExecutorIntegrationService:
    """The only Portal/Core adapter allowed to reach SecureExecutor."""

    def __init__(
        self,
        *,
        execution_scope_id: str,
        registry: SecureRunnerRegistry,
        executor: SecureExecutor,
        approvals: ApprovalStore,
        policy_verifier: PolicyDecisionVerifier,
        capability_verifier: CapabilityVerifier,
        evidence_sink: ExecutorEvidenceSink,
        approval_signer: ApprovalSignerBackend | None = None,
        approval_policy: ApprovalGrantPolicy = ApprovalGrantPolicy(),
    ) -> None:
        self.execution_scope_id = execution_scope_id
        self.registry = registry
        self._executor = executor
        self.approvals = approvals
        self.policy_verifier = policy_verifier
        self.capability_verifier = capability_verifier
        self.evidence_sink = evidence_sink
        self.approval_signer = approval_signer
        self.approval_policy = approval_policy
        self._responses: dict[str, ExecutorServiceResponse] = {}
        self._secure_results: dict[str, tuple[SecureExecutionResult, SecureRunner]] = {}

    @staticmethod
    def _execution_id() -> str:
        return "exec_" + uuid4().hex

    @staticmethod
    def _runner_id(capability: str) -> str:
        try:
            return CAPABILITY_RUNNERS[capability]
        except KeyError as exc:
            raise ValueError("CAPABILITY_NOT_MAPPED") from exc

    def _runner_and_args(self, request: ExecutorServiceRequest) -> tuple[SecureRunner, dict[str, Any]]:
        runner = self.registry.get(self._runner_id(request.capability))
        precheck = runner.normalize_and_precheck(request.arguments)
        if not precheck.allowed:
            raise ValueError("RUNNER_PRECHECK_DENIED")
        if not runner.capability_precheck(request.capability, precheck.normalized_args):
            raise ValueError("RUNNER_CAPABILITY_MISMATCH")
        normalized_target = runner.approval_target(precheck.normalized_args)
        if normalized_target != request.target:
            raise ValueError("TARGET_BINDING_MISMATCH")
        return runner, precheck.normalized_args

    @staticmethod
    def _constraints_allow(request: ExecutorServiceRequest, args: dict[str, Any]) -> bool:
        constraints = request.authorization_decision.constraints
        if not constraints or not set(constraints).issubset(_CONSTRAINT_KEYS):
            return False
        equals = constraints.get("argument_equals", {})
        if not isinstance(equals, dict) or any(args.get(key) != value for key, value in equals.items()):
            return False
        targets = constraints.get("allowed_targets")
        if targets is not None and (not isinstance(targets, list) or request.target not in targets):
            return False
        max_bytes = constraints.get("max_content_bytes")
        if max_bytes is not None:
            if not isinstance(max_bytes, int) or max_bytes < 0 or len(str(args.get("content", "")).encode("utf-8")) > max_bytes:
                return False
        methods = constraints.get("allowed_methods")
        if methods is not None and (not isinstance(methods, list) or str(args.get("method", "")).upper() not in methods):
            return False
        return True

    def _response(
        self,
        request: ExecutorServiceRequest,
        execution_id: str,
        *,
        state: str,
        executed: bool = False,
        skipped: bool = True,
        approval_required: bool = False,
        approval_id: str | None = None,
        error_code: str | None = None,
        side_effect_summary: dict[str, Any] | None = None,
        pre_state_hash: str | None = None,
        post_state_hash: str | None = None,
        rollback_state: dict[str, Any] | None = None,
    ) -> ExecutorServiceResponse:
        response = ExecutorServiceResponse(
            execution_id=execution_id,
            session_id=request.session_id,
            execution_state=state,
            executed=executed,
            skipped=skipped,
            approval_required=approval_required,
            approval_id=approval_id,
            side_effect_summary=side_effect_summary or {},
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
            rollback_state=rollback_state or {"state": "NOT_REQUESTED"},
            error_code=error_code,
        )
        evidence_ref = self.evidence_sink.append(
            session_id=request.session_id,
            event={
                "execution_id": execution_id,
                "execution_state": response.execution_state,
                "executed": response.executed,
                "approval_id": approval_id,
                "capability": request.capability,
                "tool": request.tool,
                "target": request.target,
                "arguments_hash": _canonical_hash(request.arguments),
                "decision": request.authorization_decision.decision,
                "decision_version": request.authorization_decision.source_version,
                "action_origin": request.action_origin.model_dump(),
                "evidence_context_hash": _canonical_hash(request.evidence_context),
                "error_code": error_code,
                "frozen_executor_commit": FROZEN_EXECUTOR_COMMIT,
            },
        )
        response.evidence_refs.append(evidence_ref)
        self._responses[execution_id] = response
        return response

    def _verify_policy(self, request: ExecutorServiceRequest) -> bool:
        verification = self.policy_verifier.verify(request)
        return verification.verified

    def _verify_capability(self, request: ExecutorServiceRequest) -> bool:
        verification = self.capability_verifier.verify(
            session_id=request.session_id,
            capability=request.capability,
            tool=request.tool,
            target=request.target,
        )
        return verification.granted

    def create_approval_request(
        self,
        contract: ApprovalRequestCreate,
        *,
        runner_id: str,
        normalized_arguments: dict[str, Any],
    ) -> ApprovalRecord:
        return self.approvals.create(
            execution_id=self.execution_scope_id,
            session_id=contract.session_id,
            request=contract.model_dump(mode="json"),
            runner_id=runner_id,
            capability=contract.capability,
            tool=contract.tool,
            target=contract.target,
            args=normalized_arguments,
        )

    def approve(self, approval_id: str) -> ApprovalInspectResponse:
        if self.approval_signer is None:
            raise PermissionError("PRODUCTION_APPROVAL_SIGNER_NOT_CONFIGURED")
        record = self.approvals.get(approval_id)
        grant = self.approval_signer.issue(record.binding(), self.approval_policy)
        self.approvals.approve(approval_id, grant)
        return self.inspect_approval(approval_id)

    def reject(self, approval_id: str) -> ApprovalInspectResponse:
        if self.approval_signer is None:
            raise PermissionError("PRODUCTION_APPROVAL_SIGNER_NOT_CONFIGURED")
        identity = self.approval_signer.operator_identity()
        self.approvals.reject(
            approval_id,
            rejected_by=identity.created_by,
            trusted_origin=identity.trusted_origin,
        )
        return self.inspect_approval(approval_id)

    def validate_approval(self, approval_id: str) -> ApprovalValidationResponse:
        record = self.approvals.get(approval_id)
        verification = self.approvals.verify(approval_id)
        errors = list(verification["errors"])
        if record.expires_at is not None and datetime.fromisoformat(record.expires_at) <= datetime.now(timezone.utc):
            errors.append("approval_expired")
        if record.usage_limit and record.usage_count >= record.usage_limit:
            errors.append("usage_limit_exhausted")
        return ApprovalValidationResponse(
            approval_id=approval_id,
            valid=not errors,
            status=record.status,
            usage_count=record.usage_count,
            usage_limit=record.usage_limit,
            errors=errors,
        )

    def inspect_approval(self, approval_id: str) -> ApprovalInspectResponse:
        record = self.approvals.get(approval_id)
        verification = self.approvals.verify(approval_id)
        return ApprovalInspectResponse(
            approval_id=record.approval_id,
            execution_id=record.execution_id,
            session_id=record.session_id,
            status=record.status,
            capability=record.capability,
            tool=record.tool,
            target=record.target,
            arguments_hash=record.arguments_hash,
            once=record.once,
            usage_limit=record.usage_limit,
            usage_count=record.usage_count,
            expires_at=record.expires_at,
            created_by=record.created_by,
            trusted_origin=record.trusted_origin,
            trace_states=[event["event_type"] for event in record.events],
            valid=verification["valid"],
            validation_errors=verification["errors"],
        )

    def consume(
        self,
        approval_id: str,
        *,
        request: ExecutorServiceRequest,
        runner: SecureRunner,
        normalized_arguments: dict[str, Any],
    ) -> SecureExecutionResult:
        self.approvals.consume(
            approval_id,
            session_id=request.session_id,
            capability=request.capability,
            tool=request.tool,
            target=request.target,
            args=normalized_arguments,
        )
        result = self._executor.execute(
            execution_id=self.execution_scope_id,
            runner=runner,
            capability=request.capability,
            args=normalized_arguments,
        )
        self.approvals.attach_execution_result(approval_id, result.as_dict())
        return result

    def _executed_response(
        self,
        request: ExecutorServiceRequest,
        execution_id: str,
        result: SecureExecutionResult,
        runner: SecureRunner,
        *,
        resumed: bool,
    ) -> ExecutorServiceResponse:
        self._secure_results[execution_id] = (result, runner)
        return self._response(
            request,
            execution_id,
            state="FAILED" if result.error else ("RESUMED" if resumed else "EXECUTED"),
            executed=result.runner_invocation_count > 0,
            skipped=result.runner_invocation_count == 0,
            error_code="SECURE_EXECUTOR_ERROR" if result.error else None,
            side_effect_summary={
                "runner_id": result.runner_id,
                "runner_invocation_count": result.runner_invocation_count,
                "side_effect_count": result.side_effect_count,
                "output_fields": sorted(result.output),
                "trace_root_hash": result.trace_root_hash,
            },
            pre_state_hash=result.before_state,
            post_state_hash=result.after_state,
        )

    def execute(self, request: ExecutorServiceRequest) -> ExecutorServiceResponse:
        execution_id = self._execution_id()
        try:
            disposition: DecisionDisposition = map_core_decision(request.authorization_decision.decision)
        except ValueError:
            return self._response(request, execution_id, state="SKIPPED", error_code="UNSUPPORTED_DECISION")
        if not self._verify_policy(request):
            error = "UNTRUSTED_AUTHORIZATION_ORIGIN" if request.action_origin.authority != "policy_engine" else "POLICY_VERIFICATION_FAILED"
            return self._response(request, execution_id, state="SKIPPED", error_code=error)
        if not self._verify_capability(request):
            return self._response(request, execution_id, state="SKIPPED", error_code="CAPABILITY_NOT_GRANTED")
        try:
            runner, normalized_arguments = self._runner_and_args(request)
        except (KeyError, ValueError) as exc:
            return self._response(request, execution_id, state="SKIPPED", error_code=str(exc).strip("'"))
        if disposition.canonical == "QUARANTINE_AND_CONTINUE":
            return self._response(request, execution_id, state="CONTINUING")
        if disposition.canonical == "DENY_ACTION":
            return self._response(request, execution_id, state="SKIPPED", error_code="POLICY_DENIED")
        if disposition.terminate:
            return self._response(request, execution_id, state="TERMINATED", error_code="POLICY_TERMINATED")
        if disposition.constrained and not self._constraints_allow(request, normalized_arguments):
            return self._response(request, execution_id, state="SKIPPED", error_code="CONSTRAINTS_NOT_SATISFIED")
        if disposition.approval_required:
            if request.approval_reference is None:
                approval = self.create_approval_request(
                    ApprovalRequestCreate(
                        execution_id=execution_id,
                        session_id=request.session_id,
                        capability=request.capability,
                        tool=request.tool,
                        target=request.target,
                        arguments=normalized_arguments,
                        request_context={
                            "executor_contract_version": request.contract_version,
                            "authorization_decision": request.authorization_decision.model_dump(),
                            "action_origin": request.action_origin.model_dump(),
                            "evidence_context_hash": _canonical_hash(request.evidence_context),
                        },
                    ),
                    runner_id=runner.runner_id,
                    normalized_arguments=normalized_arguments,
                )
                return self._response(
                    request,
                    execution_id,
                    state="PAUSED",
                    approval_required=True,
                    approval_id=approval.approval_id,
                )
            try:
                result = self.consume(
                    request.approval_reference,
                    request=request,
                    runner=runner,
                    normalized_arguments=normalized_arguments,
                )
            except (KeyError, PermissionError, ValueError):
                return self._response(
                    request,
                    execution_id,
                    state="SKIPPED",
                    approval_required=True,
                    approval_id=request.approval_reference,
                    error_code="APPROVAL_INVALID",
                )
            return self._executed_response(request, execution_id, result, runner, resumed=True)
        result = self._executor.execute(
            execution_id=self.execution_scope_id,
            runner=runner,
            capability=request.capability,
            args=normalized_arguments,
        )
        return self._executed_response(request, execution_id, result, runner, resumed=False)

    def status(self, execution_id: str) -> ExecutorServiceResponse:
        try:
            return self._responses[execution_id]
        except KeyError as exc:
            raise KeyError(f"unknown integration execution: {execution_id}") from exc

    def session_trace(self, session_id: str) -> SessionExecutionTraceResponse:
        return SessionExecutionTraceResponse(session_id=session_id, events=self.evidence_sink.session_events(session_id=session_id))

    def rollback(self, execution_id: str) -> ExecutorServiceResponse:
        result, runner = self._secure_results[execution_id]
        rolled_back = self._executor.rollback(result, runner)
        previous = self._responses[execution_id]
        previous.execution_state = "ROLLED_BACK"
        previous.post_state_hash = rolled_back.after_state
        previous.rollback_state = rolled_back.rollback or {"state": "FAILED"}
        evidence_ref = self.evidence_sink.append(
            session_id=previous.session_id,
            event={
                "execution_id": execution_id,
                "execution_state": "ROLLED_BACK",
                "rollback_state": previous.rollback_state,
                "frozen_executor_commit": FROZEN_EXECUTOR_COMMIT,
            },
        )
        previous.evidence_refs.append(evidence_ref)
        return previous
