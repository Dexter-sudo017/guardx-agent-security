from fastapi import FastAPI, HTTPException, Request

from app.integration.executor_service import ExecutorIntegrationService


def configure_executor_integration(app: FastAPI, service: ExecutorIntegrationService) -> None:
    app.state.executor_integration_service = service


def executor_service(request: Request) -> ExecutorIntegrationService:
    service = getattr(request.app.state, "executor_integration_service", None)
    if not isinstance(service, ExecutorIntegrationService):
        raise HTTPException(status_code=503, detail="executor integration service is not configured")
    return service
