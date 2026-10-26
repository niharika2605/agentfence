from fastapi import FastAPI

from agentfence.config import get_settings

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness: the process is running."""
    return {"status": "ok"}


@app.get("/readyz")
def readyz() -> dict[str, object]:
    """Readiness: the gateway can serve traffic.
    Later this will also check the database and policy engine.
    """
    return {"status": "ready", "fail_closed": settings.fail_closed}