"""App factory — wires lifespan, middleware, and routes together.

This module must not contain business logic; it only assembles the application.
"""
import structlog

from fastapi import FastAPI

from app.core.config import settings
from app.core.lifespan import lifespan
from app.core.logging import configure_logging
from app.middleware.cors import add_cors_middleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.routes.v1 import router

# Configure logging before the app object is created
configure_logging(settings.log_level)

_log = structlog.get_logger(__name__)
_log.info("app.starting", name=settings.app_name, version=settings.app_version, environment=settings.environment)
_log.info("app.config", log_level=settings.log_level, model_version=settings.model_version, debug=settings.debug)
_log.info("app.database", status="configured")
_log.info("app.artifacts", directory=str(settings.artifact_dir))


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,  # artifact loading + DB pool in core/lifespan.py
    )

    # Middleware applied in reverse order (last added = outermost)
    add_cors_middleware(app)
    app.add_middleware(RateLimitMiddleware)

    app.include_router(router)
    return app


app = create_app()


if __name__ == "__main__":
    import os
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
