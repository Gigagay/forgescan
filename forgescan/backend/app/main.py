# backend/app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import uuid
from datetime import datetime
import inspect
import asyncio
import functools

from app.core.config import settings
from app.core.logging import logger
# Ensure core shims and compatibility layers are loaded early
from app.db.database import init_db, close_db
from app.scanners.plugin_manager import PluginManager
from app.api.v1.router import api_router
from app.api.v1 import websocket
from app.core.audit_log import AuditLogger, AuditEventType




@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting ForgeScan API")
    await init_db()
    
    # Initialize plugin manager
    plugin_manager = PluginManager()
    await plugin_manager.initialize()
    app.state.plugin_manager = plugin_manager
    
    yield
    
    # Shutdown
    logger.info("Shutting down ForgeScan API")
    await plugin_manager.cleanup_all()
    await close_db()


app = FastAPI(
    title="ForgeScan API",
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=("/api/docs" if settings.ENVIRONMENT == "development" else None),
    redoc_url=("/api/redoc" if settings.ENVIRONMENT == "development" else None),
    lifespan=lifespan
)

# Normalize CORS origins config (accept list or comma-separated string)
_origins = settings.BACKEND_CORS_ORIGINS
if isinstance(_origins, str):
    BACKEND_CORS_ORIGINS = [o.strip() for o in _origins.split(",") if o.strip()]
else:
    BACKEND_CORS_ORIGINS = list(_origins or [])

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in BACKEND_CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Include routers
app.include_router(api_router, prefix=settings.API_V1_STR)
# Websocket routes
app.include_router(websocket.router, prefix=settings.API_V1_STR, tags=["websocket"])

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.exception("Unhandled exception while handling request", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )

@app.middleware("http")
async def audit_log_request_middleware(request: Request, call_next):
    """Automatically log all API requests but avoid blocking or crashing the request flow"""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    start_time = datetime.utcnow()
    # execute request
    response = await call_next(request)
    duration = (datetime.utcnow() - start_time).total_seconds()

    user = getattr(request.state, "user", None)
    ip_address = request.client.host if getattr(request, "client", None) else None

    try:
        audit_logger = AuditLogger()
        kwargs = dict(
            event_type=AuditEventType.API_REQUEST,
            user_id=user.id if user else None,
            tenant_id=user.tenant_id if user else None,
            details={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration * 1000
            },
            ip_address=ip_address,
            user_agent=request.headers.get("user-agent"),
            request_id=request_id
        )

        if inspect.iscoroutinefunction(audit_logger.log_event):
            # async implementation
            await asyncio.wait_for(audit_logger.log_event(**kwargs), timeout=2.0)
        else:
            # run sync implementation in threadpool with a short timeout
            loop = asyncio.get_running_loop()
            fut = loop.run_in_executor(None, functools.partial(audit_logger.log_event, **kwargs))
            await asyncio.wait_for(fut, timeout=2.0)
    except asyncio.TimeoutError:
        logger.warning("Audit logging timed out (ignored)")
    except Exception:
        logger.exception("Failed to write audit log (ignored)")

    return response
