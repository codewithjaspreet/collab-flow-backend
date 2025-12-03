from fastapi import FastAPI
from auth_service.api.routes.auth import router as auth_router

def get_application() -> FastAPI:
    app = FastAPI(
        title="Auth Service",
        version="1.0.0",
        description="Handles registration, login, JWT authentication, and user profile.",
    )

    # Include authentication routes
    app.include_router(auth_router)

    # Health Check
    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    return app


app = get_application()
