from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.analyze import router as analyze_router


app = FastAPI(
    title="TrustTrace AI API",
    description="Local MVP API for explainable browser security analysis.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(analyze_router, prefix="/api", tags=["analysis"])
