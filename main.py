from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from config.settings import settings
from config.minio_config import minio_client
from config.redis_config import pool

import time
from routers import router_modules

from logs import setup_logging

setup_logging()

@asynccontextmanager
async def lifespan(app: FastAPI):
    
    if not minio_client.bucket_exists(settings.MINIO_BUCKET.lower().replace("_", "-")):
        minio_client.make_bucket(settings.MINIO_BUCKET.lower().replace("_", "-"))
        
    if not minio_client.bucket_exists(settings.MINIO_QUARANTINE_BUCKET.lower().replace("_", "-")):
        minio_client.make_bucket(settings.MINIO_QUARANTINE_BUCKET.lower().replace("_", "-"))
        
    yield
    
    
app = FastAPI(
    title= settings.PROJECT_NAME,
    description='NA',
    version = "0.1.0",
    docs_url='/docs' if settings.DEBUG else None,
    redoc_url='/redoc' if settings.DEBUG else None,
    contact={
        "name": "Praveen Allam",
        "email": "saipraveen.allam@copart.com"
    },
    debug= settings.DEBUG,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins = settings.BACKEND_CORS_ORIGINS,
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
)

@app.get("/health", tags=["Health Check"])
def health_check() -> dict:
    
    health_data = {"status" : "healthy", "minio_status": "unkown"}
    
    try:
        buckets = minio_client.list_buckets()
        health_data["minio_status"] = "healthy" if buckets else "unhealthy"
    except Exception as e:
        health_data["minio_status"] = "unhealthy"
    
    return health_data

for router_module in router_modules:
    app.include_router(router_module.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host = "0.0.0.0", port = 8000, reload = True)