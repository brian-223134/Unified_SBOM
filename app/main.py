from fastapi import FastAPI

app = FastAPI(title="Integrated SBOM Demo", version="0.1.0")

@app.get("/")
async def root():
    return {
        "message": "통합 SBOM 시연용 API 서버가 정상 작동 중입니다.",
        "manager": "uv",
        "python_version": "3.12"
    }

@app.get("/health")
async def health_check():
    return {"status": "ok"}