from fastapi import FastAPI, Request, File, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pathlib import Path

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/upload")
async def process_sboms(
    hatbom_file: UploadFile = File(...), 
    syft_file: UploadFile = File(...)
):
    # 실제 분석 로직이 들어갈 자리입니다.
    # 우선은 파일이 잘 들어왔는지 확인하는 정보를 반환합니다.
    
    return {
        "status": "success",
        "received_files": {
            "hatbom": {
                "filename": hatbom_file.filename,
                "content_type": hatbom_file.content_type
            },
            "syft": {
                "filename": syft_file.filename,
                "content_type": syft_file.content_type
            }
        },
        "message": "두 개의 SBOM 파일을 성공적으로 수신했습니다. 통합 분석을 시작합니다."
    }

@app.get("/health")
async def health_check():
    return {"status": "ok"}