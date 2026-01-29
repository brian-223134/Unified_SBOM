import json
from fastapi import FastAPI, Request, File, UploadFile, HTTPException
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


@app.post("/analyze-single", response_class=HTMLResponse)
async def analyze_single_sbom(request: Request, file: UploadFile = File(...)):
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="JSON 파일만 업로드 가능합니다.")

    content = await file.read()
    try:
        sbom_data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="유효한 JSON 형식이 아닙니다.")

    # --- 안전한 도구 이름(tool_name) 추출 로직 ---
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", {})
    tool_name = "Unknown"

    if isinstance(tools, list) and len(tools) > 0:
        # 구버전 CycloneDX (리스트 형태)
        tool_name = tools[0].get("name", "Unknown")
    elif isinstance(tools, dict):
        # 신버전 CycloneDX (객체 형태: components나 services 안에 도구 정보 포함)
        tool_components = tools.get("components", [])
        if tool_components:
            tool_name = tool_components[0].get("name", "Unknown")
        else:
            # metadata.tools 자체가 직접 정보를 담고 있는 경우 대비
            tool_name = tools.get("name", "Unknown")

    # --- 패키지 목록 추출 ---
    components = sbom_data.get("components", [])
    package_list = []
    
    for c in components:
        # 라이선스 정보 추출 (안전하게)
        licenses = c.get("licenses", [])
        lic_name = "N/A"
        if licenses:
            # license 객체 혹은 expression 확인
            lic_item = licenses[0]
            if "license" in lic_item:
                lic_name = lic_item["license"].get("id") or lic_item["license"].get("name", "N/A")
            elif "expression" in lic_item:
                lic_name = lic_item["expression"]

        package_list.append({
            "name": c.get("name", "Unknown"),
            "version": c.get("version", "Unknown"),
            "license": lic_name
        })

    analysis_result = {
        "filename": file.filename,
        "total_packages": len(components),
        "tool_name": tool_name,
        "package_list": package_list[:50]  # 상위 50개까지만 표시
    }

    return templates.TemplateResponse("analysis.html", {
        "request": request, 
        "result": analysis_result
    })