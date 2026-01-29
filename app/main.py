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

cicd_keywords = ['github', 'action', 'docker', 'workflow', 'yaml', 'yml']

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
    content = await file.read()
    try:
        sbom_data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="유효하지 않은 JSON 파일입니다.")

    # 1. 도구 이름 추출 (Syft 1.6 버전 대응)
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", {})
    tool_name = "Unknown"
    if isinstance(tools, dict):
        tool_components = tools.get("components", [])
        tool_name = tool_components[0].get("name", "Unknown") if tool_components else "Unknown"
    elif isinstance(tools, list) and len(tools) > 0:
        tool_name = tools[0].get("name", "Unknown")

    # 2. 패키지 분석 및 CI/CD 필터링 태그 부여
    cicd_keywords = ['github', 'action', 'docker', 'workflow', 'yaml', 'yml', '.github/']
    components = sbom_data.get("components", [])
    package_list = []
    
    for c in components:
        name = c.get("name", "Unknown")
        # 이름이나 경로에 CI/CD 키워드가 포함되었는지 확인
        is_cicd = any(key in name.lower() for key in cicd_keywords)
        
        # 라이선스 추출
        licenses = c.get("licenses", [])
        lic_name = "N/A"
        if licenses:
            lic_item = licenses[0]
            if "license" in lic_item:
                lic_name = lic_item["license"].get("id") or lic_item["license"].get("name", "N/A")
            elif "expression" in lic_item:
                lic_name = lic_item["expression"]

        package_list.append({
            "name": name,
            "version": c.get("version", "Unknown"),
            "license": lic_name,
            "is_cicd": is_cicd
        })

    analysis_result = {
        "filename": file.filename,
        "total_packages": len(components),
        "tool_name": tool_name,
        "package_list": package_list
    }

    return templates.TemplateResponse("analysis.html", {"request": request, "result": analysis_result})