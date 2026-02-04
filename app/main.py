import json
from fastapi import FastAPI, Request, File, UploadFile, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path
from typing import Optional

from app.services.parse import SBOMParser
from app.services.integrate import SBOMIntegrator
from app.services.export import SBOMExporter
from app.models.hatbom_sbom import HatbomSbom
from app.models.syft_sbom import SyftSbom

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

cicd_keywords = ['github', 'action', 'docker', 'workflow', 'yaml', 'yml']

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/upload", response_class=HTMLResponse)
async def process_sboms(
    request: Request,
    hatbom_file: UploadFile = File(...), 
    syft_file: UploadFile = File(...)
):
    """
    Hatbom과 Syft SBOM 파일을 업로드하여 통합된 SBOM을 생성하고 결과 페이지를 렌더링합니다.
    """
    try:
        # 1. 파일 내용 읽기
        hatbom_content = await hatbom_file.read()
        syft_content = await syft_file.read()
        
        # 2. JSON 파싱
        try:
            hatbom_data = json.loads(hatbom_content)
            syft_data = json.loads(syft_content)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"유효하지 않은 JSON 파일입니다: {str(e)}")
        
        # 3. SBOM 객체로 변환
        hatbom_sbom = HatbomSbom.from_json(hatbom_data)
        syft_sbom = SyftSbom.from_json(syft_data)
        
        # 4. SBOM 통합
        integrator = SBOMIntegrator()
        unified_sbom = integrator.integrate(hatbom_sbom, syft_sbom)
        
        # 5. Export
        exporter = SBOMExporter(unified_sbom)
        summary = exporter.get_summary()
        unified_dict = exporter.to_dict()
        
        # 6. 템플릿용 컴포넌트 데이터 가공
        components_for_template = []
        for comp in unified_dict.get("components", []):
            # 출처 확인
            source = "Unknown"
            integrated = False
            for prop in comp.get("properties", []):
                if prop.get("name") == "source_tool":
                    source = prop.get("value", "Unknown")
                if prop.get("name") == "integrated_with":
                    integrated = True
            
            # 라이선스 추출
            license_name = "N/A"
            licenses = comp.get("licenses", [])
            if licenses:
                lic = licenses[0].get("license", {})
                license_name = lic.get("id") or lic.get("name") or "N/A"
            
            # Authors 추출
            authors_str = ""
            authors = comp.get("authors", [])
            if authors:
                author_names = [a.get("name") or a.get("email") or "" for a in authors[:2]]
                authors_str = ", ".join(filter(None, author_names))
                if len(authors) > 2:
                    authors_str += f" 외 {len(authors) - 2}명"
            
            components_for_template.append({
                "name": comp.get("name", "Unknown"),
                "version": comp.get("version", "Unknown"),
                "type": comp.get("type", "Unknown"),
                "license": license_name,
                "source": source,
                "integrated": integrated,
                "authors": authors_str
            })
        
        return templates.TemplateResponse("unified_result.html", {
            "request": request,
            "summary": summary,
            "components": components_for_template,
            "dependencies": unified_dict.get("dependencies", []),
            "unified_sbom_json": json.dumps(unified_dict, indent=2, ensure_ascii=False),
            "filename": exporter.get_filename()
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SBOM 통합 중 오류가 발생했습니다: {str(e)}")


@app.post("/integrate")
async def integrate_sboms(
    hatbom_file: UploadFile = File(...), 
    syft_file: UploadFile = File(...)
):
    """
    Hatbom과 Syft SBOM 파일을 통합하고 통합된 SBOM만 반환합니다.
    (다운로드용 - 순수 CycloneDX JSON)
    """
    try:
        hatbom_content = await hatbom_file.read()
        syft_content = await syft_file.read()
        
        hatbom_data = json.loads(hatbom_content)
        syft_data = json.loads(syft_content)
        
        hatbom_sbom = HatbomSbom.from_json(hatbom_data)
        syft_sbom = SyftSbom.from_json(syft_data)
        
        integrator = SBOMIntegrator()
        unified_sbom = integrator.integrate(hatbom_sbom, syft_sbom)
        
        exporter = SBOMExporter(unified_sbom)
        filename = exporter.get_filename()
        
        return JSONResponse(
            content=exporter.to_dict(),
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"유효하지 않은 JSON 파일입니다: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SBOM 통합 중 오류가 발생했습니다: {str(e)}")


@app.post("/summary")
async def get_integration_summary(
    hatbom_file: UploadFile = File(...), 
    syft_file: UploadFile = File(...)
):
    """
    SBOM 통합 후 요약 정보만 반환합니다.
    """
    try:
        hatbom_content = await hatbom_file.read()
        syft_content = await syft_file.read()
        
        hatbom_data = json.loads(hatbom_content)
        syft_data = json.loads(syft_content)
        
        hatbom_sbom = HatbomSbom.from_json(hatbom_data)
        syft_sbom = SyftSbom.from_json(syft_data)
        
        integrator = SBOMIntegrator()
        unified_sbom = integrator.integrate(hatbom_sbom, syft_sbom)
        
        exporter = SBOMExporter(unified_sbom)
        
        return {
            "status": "success",
            "summary": exporter.get_summary(),
            "received_files": {
                "hatbom": hatbom_file.filename,
                "syft": syft_file.filename
            }
        }
        
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"유효하지 않은 JSON 파일입니다: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SBOM 통합 중 오류가 발생했습니다: {str(e)}")

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