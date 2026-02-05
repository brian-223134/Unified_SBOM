# Unified SBOM Integrator

Hatbom / Syft로 생성된 SBOM(JSON)을 업로드하면, 두 결과를 통합하여 CycloneDX 형식의 “통합 SBOM”을 생성하고 화면에서 요약/목록을 확인하거나 JSON으로 내려받을 수 있는 데모 웹 애플리케이션입니다.

## 주요 기능
- Hatbom + Syft SBOM 통합(components 중심) 및 통합 결과 JSON 생성
- 단일 SBOM(syft, hatbom) 업로드 분석 화면 제공
- 결과 화면에서 통계/요약 및 JSON 다운로드(attachment)

## 프로젝트 디렉토리 구조

아래는 핵심 디렉토리(app, data)와 주요 파일의 역할을 정리한 것입니다.

```
unified_sbom/
  app/
    main.py                  # FastAPI 엔트리포인트(웹 UI, 업로드/통합/분석 라우트)
    api/
      endpoints/
        sbom.py               # (현재 비어있음) 향후 API 라우터 분리용 자리
    models/                   # SBOM 모델 정의(원본 포맷 + 통합 포맷)
      hatbom_sbom.py
      syft_sbom.py
      unified_sbom.py         # UnifiedSbom(serial_number 기본 생성 포함)
    services/                 # 파싱/통합/내보내기 로직
      parse.py                # 업로드된 JSON -> 모델 변환, author 파싱 등
      integrate.py            # Hatbom/Syft 모델 -> UnifiedSbom 통합
      export.py               # UnifiedSbom -> CycloneDX JSON(dict) 변환/저장
    templates/                # Jinja2 템플릿(화면)
      index.html
      analysis.html
      unified_result.html
    static/                   # 정적 파일(CSS/JS 등)
    test/                     # 간단 테스트 스크립트(직접 실행 형태)
  data/
    *_hatbom_sbom.json        # 예시 Hatbom SBOM JSON
    *_syft_sbom.json          # 예시 Syft SBOM JSON
    *_unified_sbom.json       # 예시 통합 결과 JSON
  docker-compose.yml
  dockerfile
  pyproject.toml
```

## 화면 예시

### 초기 화면
<img width="1920" height="942" alt="image" src="https://github.com/user-attachments/assets/f6638230-666b-4dc6-9afd-eea67d296135" />

---

### 단일 SBOM 분석 화면 (syft, hatbom 지원)
<img width="1905" height="936" alt="image" src="https://github.com/user-attachments/assets/e543470e-c662-4575-9976-f7c07387e43e" />
<img width="1903" height="940" alt="image" src="https://github.com/user-attachments/assets/404976c7-14aa-409c-b3d7-b3729f64db70" />


### 통합 이후 화면
<img width="1534" height="937" alt="image" src="https://github.com/user-attachments/assets/0792026e-db9e-4bb0-b363-1891c40a5e93" />

---

## 사용 방법

### Docker로 실행
- Docker 실행 후, 아래 명령을 프로젝트 루트에서 실행합니다.
- Windows는 WSL2-Docker 연동 설정이 되어 있어야 정상 동작합니다.

```powershell
docker-compose up --build
```

브라우저에서 http://localhost:8000 으로 접속합니다.

---

## 테스트 방법
- 현재는 root directory에서 app/test/ 내 테스트 파일을 직접 실행/확인하는 형태입니다.




