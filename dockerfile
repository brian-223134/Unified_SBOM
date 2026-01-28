# 1. uv 설치된 빌더 이미지 사용
FROM ghcr.io/astral-sh/uv:latest AS uv_setup

# 2. 실행용 파이썬 이미지
FROM python:3.12-slim

# 환경 변수 설정
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# uv 바이너리 복사
COPY --from=uv_setup /uv /uvx /bin/

WORKDIR /app

# 의존성 파일 먼저 복사 및 설치 (캐싱 활용)
COPY pyproject.toml uv.lock ./
RUN uv pip install --system --no-cache -r pyproject.toml

# 소스 코드 복사
COPY . .

# 포트 노출
EXPOSE 8000

# 서버 실행
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]