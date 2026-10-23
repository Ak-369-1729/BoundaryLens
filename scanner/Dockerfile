# Multi-stage: build the React dashboard, then serve it from the Python backend.
FROM node:22-slim AS frontend
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    BL_FRONTEND_DIST=/app/frontend_dist \
    BL_DATABASE_URL=sqlite:////data/boundarylens.db \
    BL_HOST=0.0.0.0 BL_PORT=8080 \
    BL_MANIFEST=/app/manifests/ledgerly.yaml

COPY scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner/boundarylens ./boundarylens
COPY manifests ./manifests
COPY --from=frontend /ui/dist ./frontend_dist

RUN mkdir -p /data
EXPOSE 8080
CMD ["uvicorn", "boundarylens.app:app", "--host", "0.0.0.0", "--port", "8080"]
