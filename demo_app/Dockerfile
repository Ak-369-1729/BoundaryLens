FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ledgerly ./ledgerly

EXPOSE 8000
# LEDGERLY_MODE (vulnerable|fixed) selects the configuration at container start.
CMD ["uvicorn", "ledgerly.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
