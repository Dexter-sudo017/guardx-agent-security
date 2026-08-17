FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV GUARDX_SQLITE_PATH=data/audit.db

WORKDIR /app/prototype/guardx/backend

COPY prototype/guardx/backend/requirements-ci.txt ./requirements-ci.txt
RUN pip install --no-cache-dir -r requirements-ci.txt

COPY configs /app/configs
COPY prototype/guardx/backend /app/prototype/guardx/backend

EXPOSE 8014

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8014"]
