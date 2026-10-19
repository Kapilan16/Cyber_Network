FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt constraints-cpu.txt ./
RUN pip install --no-cache-dir \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    --constraint constraints-cpu.txt \
    -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY scripts ./scripts
COPY alembic.ini .

EXPOSE 8100

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8100"]
