FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY dashboard ./dashboard
COPY main.py ./main.py

EXPOSE 8010 8502

CMD ["python", "-m", "uvicorn", "backend.api.app:app", "--host", "0.0.0.0", "--port", "8010"]