FROM python:3.11-slim

WORKDIR /app

COPY requirements-runtime.txt .
RUN pip install -r requirements-runtime.txt

COPY app.py .
COPY schema.sql .

EXPOSE 5000

CMD ["python", "app.py"]
