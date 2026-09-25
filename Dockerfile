FROM gcc:13 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --target dpi_web_analyzer -j2

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 ANALYZER_PATH=/app/build/dpi_web_analyzer MAX_UPLOAD_SIZE=209715200 HOST=0.0.0.0 PORT=8000
WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY --from=builder /src/build/dpi_web_analyzer ./build/dpi_web_analyzer
COPY backend ./backend
COPY frontend ./frontend
WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('PORT','8000')+'/api/health', timeout=2)"
CMD ["python", "-m", "app.run"]
