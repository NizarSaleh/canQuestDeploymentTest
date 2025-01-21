FROM python:3.9-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir python-can
CMD ["python", "old_uds_server.py", "socketcan"]
