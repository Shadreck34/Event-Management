# Dockerfile for Flask backend (production-ready using gunicorn)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# system deps for mysqlclient (if using mysqlclient). Uncomment if required
# RUN apt-get update && apt-get install -y build-essential default-libmysqlclient-dev gcc \
#     && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

EXPOSE 5000

# Use a production WSGI server
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
