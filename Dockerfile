# -------------------------------
# Base image
# -------------------------------
FROM python:3.10-slim

# -------------------------------
# Environment variables
# -------------------------------
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# -------------------------------
# Working directory
# -------------------------------
WORKDIR /my_app

# -------------------------------
# Install OS dependencies
# -------------------------------
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# -------------------------------
# Copy dependency file
# -------------------------------
COPY requirements.txt /my_app/

# -------------------------------
# Install Python dependencies
# -------------------------------
RUN pip install --no-cache-dir -r requirements.txt

# -------------------------------
# Copy ALL application files
# -------------------------------
COPY . /my_app/

# -------------------------------
# Default run command
# -------------------------------
CMD ["python", "main.py"]
