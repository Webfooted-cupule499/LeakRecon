# Use an official Python runtime as a parent image, matching type safety requirement (3.10+)
FROM python:3.11-slim

# Set environment variables to optimize Python execution within Docker
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
# We might need gcc for some Python packages like aiohttp_socks or sqlite headers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to leverage Docker cache
COPY requirements.txt /app/

# Install Python dependencies
# Adding aiohttp, aiohttp_socks, pydantic-settings explicitly in case they aren't in requirements.txt yet
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install aiohttp aiohttp_socks pydantic-settings pdfkit

# Copy the rest of the application codebase into the container
COPY . /app/

# Create a non-root user for security purposes
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app
USER appuser

# Define the command to run the application
CMD ["python", "main.py"]
