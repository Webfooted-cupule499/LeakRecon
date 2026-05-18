# Use an official Python runtime as a parent image, matching type safety requirement (3.10+)
FROM python:3.11-slim

# Set environment variables to optimize Python execution within Docker
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Set the working directory in the container
WORKDIR /app

# Install system dependencies including wkhtmltopdf for enterprise PDF reporting
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    wkhtmltopdf \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to leverage Docker cache
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the rest of the application codebase into the container
COPY . /app/

# Create a non-root user for security purposes
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app
USER appuser

# Define the command to run the application
CMD ["python", "main.py"]
