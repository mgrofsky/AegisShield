# Specify the base image
FROM python:3.13-slim

# Install system dependencies for PDF generation (Cairo/Pango for xhtml2pdf)
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-dev \
    libffi-dev \
    pkg-config \
    shared-mime-info \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 8501 available to the world outside this container
EXPOSE 8501

# Test if the container is listening on port 8501
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# Configure the container to run as an executable
ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]