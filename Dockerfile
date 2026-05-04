FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for LDAP and cryptography
RUN apt-get update && apt-get install -y \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Environment variables
ENV PYTHONUNBUFFERED=1

EXPOSE 3007

# Run the application
CMD ["python", "backend/main.py"]
