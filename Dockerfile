FROM python:3.11

WORKDIR /app

# Install system dependencies for LDAP and cryptography
RUN apt-get update && apt-get install -y \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Enable OpenSSL legacy provider for NTLM (MD4) support
RUN sed -i 's/default = default_sect/default = default_sect\nlegacy = legacy_sect/' /etc/ssl/openssl.cnf && \
    sed -i 's/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[legacy_sect\]\nactivate = 1/' /etc/ssl/openssl.cnf

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
