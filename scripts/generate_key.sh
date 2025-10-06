#!/bin/bash

# Script to generate all necessary certificates for RAM-USB system
# Generates CA certificate and separate certificates for each component:

# - Entry-Hub
# - Security-Switch  
# - Database-Vault
# - Storage-Service
# - User-Client

# Below, the meaning of the various openssl flags for convenience

# -in               : Input file
# -out              : Output file (where to save keys, certificates, etc.)
# -new              : Create a new certificate request
# -x509             : Generate an X.509 certificate
# -days             : Validity period of the certificate
# -key              : Private key file to use for signing or generation
# -subj             : Specifies the Distinguished Name (DN) of the certificate inline, without interactive prompt
# -req              : Indicates that you are working on a certificate request (CSR)
# -CA               : Certificate Authority (CA) file used for signing
# -CAkey            : Private key file of the CA used for signing
# -CAcreateserial   : Creates a new serial file for the CA if it does not exist (needed for signing multiple certificates)
# -extfile          : Specifies the path to the configuration file from which to read the section indicated by -extensions
# -extensions       : Name of the extensions section to apply to the certificate
    # [V3_req] is the section that contains extensions:
    # Keyusage: for what the key can be used (data encryption).
    # Extendedkeyusage: more specific uses (Serverauth for https).
    # Subjectname: List of alternative hosts valid for the certificate (Localhost, 127.0.0.1, ...).

set -e  # Exit if any command fails

echo "============================================"
echo "RAM-USB Certificate Generation Script"
echo "============================================"
echo ""

# Create the certificates directory structure
echo "Creating certificate directory structure..."
mkdir -p ../certificates/{certification-authority,entry-hub,security-switch,database-vault,storage-service,postgresql}
mkdir -p ../certificates/{metrics-collector,mqtt-broker,timescaledb}


# Change to certificates directory
cd ../certificates

echo "Working directory: $(pwd)"
echo ""
# ===========================
# CERTIFICATION AUTHORITY (CA)
# ===========================
cd certification-authority

# Generate CA private key
# This key will be used to sign all certificates in the system
openssl genrsa \
  -out ca.key 4096

# Generate the self-signed CA certificate
# This certificate will be distributed to all components to verify other certificates
openssl req \
  -new \
  -x509 \
  -days 365 \
  -key ca.key \
  -out ca.crt \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=RAMUSB-CA/CN=RAMUSB Development CA"

cd ..

# ===========================
# ENTRY-HUB CERTIFICATES
# ===========================
cd entry-hub

# Generate Entry-Hub server private key
# Used by Entry-Hub to secure HTTPS connections from clients
openssl genrsa \
  -out server.key 4096

# Generate Entry-Hub server Certificate Signing Request (CSR)
openssl req \
  -new \
  -key server.key \
  -out server.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=EntryHub/CN=entry-hub"

# Create configuration file for Entry-Hub server certificate with SAN
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = IT
ST = Friuli-Venezia Giulia
L = Udine
O = EntryHub
CN = entry-hub

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = entry-hub
DNS.2 = localhost
DNS.3 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate Entry-Hub server certificate signed by CA
openssl x509 \
  -req \
  -in server.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile server.conf

# Generate Entry-Hub client private key
# Used by Entry-Hub when connecting to Security-Switch as a client
openssl genrsa \
  -out client.key 4096

# Generate Entry-Hub client CSR
openssl req \
  -new \
  -key client.key \
  -out client.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=EntryHub/CN=entry-hub-client"

# Generate Entry-Hub client certificate signed by CA
openssl x509 \
  -req \
  -in client.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 365

# Clean up temporary files
rm -f server.csr client.csr server.conf

cd ..

# ===========================
# SECURITY-SWITCH CERTIFICATES
# ===========================
cd security-switch

# Generate Security-Switch server private key
# Used by Security-Switch to accept mTLS connections from Entry-Hub
openssl genrsa \
  -out server.key 4096

# Generate Security-Switch server CSR
openssl req \
  -new \
  -key server.key \
  -out server.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=SecuritySwitch/CN=security-switch"

# Create configuration file for Security-Switch server certificate
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = IT
ST = Friuli-Venezia Giulia
L = Udine
O = SecuritySwitch
CN = security-switch

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = security-switch
DNS.2 = localhost
EOF

# Generate Security-Switch server certificate signed by CA
openssl x509 \
  -req \
  -in server.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile server.conf

# Generate Security-Switch client private key
# Used by Security-Switch when connecting to Database-Vault as a client
openssl genrsa \
  -out client.key 4096

# Generate Security-Switch client CSR
openssl req \
  -new \
  -key client.key \
  -out client.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=SecuritySwitch/CN=security-switch-client"

# Generate Security-Switch client certificate signed by CA
openssl x509 \
  -req \
  -in client.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 365

# Clean up temporary files
rm -f server.csr client.csr server.conf

cd ..

# ===========================
# DATABASE-VAULT CERTIFICATES
# ===========================
cd database-vault

# Generate Database-Vault server private key
# Used by Database-Vault to accept mTLS connections from Security-Switch
openssl genrsa \
  -out server.key 4096

# Generate Database-Vault server CSR
openssl req \
  -new \
  -key server.key \
  -out server.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=DatabaseVault/CN=database-vault"

# Create configuration file for Database-Vault server certificate
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = IT
ST = Friuli-Venezia Giulia
L = Udine
O = DatabaseVault
CN = database-vault

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = database-vault
DNS.2 = localhost
EOF

# Generate Database-Vault server certificate signed by CA
openssl x509 \
  -req \
  -in server.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile server.conf

# Generate Database-Vault client private key
# Used by Database-Vault when connecting to Storage-Service as a client
openssl genrsa \
  -out client.key 4096

# Generate Database-Vault client CSR
openssl req \
  -new \
  -key client.key \
  -out client.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=DatabaseVault/CN=database-vault-client"

# Generate Database-Vault client certificate signed by CA
openssl x509 \
  -req \
  -in client.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 365

# Clean up temporary files
rm -f server.csr client.csr server.conf

cd ..

# ===========================
# STORAGE-SERVICE CERTIFICATES
# ===========================
cd storage-service

# Generate Storage-Service server private key
# Used by Storage-Service to accept connections for file storage
openssl genrsa \
  -out server.key 4096

# Generate Storage-Service server CSR
openssl req \
  -new \
  -key server.key \
  -out server.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=StorageService/CN=storage-service"

# Create configuration file for Storage-Service server certificate
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = IT
ST = Friuli-Venezia Giulia
L = Udine
O = StorageService
CN = storage-service

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = storage-service
DNS.2 = localhost
EOF

# Generate Storage-Service server certificate signed by CA
openssl x509 \
  -req \
  -in server.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile server.conf

# Generate Storage-Service client private key
openssl genrsa \
  -out client.key 4096

# Generate Storage-Service client CSR
openssl req \
  -new \
  -key client.key \
  -out client.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=StorageService/CN=storage-service-client"

# Generate Storage-Service client certificate signed by CA
openssl x509 \
  -req \
  -in client.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 365

# Clean up temporary files
rm -f server.csr client.csr server.conf
cd ..

# ===========================
# POSTGRESQL CERTIFICATES
# ===========================
cd postgresql

# Generate PostgreSQL server private key
# Used by PostgreSQL server for SSL/TLS connections
openssl genrsa \
  -out server.key 4096

# Generate PostgreSQL server CSR
openssl req \
  -new \
  -key server.key \
  -out server.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=PostgreSQL/CN=postgresql-server"

# Create configuration file for PostgreSQL server certificate
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = IT
ST = Friuli-Venezia Giulia
L = Udine
O = PostgreSQL
CN = postgresql-server

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = postgresql-server
DNS.2 = localhost
DNS.3 = postgres
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate PostgreSQL server certificate signed by CA
openssl x509 \
  -req \
  -in server.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile server.conf

# Clean up temporary files
rm -f server.csr server.conf

# PostgreSQL requires specific permissions for SSL files
chmod 600 server.key
chmod 644 server.crt

echo "PostgreSQL SSL certificates generated:"
echo "  Server cert: server.crt"
echo "  Server key:  server.key (permissions: 600)"

cd ..

# ===========================
# MQTT PUBLISHER CERTIFICATES 
# ===========================
echo "Generating MQTT Publisher certificates for all services..."

# Entry-Hub MQTT Publisher
cd entry-hub

openssl genrsa -out mqtt-publisher.key 4096
openssl req -new -key mqtt-publisher.key -out mqtt-publisher.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=EntryHubPublisher/CN=entry-hub-mqtt-publisher"
openssl x509 -req -in mqtt-publisher.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial -out mqtt-publisher.crt -days 365
rm mqtt-publisher.csr

# Security-Switch MQTT Publisher  
cd ../security-switch
openssl genrsa -out mqtt-publisher.key 4096
openssl req -new -key mqtt-publisher.key -out mqtt-publisher.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=SecuritySwitchPublisher/CN=security-switch-mqtt-publisher"
openssl x509 -req -in mqtt-publisher.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial -out mqtt-publisher.crt -days 365
rm mqtt-publisher.csr

# Database-Vault MQTT Publisher
cd ../database-vault
openssl genrsa -out mqtt-publisher.key 4096
openssl req -new -key mqtt-publisher.key -out mqtt-publisher.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=DatabaseVaultPublisher/CN=database-vault-mqtt-publisher"
openssl x509 -req -in mqtt-publisher.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial -out mqtt-publisher.crt -days 365
rm mqtt-publisher.csr

# ===========================
# METRICS-COLLECTOR CERTIFICATES
# ===========================
cd ../metrics-collector

# Server certificates for accepting mTLS connections
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=MetricsCollector/CN=metrics-collector"

# Create configuration file for Metrics-Collector server certificate
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = IT
ST = Friuli-Venezia Giulia
L = Udine
O = MetricsCollector
CN = metrics-collector

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = metrics-collector
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate Metrics-Collector server certificate signed by CA
openssl x509 -req -in server.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial -out server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile server.conf

# Client certificate for subscribing to MQTT
openssl genrsa -out mqtt-subscriber.key 4096
openssl req -new -key mqtt-subscriber.key -out mqtt-subscriber.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=MetricsCollectorSubscriber/CN=metrics-collector-subscriber"
openssl x509 -req -in mqtt-subscriber.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial -out mqtt-subscriber.crt -days 365

# Clean up temporary files
rm -f server.csr mqtt-subscriber.csr server.conf

# ===========================
# MQTT-BROKER CERTIFICATES
# ===========================
cd ../mqtt-broker

# Detect Tailscale IP automatically
TAILSCALE_IP=""
if command -v tailscale >/dev/null 2>&1; then
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null)
    if [ $? -eq 0 ] && [ ! -z "$TAILSCALE_IP" ]; then
        echo "Detected Tailscale IP: $TAILSCALE_IP"
    else
        echo "Warning: Could not detect Tailscale IP automatically"
        TAILSCALE_IP=""
    fi
else
    echo "Warning: Tailscale not found, MQTT broker will only work on localhost"
fi

openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=MQTTBroker/CN=mqtt-broker"

# Create configuration file for MQTT Broker server certificate with SAN
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = IT
ST = Friuli-Venezia Giulia
L = Udine
O = MQTTBroker
CN = mqtt-broker

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = mqtt-broker
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Add Tailscale IP to SAN if detected
if [ ! -z "$TAILSCALE_IP" ]; then
    echo "IP.3 = $TAILSCALE_IP" >> server.conf
fi

# Generate MQTT Broker server certificate signed by CA
openssl x509 -req -in server.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extensions v3_req -extfile server.conf

# Clean up temporary files
rm -f server.csr server.conf

# ===========================
# TIMESCALEDB CERTIFICATES
# ===========================
cd ../timescaledb

# Server certificates for SSL connections to TimescaleDB instance
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
  -subj "/C=IT/ST=Friuli-Venezia Giulia/L=Udine/O=TimescaleDB/CN=timescaledb-server"

# Create configuration file for TimescaleDB server certificate  
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = IT
ST = Friuli-Venezia Giulia  
L = Udine
O = TimescaleDB
CN = timescaledb-server

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = timescaledb-server
DNS.2 = localhost
DNS.3 = postgres
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate TimescaleDB server certificate signed by CA
openssl x509 -req -in server.csr \
  -CA ../certification-authority/ca.crt \
  -CAkey ../certification-authority/ca.key \
  -CAcreateserial -out server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile server.conf

# Clean up temporary files
rm -f server.csr server.conf

# Set correct permissions for PostgreSQL/TimescaleDB
chmod 600 server.key
chmod 644 server.crt

echo "TimescaleDB SSL certificates generated:"
echo "  Server cert: server.crt"  
echo "  Server key:  server.key (permissions: 600)"

# ===========================
# USER-CLIENT SSH KEYS
# ===========================
cd ../../user-client

# Create keys directory if it doesn't exist
mkdir -p keys

# Generate SSH key pair for user-client
# Private key for future SFTP connections to Storage-Service
# Public key for user registration payload
ssh-keygen -t ed25519 \
  -f keys/ssh_private_key \
  -C "user-client@ramusb.local" \
  -N ""

# Rename public key to match expected naming
mv keys/ssh_private_key.pub keys/ssh_public_key.pub

# Set correct permissions for SSH keys
chmod 600 keys/ssh_private_key
chmod 644 keys/ssh_public_key.pub

echo "SSH keys generated for user-client:"
echo "  Private: keys/ssh_private_key"
echo "  Public:  keys/ssh_public_key.pub"

cd ..

# ===========================
# SET CORRECT PERMISSIONS
# ===========================

# Set restrictive permissions on private keys
find . -name "*.key" -exec chmod 600 {} \;

# Set readable permissions on certificates
find . -name "*.crt" -exec chmod 644 {} \;

# Set readable permissions on CA serial file
cd certificates/
chmod 644 certification-authority/ca.srl

# ===========================
# VERIFICATION AND SUMMARY
# ===========================
echo ""
echo "============================================"
echo "CERTIFICATE GENERATION COMPLETE!"
echo "============================================"