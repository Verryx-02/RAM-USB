#!/bin/bash

# Script to generate all necessary certificates for R.A.M.-U.S.B. system
# Generates CA certificate and separate certificates for each component:
# - Entry-Hub
# - Security-Switch  
# - Database-Vault
# - Storage-Service

# I leave here the meaning of the various openssl flags for convenience

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
echo "R.A.M.-U.S.B. Certificate Generation Script"
echo "============================================"
echo ""

# Create the certificates directory structure
echo "Creating certificate directory structure..."
mkdir -p ../certificates/{certification-authority,entry-hub,security-switch,database-vault,storage-service}

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
# SET CORRECT PERMISSIONS
# ===========================

# Set restrictive permissions on private keys
find . -name "*.key" -exec chmod 600 {} \;

# Set readable permissions on certificates
find . -name "*.crt" -exec chmod 644 {} \;

# Set readable permissions on CA serial file
chmod 644 certification-authority/ca.srl

# ===========================
# VERIFICATION AND SUMMARY
# ===========================
echo ""
echo "============================================"
echo "CERTIFICATE GENERATION COMPLETE!"
echo "============================================"