// simple-client/README.md
# Simple Registration Client

A lightweight Go client for testing R.A.M.-U.S.B. user registration.

## Setup

1. Generate SSH key pair:
```bash
ssh-keygen -t ed25519 -f keys/ssh_private_key -C "test@example.com"
# This creates:
# - keys/ssh_private_key (private key)
# - keys/ssh_private_key.pub (public key)
```

2. Rename public key:
```bash
mv keys/ssh_private_key.pub keys/ssh_public_key.pub
```

## Usage

Make sure Entry-Hub, Security-Switch, and Database-Vault are running, then:

```bash
go run .
```

## Configuration

Edit `registration/registration.go` to modify:
- `TestEmail` - User email for registration
- `TestPassword` - User password for registration  
- `EntryHubURL` - Entry-Hub endpoint URL
- `SSHKeyPath` - SSH public key file path

## Expected Output

```
R.A.M.-U.S.B. Simple Registration Client
========================================
Starting user registration process...
Reading SSH public key from: keys/ssh_public_key.pub
SSH public key loaded: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOelEOPQ...
Sending registration request to: https://localhost:8443/api/register
Registration data: email=test@example.com, password=*****, ssh_key=ssh-ed25519 AAAAC3NzaC1lZDI1...
HTTP Status: 201 Created
Response: {"success":true,"message":"User successfully registered!"}
Registration successful: User successfully registered!
Registration process completed successfully!
```