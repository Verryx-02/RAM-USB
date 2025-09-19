![banner](assets/banner.png)

---

**R.A.M.-U.S.B.** is a geo-distributed, Remotely Accessible Multi-User Backup Server written in **Go**, designed with **zero-knowledge security principles** in mind. 

This project was designed by [**Francesco Verrengia**](https://github.com/Verryx-02) and [**Riccardo Gottardi**](https://github.com/Riccardo-Gottardi).  
Implemented by [**Francesco Verrengia**](https://github.com/Verryx-02) with **Claude AI** as part of academic work in the field of IoT and cybersecurity.  
The use of AI assistance was intentional to significantly accelerate development time and provide a case study on the capabilities and limitations of this technology in the sensitive field of cybersecurity.

We set out to build a secure, distributed backup infrastructure that ensures **privacy, resilience, and remote accessibility**, with user data protection as our highest priority.

---

## Key Features

- **Zero-Knowledge Design** — All user data is encrypted client-side; even we cannot access your files.
- **Geo-Distributed Architecture** — The system can run across multiple physical nodes for redundancy and load balancing.
- **Smart Access Control** — Only authenticated users can access storage nodes, using strict SFTP policies.
- **Multi-User Support** — Each user has an isolated environment and encryption keys.
- **Remote Access** — Users can perform secure backups and restores from anywhere in the world.
- **Modern Cryptography** — Argon2id for email and password hashing, AES for encryption.

---

## System Architecture

The system is composed of several distributed components:

- **Entry-Hub**: Exposes an HTTPS REST API created by us for initial user authentication.
- **Security-Switch**: Manages secure communication and access control between services using mutual TLS.
- **Database-Vault**: Stores credentials and user metadata, encrypted and isolated.
- **Storage-Service**: Handles encrypted file storage and retrieval.
- **Tailscale Mesh VPN**: Ensures secure, private communication across nodes without opening any public ports.

All communication between components is secured with **mutual TLS (mTLS)**.

---

See the [documentation](documentation/registration_flow.md) for more

## Getting Started

> ⚠️ This project is under active development and not ready for production use.  

To test the registration process locally:

### Prerequisites

1. **Generate certificates:**
   ```bash
   cd scripts && ./generate_key.sh
   ```

2. **Connect to Tailscale private network:**
   ```bash
   # Install and connect to Tailscale
   tailscale up
   
   # Get your Tailscale IP address
   tailscale ip -4
   ```

3. **Configure Tailscale IP addresses:**
   
   Update the configuration files with your Tailscale IP address:
   
   **File: `entry-hub/config/config.go`**
   ```go
   // Replace with your Tailscale IP
   SecuritySwitchIP: "YOUR_TAILSCALE_IP:8444"
   ```
   
   **File: `security-switch/config/config.go`**
   ```go
   // Replace with your Tailscale IP  
   DatabaseVaultIP: "YOUR_TAILSCALE_IP:8445"
   ```
   
   **Example:**
   ```bash
   # If your Tailscale IP is 100.64.123.456
   SecuritySwitchIP: "100.64.123.456:8444"
   DatabaseVaultIP: "100.64.123.456:8445"
   ```

4. **Open 4 terminal tabs**

### Setup and Start Services (in order)

**TAB-1 (Database-Vault):**
```bash
cd database-vault
export RAMUSB_ENCRYPTION_KEY=$(openssl rand -hex 32)
go run .
```

**TAB-2 (Security-Switch):**
```bash
cd security-switch  
go run .
```

**TAB-3 (Entry-Hub):**
```bash
cd entry-hub
go run .
```

**TAB-4 (Test Client):**
```bash
cd user-client
go run .
```

### Expected Success Response
```json
{"success":true,"message":"User successfully registered!"}
```

⸻

Authors
	•	Francesco Verrengia
	•	Riccardo Gottardi

⸻

License: [MIT](LICENSE)

⸻

Acknowledgments

Special thanks to the University of Udine, in particular to Professor Ivan Scagnetto, for supporting our research and experimentation on secure and distributed systems.