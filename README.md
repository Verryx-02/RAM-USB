![banner](assets/banner.png)

---

**RAM-USB** is a geo-distributed, Remotely Accessible Multi-User Backup Server written in **Go**, designed with **zero-knowledge security principles** in mind. 

This project was designed by [**Francesco Verrengia**](https://github.com/Verryx-02) and [**Riccardo Gottardi**](https://github.com/Riccardo-Gottardi).  
Implemented by [**Francesco Verrengia**](https://github.com/Verryx-02) with [**Claude AI**](https://en.wikipedia.org/wiki/Claude_(language_model)) as part of academic work in the field of IoT and cybersecurity.  
The use of AI assistance was intentional to significantly accelerate development time and provide a case study on the capabilities and limitations of this technology in the sensitive field of cybersecurity.

We set out to build a secure, distributed backup infrastructure that ensures **privacy, resilience, and remote accessibility**, with user data protection as our highest priority.

---

## Key Features

- **Zero-Knowledge Design**: All user data is encrypted client-side; even we cannot access your files.
- **Geo-Distributed Architecture**: The system can run across multiple physical nodes for redundancy and load balancing.
- **Smart Access Control**: Only authenticated users can access storage nodes, using strict SFTP policies.
- **Multi-User Support**: Each user has an isolated environment and encryption keys.
- **Remote Access**: Users can perform secure backups and restores from anywhere in the world.
- **Modern Cryptography**: Argon2id for email and password hashing, AES for encryption.
- **Zero-Knowledge Metrics System**: Using MQTT over TLS, TimescaleDB and Grafana 

---

## System Architecture

The system is composed of several distributed components:

- **Entry-Hub**: Exposes an HTTPS REST API created by us for initial user authentication.
- **Security-Switch**: Manages secure communication and access control between services using mutual TLS.
- **Database-Vault**: Stores credentials and user metadata, encrypted and isolated.
- **Storage-Service**: Handles encrypted file storage and retrieval.
- **OpenPolicyAgent**: Handles authorization for the access to the Storage-Service.
- **Jump-Host-Storage**: Prevents users from directly accessing storage. (Also known as SSH Bastion)
- **Tailscale Mesh VPN**: Ensures secure, private communication across nodes without opening any public ports.

### Architecture Overview

**Request Flow**: `Client -> Entry-Hub -> Security-Switch -> Database-Vault`

1. **Entry-Hub**: Exposes public HTTPS API, performs initial validation, forwards via mTLS
2. **Security-Switch**: Acts as security checkpoint with defense-in-depth validation  
3. **Database-Vault**: Final storage layer with email encryption and password hashing
4. **Certificate Infrastructure**: Every service authenticates via mTLS using dedicated certificates

### Key Security Features

- **Zero-Trust Network**: All inter-service communication requires mutual TLS authentication
- **Defense-in-Depth**: Each layer re-validates input data independently  
- **Email Encryption**: AES-256-GCM with random salt prevents deterministic encryption
- **Password Security**: Argon2id hashing with cryptographic salt generation
- **Certificate-Based Authentication**: Each service validates client organization certificates

Below, the communication scheme for the various services even tho, at the moment, only user registration is implemented, so only **Entry-Hub<->Security-Switch<->Database-Vault->PostgreSQL**


<img src="documentation/Images/GeneralArchitectureFlow.jpg" alt="General Architecture Flow" width="90%">

## Monitoring & Metrics System

RAM-USB implements a **distributed monitoring architecture** to track system health, performance, and security events across all microservices in real-time.

<img src="documentation/Images/Metrics-Architecture.jpg" alt="Metrics Architecture" width="90%">

### Architecture Overview

The monitoring system follows a **publish-subscribe pattern** secured with mutual TLS:

**Services -> MQTT Broker (Mosquitto) -> Metrics-Collector -> TimescaleDB**

Each service publishes metrics every 2 minutes to dedicated MQTT topics. The Metrics-Collector subscribes to all topics, and stores time-series metrics in TimescaleDB for analysis and visualization.

### Key Components

- **MQTT Broker (Mosquitto)**: Secure message broker with mTLS authentication and topic-based ACL enforcement. Each service can only publish to its own topic (`metrics/entry-hub`, `metrics/security-switch`, etc.)
- **Metrics-Collector**: Subscribes to all metrics topics, performs zero-knowledge validation, and persists data to TimescaleDB. Exposes admin API on port 8446
- **TimescaleDB**: Time-series database optimized for metrics storage with hypertables, continuous aggregates, automatic compression, and 30-day retention policy

### Monitored Metrics

- **Request metrics**: Total requests, success/error rates by endpoint
- **Performance metrics**: Request latency percentiles (p50, p95, p99), active connections
- **Business metrics**: User registrations, authentication attempts
- **System health**: Service uptime, connection status

### Security Features

- **mTLS Authentication**: All MQTT connections require valid client certificates
- **Topic Isolation**: ACL rules prevent services from accessing each other's metrics
- **Zero-Knowledge Validation**: No sensitive user data (emails, passwords, SSH keys) in metrics
- **Certificate-Based Authorization**: Each service uses dedicated certificates with organizational validation

--- 

See the [documentation](documentation/registration_flow.md) for more 

If you are Professor Scagnetto, read also [this guide](documentation/Understanding_RAM-USB.md) 

## Project Structure

RAM-USB implements a **distributed zero-trust architecture** with several microservices.
Each component has specific security responsibilities in the authentication and storage pipeline.

```
.
├── LICENSE & README.md              # Project documentation
├── assets/                          # Project assets (banner, diagrams)
│
├── certificates/                    # PKI Infrastructure for mTLS
│   ├── certification-authority/     # Root CA for the entire system
│   ├── entry-hub/                   # Server + Client certificates for Entry-Hub
│   ├── security-switch/             # Server + Client certificates for Security-Switch  
│   ├── database-vault/              # Server + Client certificates for Database-Vault
│   ├── metrics-collector/           # Server + MQTT Subscriber certificates for Metrics-Collector
│   ├── mqtt-broker/                 # Server certificates for MQTT Broker (port 8883)
│   ├── postgresql/                  # Server certificates for PostgreSQL database
│   ├── timescaledb/                 # Server certificates for TimescaleDB (metrics database)
│   └── storage-service/             # Server + Client certificates for Storage-Service
│
├── entry-hub/                      # Public HTTPS API Gateway
│   ├── handlers/                   # REST API endpoints (/api/register, /api/health)
│   ├── interfaces/                 # mTLS client for Security-Switch communication (entry-hub->security-switch)
│   ├── config/                     # Service configuration (Security-Switch IP, mTLS certificates)
│   ├── utils/                      # Input validation, HTTP helpers, JSON parsing, error handling
│   ├── types/                      # Data structures for API requests/responses (RegisterRequest, Response)
│   ├── metrics/                    # Internal metrics collection (requests, latency, registrations)
│   ├── mqtt/                       # MQTT publisher for metrics transmission to broker
│   ├── middleware/                 # Metrics middleware for HTTP request instrumentation
│   └── main.go                     # HTTPS server (port 8443)
│
├── security-switch/                # mTLS Security Gateway  
│   ├── handlers/                   # REST API endpoints (/api/register, /api/health) using defense-in-depth validation
│   ├── interfaces/                 # mTLS client for Database-Vault communication (security-switch->database-vault)
│   ├── config/                     # Service configuration (Database-Vault IP, mTLS certificates)
│   ├── utils/                      # Defense-in-depth validation, HTTP helpers, JSON parsing, error handling
│   ├── types/                      # Data structures for API requests/responses (RegisterRequest, Response)
│   ├── metrics/                    # Internal metrics collection (requests, validation failures, errors)
│   ├── mqtt/                       # MQTT publisher for metrics transmission to broker
│   ├── middleware/                 # mTLS authentication enforcement
│   └── main.go                     # mTLS server (port 8444)
│
├── database-vault/                 # Encrypted Credential Storage
│   ├── handlers/                   # User storage with AES-256-GCM encryption
│   ├── config/                     # Service configuration (database URL, encryption keys, mTLS certificates)
│   ├── database/                   # PostgreSQL Database Layer
│   │   ├── setup.sh                # Automated database setup script
│   │   ├── README.md               # Database documentation and setup guide
│   │   └── schema/                 # SQL Schema definitions
│   │       ├── 001_create_tables.sql        # Users table with encryption fields
│   │       ├── 002_create_indexes.sql       # Performance and security indexes
│   │       ├── 003_create_triggers.sql      # Automatic timestamp management
│   │       └── 004_create_constraints.sql   # Data validation constraints
│   ├── utils/                      # Final validation layer, HTTP helpers, JSON parsing, error handling
│   ├── types/                      # Data structures for storage operations (StoredUser, RegisterRequest, Response)
│   ├── crypto/                     # Argon2id hashing + AES-256-GCM encryption utilities
│   ├── storage/                    # Database interface definitions and implementations
│   │   ├── interface.go            # Storage interface definitions with security contracts
│   │   └── postgresql/             # PostgreSQL implementation
│   │       ├── postgresql.go       # Main implementation of UserStorage interface
│   │       ├── connection.go       # Connection pooling and database management  
│   │       ├── queries.go          # SQL query constants and prepared statements
│   │       └── errors.go           # PostgreSQL error mapping and categorization
│   ├── metrics/                    # Internal metrics collection (storage operations, encryption stats)
│   ├── mqtt/                       # MQTT publisher for metrics transmission to broker
│   ├── middleware/                 # mTLS authentication for Security-Switch
│   └── main.go                     # mTLS server (port 8445)
│ 
├── mqtt-broker/                    # MQTT Message Broker for Metrics Distribution
│   ├── mosquitto.conf              # TLS configuration and listener settings
│   ├── acl.conf                    # Topic-based access control (publisher/subscriber isolation)
│   └── setup.sh                    # Automated broker configuration script
│
├── metrics-collector/              # Metrics Collection and TimescaleDB Storage
│   ├── handlers/                   # Admin API endpoints (/api/health, /api/stats)
│   ├── mqtt/                       # MQTT subscriber for metrics reception from all services
│   ├── storage/                    # TimescaleDB interface and time-series operations
│   ├── config/                     # Service configuration (MQTT broker, TimescaleDB connection)
│   ├── types/                      # Metric data structures (Metric, StoredMetric, MetricQuery)
│   ├── database/                   # TimescaleDB schema and setup scripts
│   └── main.go                     # Admin mTLS server (port 8446)
│
├── user-client/                    # Client
│   ├── registration/               # HTTPS client for registration flow
│   └── keys/                       # SSH keypair
│   └── main.go                     # Registration test client
│
├── documentation/                  # Technical Documentation
│   └── registration_flow.md        # Complete system flow and security model
│
│── scripts/                        # Setup & Deployment
│   └── generate_key.sh             # Automated certificate generation script
└── env_setup.sh                    # Environment variables configuration for all services
```


## Getting Started

> ⚠️ This project is under active development and is not ready for production use. It has only been tested on macOS. It should work on Linux, but it has not been tested yet.

To test the registration process locally: (Only a reminder for me, plz don't do that)

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

4. **Open 5 terminal tabs**

### Setup and Start Services (in order)

**TAB-1 (Metrics-Collector):**
```bash
cd Metrics-Collector 
go run .
```

**TAB-2 (Database-Vault):**
```bash
cd database-vault
export RAMUSB_ENCRYPTION_KEY=$(openssl rand -hex 32)
go run .
```

**TAB-3 (Security-Switch):**
```bash
cd security-switch  
go run .
```

**TAB-4 (Entry-Hub):**
```bash
cd entry-hub
go run .
```

**TAB-5 (Test Client):**
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
	•	[**Francesco Verrengia**](https://github.com/Verryx-02)
	•	[**Riccardo Gottardi**](https://github.com/Riccardo-Gottardi)

⸻

License: [MIT](LICENSE)

⸻

Acknowledgments

Special thanks to the University of Udine, in particular to Professor Ivan Scagnetto, for supporting our research and experimentation on secure and distributed systems.
