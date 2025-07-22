# R.A.M.-U.S.B. — Remotely Accessible Multi-User Backup Server
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**R.A.M.-U.S.B.** is a geo-distributed, Remotely Accessible Multi-User Backup Server written in **Go**, designed with **zero-knowledge security principles** in mind. This project was designed and developed by **Francesco Verrengia** and **Riccardo Gottardi** as part of our academic work in the field of IoT and cybersecurity.

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

## Getting Started

> ⚠️ This project is under active development and not ready for production use.


⸻

Authors
	•	Francesco Verrengia
	•	Riccardo Gottardi

⸻

License

License: [MIT](LICENSE)

⸻

Acknowledgments

Special thanks to the University of Udine, in particular to Professor Ivan Scagnetto, for supporting our research and experimentation on secure and distributed systems.
