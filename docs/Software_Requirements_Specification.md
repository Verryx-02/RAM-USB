
---

Date: 21-Jul-2026 
Indexes: [[RAM-USB]]

---

**Version:** 1.12  
**Status:** Amended: added two entries to section 8. RISK-05 records the registration-endpoint email enumeration (`POST /api/users` answers 201 for a free address and 409 for a registered one, and a freshly generated SSH key removes the only other possible cause of the conflict), together with its account-squatting side effect and the reason the out-of-band-confirmation mitigation is deferred. RISK-06 records that the email lookup key (DV-F-03) is an unkeyed SHA-256 while the pepper (DV-F-06) protects only passwords, so a stolen database copy alone is enough to test whether a given address is registered, and states the HMAC-SHA256 mitigation and its cost. The two are distinct: RISK-05 is an online oracle against the public API, RISK-06 is offline against a dump. No requirement text changed. Still open from 1.10: the code permalinks for EH-F-01/EH-F-02 need re-pinning to the commit that landed the `GET /api/health` and `POST /api/users` rename, and EH-F-04's own wording still names the pre-rename `/api/register` path.
**Author:** Francesco Verrengia

> [!NOTE] The level of detail in this document increases with each iteration, following the spiral model of requirements engineering.

---

## 1. Introduction

### 1.1 Purpose of the document

This SRS describes **what** RAM-USB must do, not **how** it must do it.  
It is the document that architectural design, the test plan, and implementation must all refer back to.

### 1.2 Product scope

RAM-USB is a multi-user, geo-distributed, remotely accessible backup service, designed according to **zero-knowledge**, **zero-trust**, and **defense-in-depth** principles. 
The goal of the project is not to compete with commercial solutions, but to serve as an in-depth case study on the secure design of distributed backup systems. 
**Correctness and transparency of the design matter more than delivery speed or feature coverage**.

#### **Temporarily out of scope:**

- changing a user's credentials,
- revoking a user's access to the system,
- protecting backups from modification/deletion, including by administrators (see RU-09, RISK-01),
- GDPR compliance.

#### **Permanently out of scope:**

- a graphical interface for the end user,
- billing / commercial limits.

#### Deliberate design choices

Some choices below trade a theoretically stronger design for one that better serves the actual research interest behind this thesis:

- **Email/password login.** A zero-knowledge authentication protocol (e.g. SRP) would avoid ever transmitting the plaintext password, even in transit. This project deliberately uses classic email/password login instead: exploring that authentication pattern, and how far its guarantees can still be pushed (salted+peppered Argon2id hashing, encrypted email storage, never persisting or logging plaintext), is itself the object of study.
- **Filesystem-based backup over SFTP.** A block-level protocol (e.g. iSCSI) would avoid most of the complexity in ST-F-06..ST-F-11 (POSIX user creation, chroot isolation, `AuthorizedKeysCommand`), since the server would never need to reason about directories or user escaping at all. This project deliberately backs up to a filesystem instead, because the research interest is specifically in filesystem-level isolation and preventing directory escaping via chroot.
- **`/api/login` kept as an action endpoint, not a `/api/sessions` resource.** The idiomatic REST mapping for login is `POST` to create a session resource, inspectable via `GET` and revocable via `DELETE`. This project deliberately does not do that: no session ID is ever returned to the client, nothing can `GET` a session's status, and there is no logout use case (UC-01..05) — the 12-hour ACL grant simply expires on its own (NM-F-10). Building the missing `GET`/`DELETE` semantics to justify a resource-style name would mean implementing user-access revocation, which RU-09/RISK-01 already marks out of scope. `/api/login` stays an explicitly-named action, honest about being create-only, rather than a resource name with no resource behind it.

### 1.3 Definitions and acronyms

| **Term**           | **Meaning**                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| [Zero-knowledge]() | No server-side component can access the user's data in plaintext                                             |
| Zero-trust         | No component implicitly trusts data received from another component, even if that component is authenticated |
| Defense-in-depth   | Every layer independently re-validates input, regardless of upstream checks                                  |
| mTLS               | Mutual TLS: mutual authentication via X.509 certificates signed by the private CA                            |
| SRS                | This document                                                                                                |
| RU / RS            | User Requirements / System Requirements                                                                      |

---

## 2. General description

### 2.1 Product perspective

RAM-USB is an n-tier client-server microservices architecture made up of 11 Docker containers.

|**Component**|**Current implementation status**|
|---|---|
|User|Done|
|Entry-Hub|Done|
|Security-Switch|Done|
|Database-Vault|Done|
|Storage-Service|Done|
|Network-Manager|Done|
|[Headscale](https://github.com/juanfont/headscale)|Done|
|Mosquitto (MQTT broker)|Done|
|Metrics-Collector|Done|
|Metrics-Visualizer (Grafana)|Done|
|[Certificate-Authority](https://github.com/smallstep/certificates)|Done|

### 2.2 Main product functions

1. User registration
2. User login
3. Backup of files to the server, encrypted client-side
4. File restore
5. ACL-based access control for storage
6. Zero-knowledge operational monitoring of the system

### 2.3 User classes

| **Class** | **Description**                                          |
| --------- | -------------------------------------------------------- |
| User      | Registers, performs backup/restore of their own files    |
| Admin     | Manages the infrastructure, consults operational metrics |

### 2.4 Operating environment

- **Development and testing:** Docker on macOS
- **Production target:** Docker on macOS, Docker on Proxmox VE
- **Network:** Headscale mesh VPN (self-hosted Tailscale)

> [!NOTE] Docker and Proxmox are not alternatives, they serve different purposes: Docker provides ease of deployment and per-service isolation, identical in development and production. Proxmox (KVM for Storage-Service/Database-Vault/Network-Manager, LXC for the rest, per RNF-ORG-04) provides a stronger isolation boundary underneath Docker and, if a hyperconverged cluster is built later, high availability (live migration, failover between physical nodes) that Docker alone cannot provide. Every service's Docker container runs inside its assigned Proxmox VM/container in production.

> [!NOTE] Container base image policy: every service's Dockerfile defaults to `gcr.io/distroless/static-debian12:nonroot` (no shell, no package manager, runs as a fixed non-root UID) rather than a general-purpose Linux base. This is the default because most services are a single static Go binary with no OS-level requirement beyond running that binary, and a minimal runtime narrows the attack surface available to anyone who reaches the process (RNF-SEC-03). `debian:bookworm-slim` is used only where a service has a genuine OS-level requirement a distroless image cannot satisfy, such as Storage-Service's need for `sshd`, POSIX user creation, and chroot (see the container-architecture note after section 4.5).

### 2.5 Design and implementation constraints

- **Language:** Go
- **Personal user data persistence:** PostgreSQL
- **Metrics persistence:** TimescaleDB
- **User backup persistence:** Ideally CephFS

### 2.6 Assumptions and dependencies

- The private network infrastructure is assumed to be available and working
- Certificate issuance is assumed to be handled by the Certificate-Authority (CA-F-04's bootstrap-token flow)
- For now, the encryption master key is assumed to reside in an environment variable
- The user is assumed to have installed the Tailscale client on their system before completing registration

---

> [!NOTE] Distribution of initial certificates: 
> each service receives, out-of-band (the same channel used for the master key and pepper, see 2.6), a single-use bootstrap token. It uses this token exactly once, at startup, to obtain its initial certificate from the CA (CA-F-04). Subsequent renewals happen by presenting the mTLS certificate the service already holds, not the token.

## 3. User requirements

|**ID**|**User type**|**Requirement**|
|---|---|---|
|RU-01|User|I want to register for the service by providing the minimum amount of data necessary.|
|RU-02|User|I want to be able to authenticate in sessions following registration.|
|RU-03|User|I want to be able to upload encrypted backups to the service from anywhere.|
|RU-04|User|I want to be able to access my backup only after having authenticated.|
|RU-05|User|I want the guarantee that no one, including the service administrators, can read my backups.|
|RU-06|User|I want the guarantee that no one, including the service administrators, can read my login credentials.|
|RU-07|User|I want to be able to retrieve my files at any time.|
|RU-08|User|I want to be certain that my data is isolated from that of other users.|
|RU-09|User|**Out of scope** I want no one, including the service administrators, to be able to modify or delete my backups|
|RU-10|Admin|I want to be able to observe the system's health and performance without compromising user data.|

---

## 4. System requirements (Functional)

### 4.1 Client (User)

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|CL-F-01|Must autonomously generate an SSH key pair (public/private) before registration, never transmitting the private key to any system component|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/user-client/internal/sshkey/sshkey.go#L96-L195)|
|CL-F-02|Following a user command, must send only the SSH public key to Entry-Hub during registration (`POST /api/users`), together with email and password|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/user-client/internal/entryhub/client.go#L121-L144)|
|CL-F-03|Following a user command, must re-run login (`POST /api/login`) before the 12-hour ACL grant expires, to maintain continuity of access to Storage-Service|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/user-client/internal/entryhub/client.go#L146-L164)|
|CL-F-04|Must configure and start Tailscale using the pre-auth key received in the registration response, in order to join the private mesh network|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/user-client/internal/mesh/mesh.go#L34-L56)|
|CL-F-05|Must resolve Storage-Service via MagicDNS on the mesh network, without relying on static IP addresses|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/user-client/internal/mesh/mesh.go#L1-L16)|
|CL-F-06|Following a user command, must invoke `restic backup` against Storage-Service via SFTP, authenticating with the SSH private key generated in CL-F-01|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/user-client/internal/restic/restic.go#L118-L130)|
|CL-F-07|Following a user command, must invoke `restic restore` against Storage-Service via SFTP, using the same authentication method as CL-F-06|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/user-client/internal/restic/restic.go#L132-L147)|
|CL-F-08|Must handle the HTTP error codes returned by Entry-Hub (400/401/403/500/502/503/504) without exposing internal system details to the end user|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/user-client/internal/entryhub/client.go#L195-L222)|
|CL-F-09|Following a user command, must validate email, password, and (for registration only) the SSH public key locally, using the same rules Entry-Hub enforces (EH-F-04 for registration, EH-F-05 for login), before sending `POST /api/users` or `POST /api/login`; on local validation failure, must not transmit the request|Reduces needless requests; does not replace server-side re-validation (RNF-SEC-02, RNF-SEC-03) [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/user-client/internal/entryhub/client.go#L121-L164)|

### 4.2 Entry-Hub

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|EH-F-01|Must expose a public HTTPS health-check endpoint:<br>`GET /api/health`<br>with certificates signed by the **public** Let's Encrypt CA|The public CA is used so that Users can never reach the internal CA that certifies mTLS connections between the system's internal components. [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/internal/httpapi/handler.go#L86-L91) / [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/cmd/entry-hub/main.go#L428-L449)|
|EH-F-02|Must expose a public HTTPS endpoint for user registration:<br>`POST /api/users`,<br>with certificates signed by the **public** Let's Encrypt CA|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/internal/httpapi/handler.go#L100-L124)|
|EH-F-03|Must expose an HTTPS endpoint<br>`POST /api/login`<br>for the authentication of registered users, served on a **separate listener reachable only from the private mesh network** (not the public internet, unlike EH-F-01/EH-F-02's listener), <br>with certificates signed by the **public** Let's Encrypt CA — the identical certificate EH-F-01/EH-F-02 present, not mTLS; only network reachability differs|Once a client has completed registration and joined the mesh (CL-F-04), there is no remaining need for login to be reachable from outside it — keeping it mesh-only removes a whole class of unauthenticated-login-endpoint exposure. [Code](https://github.com/Verryx-02/RAM-USB/blob/cc1542f19153d9c0754c880aec783e95f0c4356d/services/entry-hub/cmd/entry-hub/main.go#L16-L35) / [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/internal/httpapi/handler.go#L130-L154)|
|EH-F-04|`/api/register` must accept JSON and validate: presence of `email`, `password`, and SSH public key fields; payload size within a defined limit; no unexpected additional fields; email format (RFC 5322); password length between 8 and 128 characters; password complexity (at least 3 character categories among lowercase, uppercase, digit, symbol); the SSH public key is well-formed.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/pkg/validation/validation.go#L150-L162)|
|EH-F-05|`/api/login` must accept JSON and validate: presence of `email` and `password` fields; payload size within a defined limit; no unexpected additional fields; email format (RFC 5322); password length between 8 and 128 characters; password complexity (at least 3 character categories).|Same as register, but without the SSH key [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/pkg/validation/validation.go#L164-L173)|
|EH-F-06|On validation failure it must:<br>- respond with HTTP 400 (Bad Request) without specifying which problem was encountered,<br>- log the issue found without identifying the user,<br>- not forward the request to any other internal service.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/internal/httpapi/handler.go#L156-L164)|
|EH-F-07|On successful validation it must:<br>- log the validation outcome without identifying the user,<br>- forward the request to Security-Switch via mTLS,<br>- verify that the certificate **comes from a Security-Switch**,<br>- verify that the X.509 certificate is valid.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/internal/httpapi/forward.go#L17-L31)|
|EH-F-08|Must forward Security-Switch's response back to the user|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/internal/httpapi/forward.go#L33-L66)|
|EH-F-09|Must map internal errors to HTTP 400/401/500/502/503, returning sanitized messages to the client and detailed logs internally only|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/internal/httpapi/forward.go#L68-L88)|
|EH-F-10|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Entry-Hub`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/cmd/entry-hub/main.go#L517-L544)|
|EH-F-11|Metrics must never contain users' personal data, only aggregated statistics|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/entry-hub/internal/httpapi/counters.go#L1-L62)|

---

### 4.3 Security-Switch

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|SS-F-01|Must accept only mTLS connections from clients with:<br>- `organization="EntryHub"`,<br>- a valid X.509 certificate,<br>- access to the private mesh network.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/security-switch/internal/server/server.go#L1-L15)|
|SS-F-02|Must re-validate the received input, independently of the validation already performed by Entry-Hub|Same validation as Entry-Hub [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/security-switch/internal/httpapi/handler.go#L114-L125)|
|SS-F-03|On validation failure it must:<br>- respond with HTTP 400 (Bad Request) without specifying which problem was encountered,<br>- log the issue found without identifying the user,<br>- not forward the request to any other internal service.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/security-switch/internal/httpapi/handler.go#L268-L276)|
|SS-F-04|On successful validation it must:<br>- log the validation outcome without identifying the user,<br>- forward the request to Database-Vault via mTLS, verifying that:<br>  - the certificate comes from a Database-Vault,<br>  - the X.509 certificate is valid.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/security-switch/internal/dbvault/client.go#L134-L177)|
|SS-F-05|After confirmation of successful authentication from Database-Vault, must request Network-Manager (over mTLS) to grant that user access to Storage-Service for 12 hours|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/security-switch/internal/networkmanager/client.go#L128-L171)|
|SS-F-06|Must map errors to HTTP 400/401/403/500/502/504|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/security-switch/internal/httpapi/handler.go#L219-L266)|
|SS-F-07|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Security-Switch`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/security-switch/cmd/security-switch/main.go#L408-L423)|
|SS-F-08|Metrics must never contain users' personal data, only aggregated statistics|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/security-switch/internal/httpapi/counters.go#L1-L63)|
|SS-F-09|After confirmation of successful registration from Database-Vault, must request Network-Manager (over mTLS) to create a dedicated Headscale user and generate a pre-auth key for the new account, then include that key in the response to Entry-Hub|Mirrors NM-F-08; distinct from SS-F-05, which covers the post-login ACL grant, not registration [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/security-switch/internal/networkmanager/client.go#L173-L211)|

---

### 4.4 Database-Vault

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|DV-F-01|Must accept only mTLS connections from clients with:<br>- `organization="SecuritySwitch"`,<br>- a valid certificate,<br>- access to the private mesh network.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/server/server.go#L1-L39)|
|DV-F-02|Must re-validate the received input, independently of the validation already performed by Security-Switch.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/httpapi/handler.go#L100-L111)|
|DV-F-03|Must compute the SHA-256 hash of the email for indexing and as primary key, never logging the plaintext email.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/hashing/hashing.go#L17-L39)|
|DV-F-04|Must encrypt the user's email: derive a per-record encryption key from the master key with HKDF-SHA256 and a random 16-byte salt, then encrypt the email with AES-256-GCM using that derived key and a random 12-byte nonce.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/encryption/encryption.go#L49-L82)|
|DV-F-05|The master key should come from a configurable source with length validation (32 bytes)|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/encryption/masterkey.go#L1-L59)|
|DV-F-06|Must hold a pepper as an environment variable|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/password/pepper.go#L1-L42)|
|DV-F-07|Must compute the password hash with Argon2id: memory 47104 KiB (46 MiB), 2 iterations, parallelism 1, 32-byte output, using a random per-record salt and the pepper (DV-F-06).|Stored as a single self-describing string (algorithm, cost parameters, salt, and digest together); no separate salt field is persisted. [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/password/hash.go#L114-L144)|
|DV-F-08|Must save the user record in an atomic transaction|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/storage/storage.go#L97-L146)|
|DV-F-09|Must ask Storage-Service to create the unique POSIX user on the server with username `user<xxxxxx>`, where `xxxxxx` are 6 random characters from a base-36 alphabet, and wait for its response|"user<xxxxxx>" all lowercase [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/posix/username.go#L30-L50) / [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/posix/client.go#L52-L101)|
|DV-F-10|If POSIX user creation fails, must delete the user from the database and inform Security-Switch that user registration failed|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/registration/registration.go#L136-L149)|
|DV-F-11|After creating the user record and the POSIX user, must inform Security-Switch that the user was registered|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/registration/registration.go#L151-L152)|
|DV-F-12|Must reject (HTTP 409) registrations with an email or SSH key that already exists, without giving details about the error|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/registration/registration.go#L124-L129)|
|DV-F-13|During login, must retrieve the salt associated with the email via the SHA-256 hash of the email (DV-F-03)|The salt is retrieved by decoding the stored password hash (DV-F-07), not a separate stored field. [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/storage/lookup.go#L52-L75)|
|DV-F-14|Must recompute Argon2id on the received password using the retrieved salt and the pepper, and compare the result with the stored hash|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/password/hash.go#L146-L168)|
|DV-F-15|Must respond with the same HTTP 401 status code for both a nonexistent email and an incorrect password, without distinguishing between the two cases either in the response or in the log|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/login/login.go#L140-L169)|
|DV-F-16|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Database-Vault`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/cmd/database-vault/main.go#L519-L534)|
|DV-F-17|Metrics must never contain users' personal data, only aggregated statistics|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/httpapi/counters.go#L1-L84)|
|DV-F-18|A master key backup procedure should exist||
|DV-F-19|A master key rotation procedure should exist||
|DV-F-20|On validation failure it must:<br>- respond with HTTP 400 (Bad Request) without specifying which problem was encountered,<br>- log the issue found without identifying the user,<br>- not forward the request to any other internal service.|Same pattern as EH-F-06/SS-F-03, added for Database-Vault [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/httpapi/handler.go#L200-L222)|

---

### 4.5 Storage-Service

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|ST-F-01|Must accept mTLS connections only from clients with:<br>- `organization="DatabaseVault"`,<br>- a valid certificate,<br>- access to the private mesh network.|Accepts both mTLS (Database-Vault) and SFTP (Users) [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/storage-service/internal/server/server.go#L1-L26)|
|ST-F-02|Must provide upload/download of client-side-encrypted files, never processing plaintext content|Files are encrypted client-side [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/deployments/docker/storage-service/sshd_config#L33-L36)|
|ST-F-03|Access must occur exclusively via SFTP authenticated with the user's registered SSH public key|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/deployments/docker/storage-service/sshd_config#L43-L46)|
|ST-F-04|Must explicitly forbid any other form of SSH connection besides SFTP|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/deployments/docker/storage-service/sshd_config#L70-L81)|
|ST-F-05|Each user must have an isolated storage space, not accessible by other users|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/deployments/docker/storage-service/sshd_config#L62-L68)|
|ST-F-06|Following a request from Database-Vault over mTLS, must create a POSIX user on the system with username `user<xxxxxx>`, where `xxxxxx` are 6 random characters from a base-36 alphabet|"user<xxxxxx>" all lowercase [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/storage-service/internal/posixuser/creator.go#L101-L170)|
|ST-F-07|Must ensure the POSIX user can never leave their own directory|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/deployments/docker/storage-service/sshd_config#L62-L81)|
|ST-F-08|The created POSIX account must not have a traditional home directory or an interactive shell; the only writable space is the dedicated subdirectory inside the chroot|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/storage-service/internal/posixuser/creator.go#L114-L167)|
|ST-F-09|Storage-Service's sshd configuration must have `PasswordAuthentication no` and `PermitRootLogin no`, regardless of the fact that the created accounts have no password set|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/deployments/docker/storage-service/sshd_config#L38-L57)|
|ST-F-10|Following successful or failed creation of the POSIX user, must report the outcome back to Database-Vault.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/storage-service/internal/httpapi/httpapi.go#L118-L161)|
|ST-F-11|On every user SFTP connection attempt, must retrieve the user's current public key from Database-Vault via `AuthorizedKeysCommand`|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/deployments/docker/storage-service/sshd_config#L83-L90) / [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/storage-service/internal/pubkeylookup/lookup.go#L91-L126)|
|ST-F-12|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Storage-Service`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.||
|ST-F-13|Metrics must never contain users' personal data, only aggregated statistics||
|ST-F-14|**Should** enforce per-user quota limits|Nice-to-have but complex|
|ST-F-15|**Should** guarantee:<br>- automatic data replication,<br>- fault tolerance for at least one node,<br>- data consistency,<br>- the ability to expand by adding new nodes without interrupting service.|Nice-to-have (CephFS)|

Storage-Service directory structure:

```
/storage/       <- root of all users
│
├── user7k2m9x/ <- chroot root of THIS user, owned by: root:root
│   │      
│   └── data/   <- ONLY writable directory
│                 owned by: user7k2m9x:user7k2m9x
│                 this is where Restic writes the user's backups
├── user3f9a1c/
│   └── data/
│
└── userxk82p1/
    └── data/
```

---

> [!NOTE] Storage-Service container architecture:
> the container runs two independent long-lived processes: a hardened `sshd` (ST-F-03/04/07/08/09) and a Go mTLS HTTP server (ST-F-06/10), supervised by `s6-overlay` on a `debian:bookworm-slim` base image. This lets the container create a new POSIX user per registration, on demand, satisfying ST-F-06. POSIX users are created via explicit `useradd` and `groupadd` calls. The container runs with `cap_drop: ALL` plus a minimal added set (`CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SYS_CHROOT`), needed by both the user-creation code and by sshd's own per-connection setuid and chroot operations, per RNF-SEC-03 and RNF-REL-01. ST-F-11's `AuthorizedKeysCommand` is a dedicated Go binary, per RNF-ORG-01, running as a dedicated unprivileged system account with no other role on the host. Any failure of its call to Database-Vault (timeout, lookup error, malformed response) denies the SSH connection, per RD-04's fail-secure principle.

---

### 4.6 Network Manager

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|NM-F-01|Must ensure that only Entry-Hub, Database-Vault, Network-Manager, and Certificate-Authority can contact Security-Switch|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/headscale/policy.go#L182-L187)|
|NM-F-02|Must ensure that only Security-Switch, Storage-Service, and Certificate-Authority can contact Database-Vault|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/headscale/policy.go#L188-L193)|
|NM-F-03|Must ensure that only Security-Switch and Certificate-Authority can contact Network-Manager|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/server/server.go#L1-L36) / [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/headscale/policy.go#L194-L206)|
|NM-F-04|Must ensure that all internal components of the network, except Users, can contact, and be contacted by, the Certificate-Authority over the mesh network|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/headscale/policy.go#L207-L224)|
|NM-F-05|Must ensure that **only authenticated users** can see and contact Storage-Service|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/headscale/policy.go#L225-L242)|
|NM-F-06|Must ensure that **registered but not authenticated Users** can see and contact only Entry-Hub|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/headscale/policy.go#L243-L252)|
|NM-F-07|Must ensure that **registered and authenticated Users** can see and contact only Entry-Hub and Storage-Service|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/headscale/policy.go#L225-L252)|
|NM-F-08|On request from Security-Switch, following successful registration, must create a dedicated Headscale user and generate a short-lived pre-auth key for the new account|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/headscale/client.go#L184-L217)|
|NM-F-09|After a successful login, on request from Security-Switch, must assign the user's node the ACL tag that enables reachability toward Storage-Service, and record an expiry 12 hours from that point|[[NM-F-09 empirical verification \| Verified]] [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/headscale/client.go#L219-L275)|
|NM-F-10|Must periodically check recorded expiries and remove the ACL tag from expired nodes, automatically and without manual intervention|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/grants/sweep.go#L30-L88)|
|NM-F-11|The expiry of every grant must be persisted, not kept only in memory, so as not to lose state if Network-Manager restarts|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/grants/store.go#L58-L197)|
|NM-F-12|Creating pre-auth keys and managing ACL tags must be restricted to Network-Manager specifically, verified via mutual TLS (`organization=NetworkManager`)|Headscale's own documentation advises against making the coordination server itself a member of the mesh it coordinates, so - unlike every other inter-service call in this system - this admin traffic cannot be restricted by network placement; it is reachable over the same public network as NM-F-14's coordination endpoint, with mTLS (RNF-SEC-04) as the sole enforcement layer.|
|NM-F-13|The pre-auth key serves solely to register the node as a mesh member; it does not, by itself, grant reachability toward Storage-Service||
|NM-F-14|Headscale's coordination endpoint is deliberately reachable from the public network (ideally hosted on its own publicly-addressable VPS)|A newly registered node has no other way to reach it before completing CL-F-04's mesh join; registration itself requires a valid pre-auth key (NM-F-08), and that key does not, by itself, grant reachability toward anything else in the private mesh (NM-F-13)|
|NM-F-15|Must configure MagicDNS with a dedicated base domain, so that Storage-Service can be resolved by all mesh nodes via a stable name rather than an IP||
|NM-F-16|Network-Manager's mesh node must accept the DNS configuration distributed by Headscale (MagicDNS), so that its own outbound calls to Certificate-Authority and MQTT-Broker resolve those hostnames over the mesh rather than falling back to a network path with no production equivalent|Originally worded the opposite way, to avoid a circular reference from Headscale's own MagicDNS nameserver answers being served by this same host - that scenario no longer applies now that Headscale is deployed as a separate, standalone service (see NM-F-12/NM-F-14). Accepting Headscale's DNS creates a residual dependency of Network-Manager's own name resolution on the ACL policy it itself pushes to Headscale (see policy.go); this trade-off is accepted, see RISK-04.|
|NM-F-17|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Network-Manager`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/cmd/network-manager/main.go#L521-L545)|
|NM-F-18|Metrics must never contain users' personal data, only aggregated statistics|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/network-manager/internal/httpapi/counters.go#L1-L61)|

### 4.7 Certificate-Authority

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|CA-F-01|Must guarantee that components presenting certificates for mTLS are truly who they claim to be|The private CA exists because services not exposed to the internet cannot be reached by a public CA such as Let's Encrypt. Provided by the underlying product.|
|CA-F-02|Must guarantee the issuance, rotation, revocation, and verification of mTLS certificates|Provided by the underlying product.|
|CA-F-03|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Certificate-Authority`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.||
|CA-F-04|Must accept a single-use bootstrap token, distributed out-of-band to each service, for issuing the initial certificate; subsequent renewals must occur via the current mTLS certificate, not via the token|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/pkg/pki/pki.go#L57-L113)|

> [!NOTE] CA-F-01 and CA-F-02 are guarantees of the underlying product, not requirements original RAM-USB code implements from scratch: the official `smallstep/step-ca` image (the `certificate-authority` service in `deployments/compose/certificate-authority.yml`) already provides certificate issuance, short-lived-certificate rotation, and revocation as native features. What RAM-USB built is the glue that makes that guarantee actually hold end-to-end for this system: `pkg/pki` (CA-F-04) for bootstrap-token-based initial issuance and automatic renewal, `pkg/mtls`'s organization-field check (PKI-F-02), and a custom certificate template (`third-party/certificate-authority/config/organization.x509.tpl`, applied automatically on every `docker compose up` by the `certificate-authority-init` compose service).

---

### 4.8 Monitoring system (MQTT-Broker / Metrics-Collector / TimescaleDB / Grafana)

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|MT-F-01|Metrics-Collector can only read `metrics/*`||
|MT-F-02|Metrics-Collector must discard metrics whose `service` field does not match the topic they came from|Using the [Mosquitto Access Control List](https://github.com/Verryx-02/RAM-USB/blob/main/mqtt-broker/acl.conf)|
|MT-F-03|Metrics must be stored as a TimescaleDB hypertable, with automatic 30-day retention and compression after 7 days||
|MT-F-04|Grafana dashboards must exist for response time, throughput, and active connections||

---

### 4.9 Network infrastructure and Public Key Infrastructure

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|PKI-F-01|Every service must mutually authenticate with X.509 certificates issued by a [valid CA](https://github.com/smallstep/certificates)|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/pkg/pki/pki.go#L1-L113)|
|PKI-F-02|Every service must verify the certificate's `organization` field, not merely its validity|[Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/pkg/mtls/mtls.go#L82-L132)|
|PKI-F-03|A certificate rotation and revocation procedure **should** exist||
|NET-F-01|Inter-service communication must occur over the private network; Entry-Hub's public endpoints and Network-Manager's Headscale coordination endpoint (NM-F-14) are the system's only deliberately public-facing surfaces||
|NET-F-02|TLS must be v1.3||

---

## 5. Non-functional requirements

### 5.1 Product requirements

|**ID**|**Requirement**|**Verifiable via**|
|---|---|---|
|RNF-SEC-01|Zero-knowledge: no server-side component ever accesses backup file contents in plaintext, since encryption happens client-side before transmission.<br>This does not extend to login credentials: email and password transit, encrypted (TLS/mTLS), through Entry-Hub, Security-Switch, and Database-Vault for validation and hashing, though they are never persisted or logged in plaintext (see DV-F-03, RD-01).||
|RNF-SEC-02|Zero-trust: no service must implicitly trust data received from another, even if mTLS-authenticated||
|RNF-SEC-03|Defense-in-depth: every layer independently re-validates input||
|RNF-SEC-04|All inter-service communication must use mTLS, with no exceptions||
|RNF-REL-01|The system must tolerate the isolated compromise of a single component without it spreading to others||
|RNF-PERF-01|HTTP request latency tracked (p50/p95/p99)||
|RNF-USA-01|Error messages that are understandable and correctly categorized by HTTP code||
|RNF-MAINT-01|Every service must be able to be isolated, re-certified, and restarted individually without impacting the others||

### 5.2 Organizational requirements

|**ID**|**Requirement**|
|---|---|
|RNF-ORG-01|Implementation language: Go|
|RNF-ORG-03|Open-source MIT license|
|RNF-ORG-04|Deployment target: Proxmox VE (KVM for Storage-Service, Database-Vault, Network-Manager; LXC for the other services)|
|RNF-ORG-05|Development and operation guaranteed on macOS and Linux (with Docker)|

### 5.3 External requirements

|**ID**|**Requirement**|
|---|---|
|RNF-EXT-01|Since the system processes personal data (email), it should comply with applicable privacy regulations (e.g. GDPR). **Currently out of scope**|

---

## 6. Domain requirements

Constraints deriving from the distributed-security domain:

|**ID**|**Requirement**|
|---|---|
|RD-01|Any new component introduced in the future must not create a path along which sensitive plaintext data crosses or is logged by a component other than the client or the component strictly necessary for its encryption/decryption|
|RD-02|Derived keys (via HKDF) must never be persisted: any new key-storage requirement must be evaluated against this constraint before being accepted|
|RD-03|Argon2id and AES-256-GCM are non-negotiable technology constraints|
|RD-04|The "fail-secure" principle applies to every component: when there is uncertainty about the validity of a request, the default is to deny access. [Code](https://github.com/Verryx-02/RAM-USB/blob/7c1e991f953a4c686e09f8142d0b3c1d9d64fc5f/services/database-vault/internal/login/login.go#L44-L55)|

---

## 7. Main use cases

### UC-01 User registration

- **Status:**
- **Actor:** User
- **Preconditions:** email and SSH key not already present in Database-Vault
- **Main flow:**
    1. The client sends `POST /api/users` to Entry-Hub over HTTPS (not mTLS): email, password, SSH key
    2. Entry-Hub validates and forwards via mTLS to Security-Switch
    3. Security-Switch re-validates and forwards via mTLS to Database-Vault
    4. Database-Vault re-validates, encrypts the email, hashes the email and password, checks that no duplicates exist, and saves the record in an atomic transaction
    5. Database-Vault asks Storage-Service to create the POSIX user on the system
    6. The response travels back up to Security-Switch
    7. Security-Switch asks Network-Manager to create a dedicated Headscale user and generate a pre-auth key for the new account
    8. The success response (HTTP 201), including the pre-auth key, travels back up the chain to the client
- **Alternative flows:**
    - validation fails at any level -> HTTP 400 and the flow stops;
    - duplicate email/key -> HTTP 409;
    - a downstream service is unreachable -> 502/503/504
- **Postconditions:** the new user exists in Database-Vault, a new POSIX User has been created on Storage-Service, the user is authenticated and able to contact Storage-Service.

### UC-02 Authentication (login)

- **Status:**
- **Actor:** Registered user
- **Preconditions:** the user already has an account in Database-Vault
- **Main flow:**
    1. The client resolves `Entry-Hub` via MagicDNS on the mesh network
    2. The client sends email and password to Entry-Hub over an HTTPS channel at `/api/login`
    3. Entry-Hub validates the field formats (email and password only) and forwards via mTLS to Security-Switch
    4. Security-Switch re-validates and forwards via mTLS to Database-Vault
    5. Database-Vault re-validates the field formats, retrieves the salt associated with the email, recomputes Argon2id with the salt and pepper, and compares the result with the stored hash
    6. The response travels back up to Security-Switch
    7. Security-Switch asks Network-Manager to grant a time-limited ACL grant for the authenticated account
    8. The response (success or failure) travels back up the chain to the client
- **Alternative flows:**
    - invalid credentials (nonexistent email or wrong password) -> HTTP 401, identical response in both cases
    - validation fails at any level -> HTTP 400 and the flow stops
    - a downstream service is unreachable -> 502/503/504
- **Postconditions:** the user is authenticated; a time-limited ACL grant exists that enables the user's mesh node to reach Storage-Service until it expires

### UC-03 Backing up a file

- **Status:**
- **Actor:** Authenticated user
- **Preconditions:**
    - The user has authenticated via the login procedure
    - The user holds the private key linked to the SSH public key sent during registration
- **Main flow:**
    1. The client resolves `Storage-Service` via MagicDNS on the mesh network (requires an active ACL grant from UC-02)
    2. The client connects via SFTP using the private key matching the registered SSH public key
    3. Storage-Service, via `AuthorizedKeysCommand`, asks Database-Vault for the user's current public key and verifies the signature
    4. If valid, the SFTP session is established inside the user's chroot (`/storage/user<xxxxxx>/data/`)
    5. The client runs `restic backup` against that directory; the data is already encrypted client-side
- **Alternative flows:**
    - the ACL grant has expired or was never granted -> the node cannot reach Storage-Service
    - the public key is no longer valid/up to date -> SFTP authentication is rejected
    - an attempt to open a non-SFTP SSH connection -> rejected (ST-F-04)
- **Postconditions:** the encrypted data is persisted in the user's isolated space.

### UC-04 Restoring a file

- **Status:**
- **Actor:** Authenticated user
- **Preconditions:** identical to UC-03
- **Main flow:**
    1. The client resolves `Storage-Service` via MagicDNS on the mesh network (requires an active ACL grant from UC-02)
    2. The client connects via SFTP using the private key matching the registered SSH public key
    3. Storage-Service, via `AuthorizedKeysCommand`, asks Database-Vault for the user's current public key and verifies the signature
    4. If valid, the SFTP session is established inside the user's chroot (`/storage/user<xxxxxx>/data/`)
    5. The client runs `restic restore` from their own directory, downloading the encrypted data and decrypting it locally
- **Alternative flows:** identical to UC-03
- **Postconditions:** the user has recovered the plaintext files only locally; Storage-Service never processed decrypted content.

### UC-05 Consulting operational metrics (Admin)

- **Status:**
- **Actor:** System administrator
- **Flow:** query on Grafana -> TimescaleDB, on raw data or hourly/daily aggregated views, filtered by service and metric name

---

## 8. Known risks and open issues

Requirements/checks knowingly deferred to a later iteration, which **do not** block the v1.0 freeze:

|**Risk ID**|**Reference**|**Description**|
|---|---|---|
|RISK-01|RU-09|RU-09 (no one can modify/delete backups) is not covered by any system requirement. It is currently out of scope due to overly tight timelines, but it is a "nice to have."|
|RISK-02|2.6, DV-F-05, DV-F-18, DV-F-19|The encryption master key resides in an environment variable (2.6), and there is not yet a binding backup procedure (DV-F-18) nor a rotation procedure (DV-F-19); both are currently "should" rather than "must." <br>Loss of the master key would cause irreversible loss of access to all encrypted data; its compromise would break the zero-knowledge guarantee for all users. <br>This is accepted as a risk for v1.0 due to time constraints.|
|RISK-03|CL-F-06, CL-F-07|The Client is currently designed to run natively on the user's own machine, not as a Docker container (docs/design/diagrams/02-architecture-deployment.puml marks it `<<external>>`). Containerizing it was considered, but rejected for now: a container cannot see arbitrary host paths (e.g. the user's Desktop) unless explicitly bind-mounted, and the set of files a user wants to back up is chosen freely at backup time, not known in advance like every other component's fixed storage paths. Revisit if containerization is later desired — the least-isolation-losing option found so far is a per-invocation bind mount of just the folder being backed up, not mounting the whole home directory.|
|RISK-04|NM-F-16|Network-Manager's own mesh node now accepts Headscale's MagicDNS (NM-F-16), so its own outbound hostname resolution (Certificate-Authority, MQTT-Broker) depends on the same ACL policy Network-Manager itself pushes to Headscale (see policy.go). If that policy is ever pushed in a broken state, Network-Manager could lose its own ability to resolve mesh hostnames, including whatever it would need to reach Headscale's admin API to correct the policy — self-healing is not guaranteed. Decided explicitly by the user on 2026-07-26, choosing the simplicity of always accepting MagicDNS over building an automated recovery path: in this failure mode, an operator resolves it manually (e.g. direct access to Headscale to fix the policy). Accepted as a risk for v1.0.|
|RISK-05|EH-F-02, EH-F-04, DV-F-12, UC-01|Registration is a public, unauthenticated endpoint that answers 201 when the submitted email is free and 409 when it is already registered (DV-F-12), so anyone can test a candidate address one request at a time. The 409 deliberately does not say *which* field collided, but a caller who submits a freshly generated (therefore unique) SSH public key has removed the only other constraint that could have caused it, so the answer is unambiguous. This is precisely the information login hides: DV-F-15 returns an identical 401 for a nonexistent email and a wrong password, with identical logs and equalized response time, and that protection was never extended to registration. Compounding it, EH-F-04 validates only the email's format and no ownership-confirmation step exists, so a probe that returns 201 actually creates the account on the probed address, which then becomes permanently unregisterable by its real owner (`email_hash` is the primary key and no deletion or administration endpoint exists). Accepted as a risk for v1.0. The mitigation is to answer identically in both cases and deliver the real outcome out of band, via a confirmation email to the submitted address; it is deferred because it requires an email-sending capability the system does not have (SMTP, confirmation tokens with expiry) and because it changes UC-01, whose pre-auth key is currently returned inside the 201 response and would have to be delivered only after confirmation. Detailed analysis in `docs/Known_Issues.md` (KI-106).|
|RISK-06|DV-F-03, DV-F-06, DV-F-13|The email lookup key is an unkeyed SHA-256 of the normalized address, while the pepper (DV-F-06) is applied only to passwords. Anyone holding a copy of the database can therefore test whether a candidate address is registered, at SHA-256 speed and over the small, guessable space of plausible email addresses; encrypting the email column (DV-F-04) does not help here, because the lookup key alone answers the question. A pepper would close this without breaking DV-F-13's login lookup: unlike a per-record salt, a single global secret keeps the digest deterministic, so the same key is recomputable at login. The correct construction would be a keyed hash (HMAC-SHA256 under the pepper), not the plain concatenation used in the password path, which is safe there only because Argon2id follows it. Distinct from RISK-05, which is an online oracle against the public API; this one is offline, against a stolen dump. Accepted as a risk for v1.0: applying it means changing DV-F-03 and DV-F-13, invalidating every stored `email_hash` (rebuildable by decrypting the email with the master key, since it is encrypted and not only hashed, so the change is reversible), and making the pepper load-bearing for record lookup and not only for password verification, which widens the consequence of losing it already described in RISK-02. Detailed analysis in `docs/Known_Issues.md` (KI-112).|

---

## 9. Traceability

> [!NOTE] Every future system requirement must be linked directly to the GitHub permalink of the code that implements it (a `blob` URL pinned to a specific commit, with the exact line range - not a merge commit), in order to maintain backward traceability (from code to requirement) and forward traceability (from requirement to code) as implementation proceeds.

| **User requirements** | **Linked system requirements**                                                                                                                                                                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RU-01                 | CL-F-01, CL-F-02, CL-F-09, <br>EH-F-02, EH-F-04, EH-F-06, EH-F-07, EH-F-09, <br>SS-F-01, SS-F-02, SS-F-03, SS-F-04, SS-F-06, SS-F-09, <br>DV-F-01, DV-F-02, DV-F-03, DV-F-04, DV-F-05, DV-F-06, DV-F-07, <br>DV-F-08, DV-F-09, DV-F-10, DV-F-11, DV-F-12, DV-F-20, <br>ST-F-06, ST-F-08, ST-F-10, <br>NM-F-08, NM-F-13 |
| RU-02                 | CL-F-03, CL-F-09, <br>EH-F-03, EH-F-05, EH-F-06, EH-F-07, EH-F-09, <br>SS-F-01, SS-F-02, SS-F-03, SS-F-04, SS-F-06, <br>DV-F-01, DV-F-02, DV-F-13, DV-F-14, DV-F-15, DV-F-20, <br>NM-F-09, NM-F-13                                                                                                            |
| RU-03                 | CL-F-04, CL-F-05, CL-F-06, <br>ST-F-01, ST-F-02, ST-F-03, ST-F-05, ST-F-07, ST-F-11, <br>NM-F-05, NM-F-09, NM-F-15,                                                                                                                                                                         |
| RU-04                 | CL-F-03, <br>NM-F-05, NM-F-06, NM-F-07, NM-F-09, NM-F-10, NM-F-11, <br>SS-F-05                                                                                                                                                                                                              |
| RU-05                 | ST-F-02, <br>RNF-SEC-01, <br>RD-01                                                                                                                                                                                                                                                          |
| RU-06                 | DV-F-03, DV-F-04, DV-F-05, DV-F-06, DV-F-07, <br>RNF-SEC-01, <br>RD-01, RD-02, RD-03                                                                                                                                                                                                        |
| RU-07                 | CL-F-04, CL-F-05, CL-F-07, <br>ST-F-01, ST-F-02, ST-F-03, ST-F-05, ST-F-07, ST-F-11                                                                                                                                                                                                         |
| RU-08                 | ST-F-05, ST-F-07, ST-F-08, <br>DV-F-09                                                                                                                                                                                                                                                      |
| RU-09                 | **None. See RISK-01**                                                                                                                                                                                                                                                                       |
| RU-10                 | MT-F-01, MT-F-02, MT-F-03, MT-F-04, <br>EH-F-10, EH-F-11, <br>SS-F-07, SS-F-08, <br>DV-F-16, DV-F-17, <br>ST-F-12, ST-F-13, <br>NM-F-17, NM-F-18, <br>CA-F-03                                                                                                                               |
