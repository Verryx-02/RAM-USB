
---

Date: 21-Jul-2026 
Indexes: [[RAM-USB]]

---

**Version:** 1.4  
**Status:** Amended: container base-image policy and Storage-Service container-architecture notes added; NM-F-10, NM-F-11, NM-F-17, NM-F-18, PKI-F-01, and PKI-F-02 linked to their merged commits; NM-F-12 reworded to document how Headscale's own CLI satisfies it; CA-F-01/CA-F-02 clarified as guarantees of the underlying step-ca product 
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

RAM-USB is an n-tier client-server microservices architecture made up of 10 Docker containers.

|**Component**|**Current implementation status**|
|---|---|
|User|Done|
|Entry-Hub|Done|
|Security-Switch|Done|
|Database-Vault|Done|
|Storage-Service|In progress|
|Network-Manager|In progress|
|Mosquitto (MQTT broker)|Not started|
|Metrics-Collector|Not started|
|Metrics-Visualizer (Grafana)|Not started|
|[Certificate-Authority](https://github.com/smallstep/certificates)|In progress|

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

> [!NOTE] Container base image policy: every service's Dockerfile defaults to `gcr.io/distroless/static-debian12:nonroot` (no shell, no package manager, runs as a fixed non-root UID) rather than a general-purpose Linux base. This is the default because most services are a single static Go binary with no OS-level requirement beyond running that binary, and a minimal runtime narrows the attack surface available to anyone who reaches the process (RNF-SEC-03). `debian:bookworm-slim` is used only where a service has a genuine OS-level requirement a distroless image cannot satisfy, such as Storage-Service's need for `sshd`, POSIX user creation, and chroot (see the container-architecture note after §4.5).

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
|CL-F-01|Must autonomously generate an SSH key pair (public/private) before registration, never transmitting the private key to any system component|[Merged](https://github.com/Verryx-02/RAM-USB/commit/64a7d9ab95edc3608f4dd7e4334756addb742582)|
|CL-F-02|Following a user command, must send only the SSH public key to Entry-Hub during registration (`POST /api/register`), together with email and password|[Merged](https://github.com/Verryx-02/RAM-USB/commit/64a7d9ab95edc3608f4dd7e4334756addb742582)|
|CL-F-03|Following a user command, must re-run login (`POST /api/login`) before the 12-hour ACL grant expires, to maintain continuity of access to Storage-Service|[Merged](https://github.com/Verryx-02/RAM-USB/commit/64a7d9ab95edc3608f4dd7e4334756addb742582)|
|CL-F-04|Must configure and start Tailscale using the pre-auth key received in the registration response, in order to join the private mesh network|[Merged](https://github.com/Verryx-02/RAM-USB/commit/64a7d9ab95edc3608f4dd7e4334756addb742582)|
|CL-F-05|Must resolve Storage-Service via MagicDNS on the mesh network, without relying on static IP addresses|[Merged](https://github.com/Verryx-02/RAM-USB/commit/64a7d9ab95edc3608f4dd7e4334756addb742582)|
|CL-F-06|Following a user command, must invoke `restic backup` against Storage-Service via SFTP, authenticating with the SSH private key generated in CL-F-01|[Merged](https://github.com/Verryx-02/RAM-USB/commit/64a7d9ab95edc3608f4dd7e4334756addb742582)|
|CL-F-07|Following a user command, must invoke `restic restore` against Storage-Service via SFTP, using the same authentication method as CL-F-06|[Merged](https://github.com/Verryx-02/RAM-USB/commit/64a7d9ab95edc3608f4dd7e4334756addb742582)|
|CL-F-08|Must handle the HTTP error codes returned by Entry-Hub (400/401/403/500/502/503/504) without exposing internal system details to the end user|[Merged](https://github.com/Verryx-02/RAM-USB/commit/64a7d9ab95edc3608f4dd7e4334756addb742582)|
|CL-F-09|Following a user command, must validate email, password, and (for registration only) the SSH public key locally, using the same rules Entry-Hub enforces (EH-F-04 for registration, EH-F-05 for login), before sending `POST /api/register` or `POST /api/login`; on local validation failure, must not transmit the request|Reduces needless requests; does not replace server-side re-validation (RNF-SEC-02, RNF-SEC-03) [Merged](https://github.com/Verryx-02/RAM-USB/commit/64a7d9ab95edc3608f4dd7e4334756addb742582)|

### 4.2 Entry-Hub

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|EH-F-01|Must expose a public HTTPS health-check endpoint:<br>`POST /api/health`<br>with certificates signed by the **public** Let's Encrypt CA|The public CA is used so that Users can never reach the internal CA that certifies mTLS connections between the system's internal components. [Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-02|Must expose a public HTTPS endpoint for user registration:<br>`POST /api/register`,<br>with certificates signed by the **public** Let's Encrypt CA|[Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-03|Must expose an HTTPS endpoint<br>`POST /api/login`<br>for the authentication of registered users, reachable only by them, <br>with certificates signed by the **public** Let's Encrypt CA|[Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-04|`/api/register` must accept JSON and validate: presence of `email`, `password`, and SSH public key fields; payload size within a defined limit; no unexpected additional fields; email format (RFC 5322); password length between 8 and 128 characters; password complexity (at least 3 character categories among lowercase, uppercase, digit, symbol); the SSH public key is well-formed.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-05|`/api/login` must accept JSON and validate: presence of `email` and `password` fields; payload size within a defined limit; no unexpected additional fields; email format (RFC 5322); password length between 8 and 128 characters; password complexity (at least 3 character categories).|Same as register, but without the SSH key [Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-06|On validation failure it must:<br>- respond with HTTP 400 (Bad Request) without specifying which problem was encountered,<br>- log the issue found without identifying the user,<br>- not forward the request to any other internal service.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-07|On successful validation it must:<br>- log the validation outcome without identifying the user,<br>- forward the request to Security-Switch via mTLS,<br>- verify that the certificate **comes from a Security-Switch**,<br>- verify that the X.509 certificate is valid.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-08|Must forward Security-Switch's response back to the user|[Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-09|Must map internal errors to HTTP 400/401/500/502/503, returning sanitized messages to the client and detailed logs internally only|[Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-10|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Entry-Hub`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-11|Metrics must never contain users' personal data, only aggregated statistics|[Merged](https://github.com/Verryx-02/RAM-USB/commit/95110b1d2bf8831680212888e06ff52f342e688d)|
|EH-F-12|Must act as a reverse proxy for Headscale coordination traffic directed at Network-Manager, routing it over the private mesh network|Users who have just completed registration need to contact Network-Manager to join the private network. But I don't want that exposed to the internet. Since Entry-Hub is already exposed, I route that traffic through it too.|

---

### 4.3 Security-Switch

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|SS-F-01|Must accept only mTLS connections from clients with:<br>- `organization="EntryHub"`,<br>- a valid X.509 certificate,<br>- access to the private mesh network.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/8345069ea1541ebed9986f1873edc84976c04a2f)|
|SS-F-02|Must re-validate the received input, independently of the validation already performed by Entry-Hub|Same validation as Entry-Hub [Merged](https://github.com/Verryx-02/RAM-USB/commit/8345069ea1541ebed9986f1873edc84976c04a2f)|
|SS-F-03|On validation failure it must:<br>- respond with HTTP 400 (Bad Request) without specifying which problem was encountered,<br>- log the issue found without identifying the user,<br>- not forward the request to any other internal service.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/8345069ea1541ebed9986f1873edc84976c04a2f)|
|SS-F-04|On successful validation it must:<br>- log the validation outcome without identifying the user,<br>- forward the request to Database-Vault via mTLS, verifying that:<br>  - the certificate comes from a Database-Vault,<br>  - the X.509 certificate is valid.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/8345069ea1541ebed9986f1873edc84976c04a2f)|
|SS-F-05|After confirmation of successful authentication from Database-Vault, must request Network-Manager (over mTLS) to grant that user access to Storage-Service for 12 hours|[Merged](https://github.com/Verryx-02/RAM-USB/commit/8345069ea1541ebed9986f1873edc84976c04a2f)|
|SS-F-06|Must map errors to HTTP 400/401/403/500/502/504|[Merged](https://github.com/Verryx-02/RAM-USB/commit/8345069ea1541ebed9986f1873edc84976c04a2f)|
|SS-F-07|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Security-Switch`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/8345069ea1541ebed9986f1873edc84976c04a2f)|
|SS-F-08|Metrics must never contain users' personal data, only aggregated statistics|[Merged](https://github.com/Verryx-02/RAM-USB/commit/8345069ea1541ebed9986f1873edc84976c04a2f)|
|SS-F-09|After confirmation of successful registration from Database-Vault, must request Network-Manager (over mTLS) to create a dedicated Headscale user and generate a pre-auth key for the new account, then include that key in the response to Entry-Hub|Mirrors NM-F-08; distinct from SS-F-05, which covers the post-login ACL grant, not registration [Merged](https://github.com/Verryx-02/RAM-USB/commit/11d9e4e7d5aacb895aa297d78fe5bea0a23acc83)|

---

### 4.4 Database-Vault

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|DV-F-01|Must accept only mTLS connections from clients with:<br>- `organization="SecuritySwitch"`,<br>- a valid certificate,<br>- access to the private mesh network.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-02|Must re-validate the received input, independently of the validation already performed by Security-Switch.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-03|Must compute the SHA-256 hash of the email for indexing and as primary key, never logging the plaintext email.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-04|Must encrypt the user's email: derive a per-record encryption key from the master key with HKDF-SHA256 and a random 16-byte salt, then encrypt the email with AES-256-GCM using that derived key and a random 12-byte nonce.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-05|The master key should come from a configurable source with length validation (32 bytes)|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-06|Must hold a pepper as an environment variable|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-07|Must compute the password hash with Argon2id: memory 47104 KiB (46 MiB), 2 iterations, parallelism 1, 32-byte output, using a random per-record salt and the pepper (DV-F-06).|Stored as a single self-describing string (algorithm, cost parameters, salt, and digest together); no separate salt field is persisted. [Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-08|Must save the user record in an atomic transaction|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-09|Must ask Storage-Service to create the unique POSIX user on the server with username `user<xxxxxx>`, where `xxxxxx` are 6 random characters from a base-36 alphabet, and wait for its response|"user<xxxxxx>" all lowercase [Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-10|If POSIX user creation fails, must delete the user from the database and inform Security-Switch that user registration failed|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-11|After creating the user record and the POSIX user, must inform Security-Switch that the user was registered|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-12|Must reject (HTTP 409) registrations with an email or SSH key that already exists, without giving details about the error|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-13|During login, must retrieve the salt associated with the email via the SHA-256 hash of the email (DV-F-03)|The salt is retrieved by decoding the stored password hash (DV-F-07), not a separate stored field. [Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-14|Must recompute Argon2id on the received password using the retrieved salt and the pepper, and compare the result with the stored hash|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-15|Must respond with the same HTTP 401 status code for both a nonexistent email and an incorrect password, without distinguishing between the two cases either in the response or in the log|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-16|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Database-Vault`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-17|Metrics must never contain users' personal data, only aggregated statistics|[Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|
|DV-F-18|A master key backup procedure should exist||
|DV-F-19|A master key rotation procedure should exist||
|DV-F-20|On validation failure it must:<br>- respond with HTTP 400 (Bad Request) without specifying which problem was encountered,<br>- log the issue found without identifying the user,<br>- not forward the request to any other internal service.|Same pattern as EH-F-06/SS-F-03, added for Database-Vault [Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|

---

### 4.5 Storage-Service

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|ST-F-01|Must accept mTLS connections only from clients with:<br>- `organization="DatabaseVault"`,<br>- a valid certificate,<br>- access to the private mesh network.|Accepts both mTLS (Database-Vault) and SFTP (Users) [Merged](https://github.com/Verryx-02/RAM-USB/commit/ff3c0d637333f2ae08534eaeaa034a8096146ab3)|
|ST-F-02|Must provide upload/download of client-side-encrypted files, never processing plaintext content|Files are encrypted client-side [Merged](https://github.com/Verryx-02/RAM-USB/commit/a2c3feb0bc18330d6a157797f8962e0f73b97db8)|
|ST-F-03|Access must occur exclusively via SFTP authenticated with the user's registered SSH public key|[Merged](https://github.com/Verryx-02/RAM-USB/commit/a2c3feb0bc18330d6a157797f8962e0f73b97db8)|
|ST-F-04|Must explicitly forbid any other form of SSH connection besides SFTP|[Merged](https://github.com/Verryx-02/RAM-USB/commit/a2c3feb0bc18330d6a157797f8962e0f73b97db8)|
|ST-F-05|Each user must have an isolated storage space, not accessible by other users|[Merged](https://github.com/Verryx-02/RAM-USB/commit/a2c3feb0bc18330d6a157797f8962e0f73b97db8)|
|ST-F-06|Following a request from Database-Vault over mTLS, must create a POSIX user on the system with username `user<xxxxxx>`, where `xxxxxx` are 6 random characters from a base-36 alphabet|"user<xxxxxx>" all lowercase [Merged](https://github.com/Verryx-02/RAM-USB/commit/a2c3feb0bc18330d6a157797f8962e0f73b97db8)|
|ST-F-07|Must ensure the POSIX user can never leave their own directory|[Merged](https://github.com/Verryx-02/RAM-USB/commit/a2c3feb0bc18330d6a157797f8962e0f73b97db8)|
|ST-F-08|The created POSIX account must not have a traditional home directory or an interactive shell; the only writable space is the dedicated subdirectory inside the chroot|[Merged](https://github.com/Verryx-02/RAM-USB/commit/a2c3feb0bc18330d6a157797f8962e0f73b97db8)|
|ST-F-09|Storage-Service's sshd configuration must have `PasswordAuthentication no` and `PermitRootLogin no`, regardless of the fact that the created accounts have no password set|[Merged](https://github.com/Verryx-02/RAM-USB/commit/a2c3feb0bc18330d6a157797f8962e0f73b97db8)|
|ST-F-10|Following successful or failed creation of the POSIX user, must report the outcome back to Database-Vault.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/ff3c0d637333f2ae08534eaeaa034a8096146ab3)|
|ST-F-11|On every user SFTP connection attempt, must retrieve the user's current public key from Database-Vault via `AuthorizedKeysCommand`|[Merged](https://github.com/Verryx-02/RAM-USB/commit/a2c3feb0bc18330d6a157797f8962e0f73b97db8)|
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
|NM-F-01|Must ensure that only Entry-Hub, Database-Vault, Network-Manager, and Certificate-Authority can contact Security-Switch|[Merged](https://github.com/Verryx-02/RAM-USB/commit/b9cbff0d0f5afc7226da81c07377de98f4f207e1)|
|NM-F-02|Must ensure that only Security-Switch, Storage-Service, and Certificate-Authority can contact Database-Vault|[Merged](https://github.com/Verryx-02/RAM-USB/commit/b9cbff0d0f5afc7226da81c07377de98f4f207e1)|
|NM-F-03|Must ensure that only Security-Switch and Certificate-Authority can contact Network-Manager|[Merged](https://github.com/Verryx-02/RAM-USB/commit/b9cbff0d0f5afc7226da81c07377de98f4f207e1)|
|NM-F-04|Must ensure that all internal components of the network, except Users, can contact, and be contacted by, the Certificate-Authority over the mesh network|[Merged](https://github.com/Verryx-02/RAM-USB/commit/b9cbff0d0f5afc7226da81c07377de98f4f207e1)|
|NM-F-05|Must ensure that **only authenticated users** can see and contact Storage-Service|[Merged](https://github.com/Verryx-02/RAM-USB/commit/b9cbff0d0f5afc7226da81c07377de98f4f207e1)|
|NM-F-06|Must ensure that **registered but not authenticated Users** can see and contact only Entry-Hub|[Merged](https://github.com/Verryx-02/RAM-USB/commit/b9cbff0d0f5afc7226da81c07377de98f4f207e1)|
|NM-F-07|Must ensure that **registered and authenticated Users** can see and contact only Entry-Hub and Storage-Service|[Merged](https://github.com/Verryx-02/RAM-USB/commit/b9cbff0d0f5afc7226da81c07377de98f4f207e1)|
|NM-F-08|On request from Security-Switch, following successful registration, must create a dedicated Headscale user and generate a short-lived pre-auth key for the new account|[Merged](https://github.com/Verryx-02/RAM-USB/commit/b9cbff0d0f5afc7226da81c07377de98f4f207e1)|
|NM-F-09|After a successful login, on request from Security-Switch, must assign the user's node the ACL tag that enables reachability toward Storage-Service, and record an expiry 12 hours from that point|[[NM-F-09 empirical verification \| Verified]] [Merged](https://github.com/Verryx-02/RAM-USB/commit/b9cbff0d0f5afc7226da81c07377de98f4f207e1)|
|NM-F-10|Must periodically check recorded expiries and remove the ACL tag from expired nodes, automatically and without manual intervention|[Merged](https://github.com/Verryx-02/RAM-USB/commit/2213099b9cbdefe453c67afc43baa09b1acb0c5c)|
|NM-F-11|The expiry of every grant must be persisted, not kept only in memory, so as not to lose state if Network-Manager restarts|[Merged](https://github.com/Verryx-02/RAM-USB/commit/2213099b9cbdefe453c67afc43baa09b1acb0c5c)|
|NM-F-12|Creating pre-auth keys and managing ACL tags must be possible only from the private network|Satisfied by Headscale's own administration CLI (`docker exec` against the container, communicating over a local Unix socket with no network listener at all) - no Network-Manager code required.|
|NM-F-13|The pre-auth key serves solely to register the node as a mesh member; it does not, by itself, grant reachability toward Storage-Service||
|NM-F-14|The Headscale coordination endpoint must be reachable only from the private network||
|NM-F-15|Must configure MagicDNS with a dedicated base domain, so that Storage-Service can be resolved by all mesh nodes via a stable name rather than an IP||
|NM-F-16|Network-Manager's mesh node must not accept the DNS configuration distributed by Headscale, to avoid a circular reference in its own host's DNS resolution||
|NM-F-17|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Network-Manager`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.|[Merged](https://github.com/Verryx-02/RAM-USB/commit/2213099b9cbdefe453c67afc43baa09b1acb0c5c)|
|NM-F-18|Metrics must never contain users' personal data, only aggregated statistics|[Merged](https://github.com/Verryx-02/RAM-USB/commit/2213099b9cbdefe453c67afc43baa09b1acb0c5c)|

### 4.7 Certificate-Authority

|**ID**|**Requirement**|**Notes**|
|---|---|---|
|CA-F-01|Must guarantee that components presenting certificates for mTLS are truly who they claim to be|The private CA exists because services not exposed to the internet cannot be reached by a public CA such as Let's Encrypt. Provided by the underlying product.|
|CA-F-02|Must guarantee the issuance, rotation, revocation, and verification of mTLS certificates|Provided by the underlying product.|
|CA-F-03|Must publish metrics every minute, and only, to its dedicated MQTT topic (`metrics/Certificate-Authority`), via mTLS, verifying that:<br>- the certificate comes from an MQTT-Broker,<br>- the X.509 certificate is valid.||
|CA-F-04|Must accept a single-use bootstrap token, distributed out-of-band to each service, for issuing the initial certificate; subsequent renewals must occur via the current mTLS certificate, not via the token|[Merged](https://github.com/Verryx-02/RAM-USB/commit/d01e06c22997ff328b97786b8ae75765826fc233)|

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
|PKI-F-01|Every service must mutually authenticate with X.509 certificates issued by a [valid CA](https://github.com/smallstep/certificates)|[Merged](https://github.com/Verryx-02/RAM-USB/commit/c8239a8941c9b83728ff562cc4c0fae2be6a204c)|
|PKI-F-02|Every service must verify the certificate's `organization` field, not merely its validity|[Merged](https://github.com/Verryx-02/RAM-USB/commit/c8239a8941c9b83728ff562cc4c0fae2be6a204c)|
|PKI-F-03|A certificate rotation and revocation procedure **should** exist||
|NET-F-01|Inter-service communication must occur over the private network; the only exposed public port is Entry-Hub's, which also acts as a reverse proxy for coordination traffic toward Network-Manager||
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
|RD-04|The "fail-secure" principle applies to every component: when there is uncertainty about the validity of a request, the default is to deny access. [Merged](https://github.com/Verryx-02/RAM-USB/commit/528d2e1502ad884645a83d4e7b4c20325db5d63e)|

---

## 7. Main use cases

### UC-01 User registration

- **Status:**
- **Actor:** User
- **Preconditions:** email and SSH key not already present in Database-Vault
- **Main flow:**
    1. The client sends `POST /api/register` to Entry-Hub over HTTPS (not mTLS): email, password, SSH key
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

---

## 9. Traceability

> [!NOTE] Every future system requirement must be linked to a merge commit on GitHub, in order to maintain backward traceability (from code to requirement) and forward traceability (from requirement to code) as implementation proceeds.

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
