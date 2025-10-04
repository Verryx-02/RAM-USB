# Comprendere il Progetto RAM-USB

Questa sezione fornisce un approccio a 3 livelli per la comprensione di R.A.M.-U.S.B.  
Spazia dalla comprensione di alto livello ai dettagli implementativi, garantendo una comprensione completa sia dell'architettura di sicurezza che della sua implementazione pratica. Più precisamente:  
- Il primo livello fornisce un'overview generale e approssimativa
- Il secondo livello scende più nei dettagli ed è già sufficiente a comprendere a pieno il progetto. 
- Il terzo livello approfondisce l'implementazione   

## Livello 1: Architettura di Alto Livello (5 minuti)

Iniziate da qui per comprendere il design del sistema e i principi di sicurezza su cui si fonda.

1. **Diagramma di Flusso di Sistema**: Iniziate con il file [documentation/registration_flow.md](documentation/registration_flow.md) per visualizzare il flusso completo delle richieste. 
2. **Panoramica dell'Architettura**: La natura distribuita del sistema con 4 microservizi
3. **Concetto Fondamentale**: Architettura zero-trust dove ogni servizio autentica ogni altro servizio

**Punti Chiave da Comprendere:**
- Il sistema implementa una pipeline: Client -> Entry-Hub -> Security-Switch -> Database-Vault
- **In parallelo**, ogni servizio pubblica metriche: Servizi -> MQTT Broker -> Metrics-Collector -> TimescaleDB
- Ogni servizio gira su una porta diversa (8443, 8444, 8445) e comunica tramite mTLS
- Per il momento gira tutto sullo stesso pc, senza container nè altro. Vengono usati 5 terminali. Idealmente ogni servizio dovrebbe girare su un container/VM separato.
- Le email degli utenti sono crittografate prima di essere salvate nel database con AES-256-GCM in modo da poter essere recuperate quando necessario, e sono salvate anche come hash.
- Le password sono salvate come hash calcolata con Argon2id, un algoritmo di hashing lento resistente agli attacchi brute force di GPU parallele. 
- Nessun componente singolo ha informazioni complete e le email non vengono mai loggate in chiaro, viene loggata la hash (principio **zero-knowledge**)
- Nessun componente si fida dei dati passatigli dagli altri componenti (principio **zero-trust**)
- Ogni componente valida i dati passatigli in modo rigoroso (principio di **defense-in-depth**)
- Il sistema include un'architettura di **monitoraggio** che raccoglie metriche operative da tutti i servizi
- Le metriche vengono trasmesse via **MQTT broker** e salvate in **TimescaleDB** per analisi time-series. Vengono poi visualizzate grazie a Grafana.
- Il sistema di metriche segue gli stessi principi **zero-knowledge**: nessun dato utente nelle metriche, solo statistiche aggregate
- **Metrics-Collector** riceve e valida le metriche.



## Livello 2: Architettura di Medio Livello (30 minuti)

Esaminate i meccanismi di sicurezza che proteggono i dati degli utenti e prevengono accessi non autorizzati:

**Autenticazione Mutual TLS:**
- **Implementazione**: [security-switch/middleware/mtls.go](security-switch/middleware/mtls.go)
- **Scopo**: Gateway di sicurezza che implementa zero-trust tra Entry-Hub e Security-Switch
- **Funzionamento Step-by-Step**:
  1. **Verifica TLS**: Controlla che la connessione sia crittografata (righe 36-43)
  2. **Validazione Certificato Client**: Assicura che Entry-Hub presenti un certificato valido (righe 45-52)
  3. **Controllo Organizzazione**: Verifica che il certificato abbia organization="EntryHub" (righe 65-72)
  4. **Audit Logging**: Registra tutti i tentativi di connessione con dettagli del certificato 
  5. **Forwarding Sicuro**: Passa la richiesta all'handler dopo aver completato l'autenticazione (righe 79-82)

- **Caratteristiche di Sicurezza**:
  - **Fail-Secure**: Nega l'accesso per default
  - **Prevenzione del Man-in-the-Middle**: Solo certificati firmati dalla CA interna sono accettati. Questo controllo viene fatto durante l'handshake TLS in [security-switch/main.go](security-switch/main.go), (riga 73). Se il middleware è stato chiamato allora sicuramente il certificato era valido. 
  - **Verifica ulteriore dell'identità**: Anche con certificato valido, deve appartenere all'organizzazione corretta
  - **Comprehensive Logging**: Ogni tentativo (successo/fallimento) viene tracciato senza esporre dati sensibili
  - **Blocco a livello di rete**: Anche se un utente malintenzionato riuscisse a superare queste misure, non potrebbe nemmeno mandare un ping ai container interni perché l'accesso è bloccato dal file ACL di Tailscale.

- **Ruolo nell'Architettura**: 
  - Implementa il "checkpoint" critico dove Entry-Hub deve dimostrare la sua identità
  - Previene che servizi esterni o compromessi raggiungano Database-Vault
  - Parte del design defense-in-depth: anche se l'Entry-Hub fosse compromesso, deve ancora presentare certificati validi

**Validazione Defense-in-Depth:**
- **Livello 1**: [entry-hub/utils/validation.go](entry-hub/utils/validation.go) - Sanitizzazione iniziale dell'input
- **Livello 2**: [security-switch/utils/validation.go](security-switch/utils/validation.go) - Ri-validazione nonostante la fiducia mTLS
- **Livello 3**: [database-vault/utils/validation.go](database-vault/utils/validation.go): Validazione finale prima dello storage
- **Motivazione**: Anche se un livello è compromesso, gli altri mantengono la sicurezza. È sufficiente cambiare i certificati dei componenti non compromessi, isolare il componente compromesso e avviarne una nuova istanza su una nuova macchina virtuale grazie a ProxmoxVE.  

Le email vengono salvate in due modi: crittografate con AES e in forma di hash con SHA256. Le password invece vengono salvate sotto forma di hash calcolata con Argon2ID

**Implementazione Crittografica:**

- **Crittografia Email Non-Deterministica**: [database-vault/crypto/aes.go](database-vault/crypto/aes.go)
  - **Processo Step-by-Step**:
    1. **Generazione del salt** (righe 83-88): 16 bytes crittograficamente sicuri per ogni utente
    2. **Derivazione della chiave** (righe 90-100): HKDF-SHA256(MasterKey + Salt + Context) -> chiave AES-256 unica
    3. **Generatione del nonce** (righe 102-107): 12 bytes random per ogni operazione di crittografia
    4. **Crittazione con AES-256-GCM** (righe 120-122): Crittografia autenticata con integrity check
    5. **Formato di Storage**: nonce + ciphertext + auth_tag -> base64 per database
  
  - **Garanzie di Sicurezza**:
    - **Non-Deterministica**: Stessa email produce cifratura diversa ogni volta (salt + nonce random)
    - **Derivazione della chiave**: La chiave viene derivata su richiesta, non viene mai salvata ed è diversa per ogni email
    - **Protezione di integrità**: GCM mode previene manomissioni del ciphertext
    - **Indicizzazione Zero-Knowledge**: SHA-256 hash delle email per query veloci senza esporre nulla in chiaro

- **Sicurezza hashing Password Memory-Hard**: [database-vault/crypto/password.go](database-vault/crypto/password.go)
  - **Algoritmo**: Argon2id con parametri resistance-tuned
    - **Costo in termini di memoria**: 32MB (lo standard è 64MB, ne vengono usati 32 per facilitare il testing)
    - **Costo in termini di tempo**: 1 iterazione (lo standard è 2 o 3. Ne viene usato 1 per motivi di testing)
    - **Parallelismo**: 4 thread - sfrutta CPU multi-core
    - **Lunghezza dell'output**: 32 bytes (256 bit) per robustezza crittografica
  
  - **Protezioni Specifiche**:
    - **Anti-GPU**: Memory-hard design rende gli attacchi GPU economicamente svantaggiosi
    - **Anti-ASIC**: Argon2id è resistente anche ad hardware specializzato
    - **Anti-Rainbow Table**: Viene usato un salt crittograficamente sicuro (16 bytes) per ogni password. Anche se la password è debole, viene "rinforzata" dal salt
    - **Anti Timing Attack**: Comparazione constant-time in VerifyPassword (righe 81-90) impedisce ad un attaccante di sapere quanti caratteri della hash sono corretti. Va migliorata

- **Gestione delle chiavi**: [database-vault/crypto/keys.go](database-vault/crypto/keys.go)
  - **Derivazione HKDF-SHA256**: Context separato per operazioni diverse (`"email-encryption-secure-v1"`)
  - **Validazione robusta**: Controllo dell'entropia, ricerca di pattern, verifica della lunghezza (Sono controlli basilari, vanno migliorati)
  - **Pulizia della memoria**: SecureKeyCleanup() sovrascrive chiavi in memoria con pattern multipli per prevenire furti della chiave dalla memoria
  - **Opzioni di fallback per ottenere la chiave**: Variabile di Ambiente -> File system -> Development generation (righe 74-106)

- **Architettura Zero-Knowledge**:
  - **Master Key**: Unico segreto critico (Per il momento Variabile di Ambiente. Idealmente serve un gestore delle password, ma per ora va bene così)
  - **Chiavi derivate**: Mai salvate
  - **Hashing dell'email**: SHA-256 per le query SQL senza usare email in chiaro

**Sistema di Monitoraggio MQTT:**

Il sistema implementa un'architettura di monitoraggio distribuito basata su MQTT per raccogliere metriche operative da tutti i servizi mantenendo i principi zero-knowledge.

- **MQTT Broker**: [mqtt-broker/mosquitto.conf](/mqtt-broker/mosquitto.conf) e [mqtt-broker/acl.conf](../mqtt-broker/acl.conf)
  - **Scopo**: Message broker centrale per distribuzione sicura delle metriche
  - **Autenticazione**: mTLS obbligatorio per tutti i client (publisher e subscriber)
  - **Controllo Accessi Topic-Based**:
    - Ogni servizio può pubblicare **solo** sul proprio topic (`metrics/entry-hub`, `metrics/security-switch`, `metrics/database-vault`)
    - Metrics-Collector può leggere da `metrics/*` ma **non** pubblicare
    - Isolamento completo: nessun servizio può leggere o scrivere sui topic altrui
  - **Configurazione**:
    - TLS 1.3 enforced (mosquitto.conf righe 25-27)
    - Certificate-based authentication con validazione CA (mosquitto.conf righe 29-46)
    - ACL rules per publisher/subscriber isolation (acl.conf righe 52-59)

- **Metrics Collection nei Servizi**: Ogni servizio (Per ora solo Entry-Hub, ma idealmente anche gli altri) implementa:
  - **Collector interno**: [entry-hub/metrics/collector.go](../entry-hub/metrics/collector.go)
    - Raccoglie metriche in-memory: requests, latency, errors, registrations
    - **Zero-Knowledge**: nessun campo per user data, solo statistiche aggregate
    - **Thread-Safety con Mutex RWLock**:
      - Visto che più richieste HTTP simultanee chiamano `IncrementRequest()` contemporaneamente, viene utilizzato `sync.RWMutex`. In questo modo:
        - Sono permesse multiple letture concorrenti (RLock) quando si esportano metriche verso MQTT
        - Viene imposta la scrittura esclusiva (Lock) quando si incrementano contatori
    
    - **Analisi della latenza con percentili**:
      - **p50 (mediana)**: 50% delle richieste sono più veloci di questo valore → "latenza tipica"
      - **p95**: 95% delle richieste sono più veloci → identifica problemi di performance
      - **p99**: 99% delle richieste sono più veloci → rileva outliers e casi peggiori possibili
      - **Esempio pratico**: Se p50=20ms, p95=80ms, p99=300ms → il 99% degli utenti ha risposta entro 300ms, ma c'è un 1% che sperimenta rallentamenti da investigare
      - **Utilizzo**: Questi dati vengono graficati sulla dashboard Grafana per il monitoraggio real-time e alerting
  - **MQTT Publisher**: [entry-hub/mqtt/publisher.go](entry-hub/mqtt/publisher.go)
    - **Publishing Schedule (ogni 2 minuti)**:
      - Intervallo di pubblicazione: 120 secondi tra ogni invio di metriche
      - **Perché non più frequente**: Bilanciamento tra visibilità real-time e carico sul broker MQTT
      - **Perché non meno frequente**: 2 minuti garantisce detection rapida di problemi (es. spike di errori)
      - Ogni pubblicazione invia uno snapshot completo delle metriche accumulate dall'ultimo invio
    
    - **Staggered Start (Random Delay 0-60 secondi)**:
      - **Problema**: Se tutti i servizi (Entry-Hub, Security-Switch, Database-Vault) partono simultaneamente, inviano metriche allo stesso istante ogni 2 minuti
      - **Conseguenza**: Il broker MQTT riceve troppi messaggi simultanei creando picchi di carico
      - **Soluzione**: Ogni servizio aspetta un delay casuale (0-60s) prima di iniziare il loop di pubblicazione. In questo modo le pubblicazioni sono distribuite uniformemente nel tempo
      - **Implementazione**: `time.Sleep(time.Duration(rand.Intn(60)) * time.Second)` all'avvio del publisher
    
    - **Riconnessione automatica con backoff esponenziale**:
      - Cosa succede quando il broker MQTT è temporaneamente irraggiungibile
      - **Strategia di Reconnection**:
        1. **Primo tentativo**: Attende 1 secondo e riprova
        2. **Secondo tentativo**: Attende 2 secondi (2^1)
        3. **Terzo tentativo**: Attende 4 secondi (2^2)
        4. **Quarto tentativo**: Attende 8 secondi (2^3)
        5. **Max backoff**: Cap a 60 secondi per evitare attese eccessivamente lunghe
      - In questo modo si evita che centinaia di client provino a riconnettersi ogni millisecondo, sovraccaricando il broker appena riavviato
    
    - **QoS 1 (At-Least-Once Delivery)**:
      - **Livelli QoS disponibili in MQTT**:
        - **QoS 0** (At-Most-Once): "Fire and forget": nessuna garanzia, può perdere messaggi
        - **QoS 1** (At-Least-Once): Garantisce la consegna ma con possibili duplicati
        - **QoS 2** (Exactly-Once): Garanzia assoluta ma overhead maggiore
      - **Flow QoS 1**:
        1. Publisher invia `PUBLISH` message al broker
        2. Broker salva il messaggio e risponde con `PUBACK`
        3. Publisher marca messaggio come consegnato
        4. Se non riceve nessun `PUBACK` entro il tempo di timeout, il publisher reinvia automaticamente
    
    - **Message Format & Topic Strategy**:
      - **Topic dedicato per servizio**: `metrics/entry-hub`, `metrics/security-switch`, `metrics/database-vault`
      - **Payload JSON**: Serializzazione di `types.Metric` con campi: `service`, `timestamp`, `name`, `value`, `labels`, `type`
      - **mTLS Authentication**: Ogni publisher usa un certificato dedicato (`mqtt-publisher.crt`) validato dal broker tramite ACL
      - **ACL Enforcement**: Il publisher può scrivere SOLO sul proprio topic


- **Metrics-Collector**: [metrics-collector/main.go](metrics-collector/main.go)
  - **MQTT Subscriber**: [metrics-collector/mqtt/subscriber.go](metrics-collector/mqtt/subscriber.go)
    - Sottoscritto a `metrics/*` per ricevere metriche da tutti i servizi
    - **Zero-Knowledge Validation** (righe 76-97): rifiuta metriche con label keys proibite (`email`, `password`, `ssh_key`, `user_id`)
    - Verifica service name consistency (topic vs metric.Service)
    - Timestamp validation per prevenire metriche future o troppo vecchie
  - **TimescaleDB Storage**: [metrics-collector/storage/timescaledb.go](metrics-collector/storage/timescaledb.go)
    - Hypertable per ottimizzazione time-series
    - Continuous aggregates (hourly/daily) per performance
    - Retention policy automatica (30 giorni)
    - Compression per dati più vecchi di 7 giorni
  - **Admin API** (port 8446): endpoints per health check e statistiche

**Caratteristiche di Sicurezza del Sistema di Metriche**:

- **Isolamento dei Topic**: 
  - Le ACL del broker MQTT garantiscono che ogni servizio possa pubblicare esclusivamente sul proprio topic dedicato (`metrics/entry-hub`, `metrics/security-switch`, `metrics/database-vault`). 
  - Il Metrics-Collector può leggere da tutti i topic tramite `metrics/*` ma non può pubblicare. 
Questo design rende impossibile per un servizio impersonare un altro o iniettare metriche fraudolente.

- **mTLS End-to-End**: Broker, publisher e subscriber utilizzano autenticazione basata su certificati X.509. Forse è un pò Over Power per un sistema di metriche, ma va bene così. 

- **Autenticazione del Servizio**: Le metriche sono validate confrontando il campo `metric.Service` con il topic MQTT di provenienza. 
Se una metrica dichiara `service: "entry-hub"` ma in qualche modo arriva su `metrics/security-switch`, viene automaticamente rifiutata per prevenire metric injection.

- **Storage Immutabile**: I dati time-series in TimescaleDB seguono semantica append-only. Nessuna operazione di UPDATE o DELETE è consentita manualmente. La rimozione dei vecchi dati (oltre 30 giorni) avviene esclusivamente tramite retention policy automatica, preservando l'integrità storica.

- **Audit Trail Completo**: Tutte le connessioni MQTT e i validation failures sono registrati con dettagli su chi si connette, quando, con quale certificato, e perché una metrica è stata rifiutata.

**Ruolo nell'Architettura**:

Il sistema di metriche svolge quattro funzioni critiche nell'ecosistema R.A.M.-U.S.B.:

- **Visibilità Operativa**: Le dashboard Grafana mostrano metriche aggregate. 

- **Analisi delle Performance**: Tracciamento di latenza delle richieste (p50, p95, p99), tassi di errore e throughput per identificare colli di bottiglia.

- **Monitoraggio della Sicurezza**: Detection precoce di attacchi attraverso l'analisi di pattern anomali: burst improvvisi di 401 Unauthorized, anomalie nel traffico mTLS (tentativi di man-in-the-middle) e molto altro.

- **Capacity Planning**: Monitoraggio continuo di connessioni attive, carico del database e utilizzo delle risorse hardware. Questi dati permettono di prevedere quando scalare l'infrastruttura e forniscono metriche concrete per il dimensionamento ottimale.


## Livello 3: Architettura di Basso Livello (50 minuti)

Seguite una richiesta di registrazione utente attraverso l'intero sistema per comprendere l'implementazione nel dettaglio.

### **User-Client -> Entry-Hub:**
- **Implementazione**: [entry-hub/handlers/register.go](entry-hub/handlers/register.go)
- **Scopo**: Punto di ingresso pubblico che riceve richieste HTTPS dai client e le inoltra via mTLS al Security-Switch
- **Flusso di Esecuzione**:
  1. **Controllo delle Richieste** (righe 41-43): logging dell'IP e metodo HTTP
  2. **Controllo Metodo HTTP** (righe 49-53): Accetta solo richieste POST
  3. **Elaborazione JSON** (righe 55-67): Lettura della richiesta e parsing del JSON
  4. **Validazione dei dati ricevuti** (righe 69-123): Validazione completa dell'input utente
  5. **Registrazione Zero-Knowledge** (riga 126): `emailHash := utils.HashEmail(req.Email)` per log senza esporre le email in chiaro
  6. **Configurazione Client mTLS** (righe 128-157): Inizializzazione client con certificati per Security-Switch
  7. **Inoltro della richiesta verso il Security-Switch** (righe 159-188): `securityClient.ForwardRegistration(req)`

### **Entry-Hub -> Security-Switch:**
- **Implementazione**: [security-switch/handlers/register.go](security-switch/handlers/register.go)
- **Scopo**: Il Security-Switch fa da centro di controllo. Implementa defense-in-depth e zero-trust ed inoltra la richiesta verso il Database-Vault
- **Implementazione Difesa in Profondità**:
  1. **Ri-controllo Metodo** (righe 41-43): Ri-verifica POST nonostante il mTLS
  2. **Ri-elaborazione JSON** (righe 45-57): Riprocessa tutto da zero, non si fida dell'Entry-Hub
  3. **Ri-validazione Completa** (righe 59-113): Validazione identica all'Entry-Hub 
  4. **Configurazione Client Database-Vault** (righe 118-147): Inizializzazione client con certificati per Database-Vault
  5. **Inoltro Sicuro** (righe 149-175): `dbClient.StoreUserCredentials(req)` verso Database-Vault
  6. **Validazione Risposta** (righe 177-184): Verifica risposta Database-Vault + inoltro errori

- **Garanzie di Sicurezza**:
  - **Architettura Zero-Trust**: Assume che l'Entry-Hub potrebbe essere compromesso
  - **Validazione Identica**: Stessi controlli del livello precedente per coerenza
  - **Catena Certificati**: Verifica `organization="SecuritySwitch"` per Database-Vault
  - **Isolamento Errori**: Categorizza errori senza esporre dati degli utenti e dettagli interni

- **Ruolo nell'Architettura**:
  - **Perimetro di Sicurezza**: Il Security-Switch separa il Database-Vault dal punto di ingresso per gli utenti, fungendo da barriera aggiuntiva nel caso in cui l'Entry-Hub dovesse essere compromesso. 
L'idea è di tenere il database più lontano possibile dagli utenti, infatti gira su una macchina virtuale separata, non direttamente raggiungibile dall'Entry-Hub

### **Security-Switch -> Database-Vault:**
- **Implementazione**: [database-vault/handlers/store.go](database-vault/handlers/store.go)
- **Scopo**: Layer finale di archiviazione con crittografia email e hashing password prima della persistenza
- **Processo di Archiviazione Crittografica**:
  1. **Validazione Finale** (righe 68-160): Terza validazione identica (ultimo controllo)
  2. **Verifica disponibilità del Database-Vault** (righe 162-168): Verifica che userStorage sia inizializzato correttamente. 
  3. **Caricamento Chiave Crittografia** (righe 170-177): Carica la chiave AES-256 per crittografare l'email
  4. **Elaborazione Crittografica Email** (righe 184-192):
     - `emailHash := crypto.HashEmail(req.Email)` (SHA-256 per indicizzazione veloce)
     - `encryptedEmail, emailSalt, err := crypto.EncryptEmailSecure(req.Email, cfg.EncryptionKey)` (AES-256-GCM non-deterministico)
  5. **Prevenzione Duplicati** (righe 194-222): Controllo hash email e chiave SSH per unicità
  6. **Elaborazione Sicurezza Password** (righe 224-236): Generazione salt + hashing Argon2id
  7. **Transazione Database** (righe 238-279): Archiviazione in PostgreSQL

### **Database PostgreSQL:**
- **Implementazione**: [database-vault/storage/postgresql/postgresql.go](database-vault/storage/postgresql/postgresql.go)
- **Scopo**: Persistenza sicura con prepared statement e pooling connessioni
- **Flusso Transazione** (metodo `StoreUser`):
  - Controlla se la hash dell'email è già presente usando i prepared statement (righe 112-127): 
  - Controlla se la chiave SSH è già presente (righe 129-144): 
  - Inserimento con prepared statement dell'utente con i suoi attributi (righe 146-160): 
  - Commit della transazione solo se tutti i controlli passano (righe 162-166):
  - Log del successo dell'inserimento con timestamp senza dati sensibili (righe 168-174): 

- **Caratteristiche Sicurezza Database**:
  - I **Prepared Statement** impediscono attacchi basati su SQL-injection via [database-vault/storage/postgresql/queries.go](database-vault/storage/postgresql/queries.go)
  - Il **Pooling delle connessioni** permette di gestire in maniera efficiente le transazioni riducendo il rischio di crash del database dovuto ad un numero elevato di transazioni.

- [Design Schema-ER](database-vault/database/ER-diagram.png) per ora c'è solo la tabella Utente
  - [Struttura delle tabelle:](database-vault/database/schema/001_create_tables.sql) 
  - [Indici per prestazioni](database-vault/database/schema/002_create_indexes.sql): Indice su email_hash (PK) e ssh_public_key (unique)
  - [Validazione Dati](database-vault/database/schema/004_create_constraints.sql): Vincoli a livello database per formato hash email, hash password, chiave SSH
  - [Trigger Automatici](database-vault/database/schema/003_create_triggers.sql): Aggiornamento automatico timestamp updated_at
