# Comprendere il Progetto RAM-USB

Questa sezione fornisce un approccio a 3 livelli per la comprensione di R.A.M.-U.S.B.  
Spazia dalla comprensione di alto livello ai dettagli implementativi, garantendo una comprensione completa sia dell'architettura di sicurezza che della sua implementazione pratica. Più precisamente:  
- Il primo livello fornisce un'overview generale e approssimativa
- Il secondo livello scende più nei dettagli ed è già sufficiente a comprendere a pieno il progetto. 
- Il terzo livello approfondisce l'implementazione   

## Livello 1: Architettura di Alto Livello (5 minuti)

Iniziate da qui per comprendere il design del sistema e i principi di sicurezza su cui si fonda.

1. **Diagramma di Flusso di Sistema**: Iniziate con il file [documentation/registration_flow.md](registration_flow.md) per visualizzare il flusso completo delle richieste. 
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
- **Implementazione**: [security-switch/middleware/mtls.go](../security-switch/middleware/mtls.go)
- **Scopo**: Gateway di sicurezza che implementa zero-trust tra Entry-Hub e Security-Switch
- **Funzionamento Step-by-Step**:
  1. **Verifica TLS**: Controlla che la connessione sia crittografata (righe 36-43)
  2. **Validazione Certificato Client**: Assicura che Entry-Hub presenti un certificato valido (righe 45-52)
  3. **Controllo Organizzazione**: Verifica che il certificato abbia organization="EntryHub" (righe 65-72)
  4. **Audit Logging**: Registra tutti i tentativi di connessione con dettagli del certificato 
  5. **Forwarding Sicuro**: Passa la richiesta all'handler dopo aver completato l'autenticazione (righe 79-82)

- **Caratteristiche di Sicurezza**:
  - **Fail-Secure**: Nega l'accesso per default
  - **Prevenzione del Man-in-the-Middle**: Solo certificati firmati dalla CA interna sono accettati. Questo controllo viene fatto durante l'handshake TLS in [security-switch/main.go](../security-switch/main.go), (riga 73). Se il middleware è stato chiamato allora sicuramente il certificato era valido. 
  - **Verifica ulteriore dell'identità**: Anche con certificato valido, deve appartenere all'organizzazione corretta
  - **Comprehensive Logging**: Ogni tentativo (successo/fallimento) viene tracciato senza esporre dati sensibili
  - **Blocco a livello di rete**: Anche se un utente malintenzionato riuscisse a superare queste misure, non potrebbe nemmeno mandare un ping ai container interni perché l'accesso è bloccato dal file ACL di Tailscale.

- **Ruolo nell'Architettura**: 
  - Implementa il "checkpoint" critico dove Entry-Hub deve dimostrare la sua identità
  - Previene che servizi esterni o compromessi raggiungano Database-Vault
  - Parte del design defense-in-depth: anche se l'Entry-Hub fosse compromesso, deve ancora presentare certificati validi

**Validazione Defense-in-Depth:**
- **Livello 1**: [entry-hub/utils/validation.go](../entry-hub/utils/validation.go) - Sanitizzazione iniziale dell'input
- **Livello 2**: [security-switch/utils/validation.go](../security-switch/utils/validation.go) - Ri-validazione nonostante la fiducia mTLS
- **Livello 3**: [database-vault/utils/validation.go](../database-vault/utils/validation.go): Validazione finale prima dello storage
- **Motivazione**: Anche se un livello è compromesso, gli altri mantengono la sicurezza. È sufficiente cambiare i certificati dei componenti non compromessi, isolare il componente compromesso e avviarne una nuova istanza su una nuova macchina virtuale grazie a ProxmoxVE.  

Le email vengono salvate in due modi: crittografate con AES e in forma di hash con SHA256. Le password invece vengono salvate sotto forma di hash calcolata con Argon2ID

**Implementazione Crittografica:**

- **Crittografia Email Non-Deterministica**: [database-vault/crypto/aes.go](../database-vault/crypto/aes.go)
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

- **Sicurezza hashing Password Memory-Hard**: [database-vault/crypto/password.go](../database-vault/crypto/password.go)
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

- **Gestione delle chiavi**: [database-vault/crypto/keys.go](../database-vault/crypto/keys.go)
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

- **MQTT Broker**: [mqtt-broker/mosquitto.conf](../mqtt-broker/mosquitto.conf) e [mqtt-broker/acl.conf](../mqtt-broker/acl.conf)
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
  - **MQTT Publisher**: [entry-hub/mqtt/publisher.go](../entry-hub/mqtt/publisher.go)
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


- **Metrics-Collector**: [metrics-collector/main.go](../metrics-collector/main.go)
  - **MQTT Subscriber**: [metrics-collector/mqtt/subscriber.go](../metrics-collector/mqtt/subscriber.go)
    - Sottoscritto a `metrics/*` per ricevere metriche da tutti i servizi
    - **Zero-Knowledge Validation** (righe 76-97): rifiuta metriche con label keys proibite (`email`, `password`, `ssh_key`, `user_id`)
    - Verifica service name consistency (topic vs metric.Service)
    - Timestamp validation per prevenire metriche future o troppo vecchie
  - **TimescaleDB Storage**: [metrics-collector/storage/timescaledb.go](../metrics-collector/storage/timescaledb.go)
    - Hypertable per ottimizzazione time-series
    - Continuous aggregates (hourly/daily) per performance
    - Retention policy automatica (30 giorni)
    - Compression per dati più vecchi di 7 giorni
  - **Admin API** (port 8446): endpoints per health check e statistiche

**Caratteristiche di Sicurezza del Sistema di Metriche**:

- **Isolamento dei Topic**: 
  - Le ACL del broker MQTT garantiscono che ogni servizio possa pubblicare esclusivamente sul proprio topic dedicato (`metrics/entry-hub`, `metrics/security-switch`, `metrics/database-vault`). 
  - Il Metrics-Collector può leggere da tutti i topic tramite `metrics/*` (permesso esplicito con `topic read`) ma non può pubblicare (negato implicitamente perché non ha permesso `write`).
  - Questo design rende impossibile per un servizio impersonare un altro o iniettare metriche fraudolente.

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


## Livello 3: Architettura di Basso Livello (90 minuti)

Seguite una richiesta di registrazione utente attraverso l'intero sistema per comprendere l'implementazione nel dettaglio.

### **User-Client -> Entry-Hub:**
- **Implementazione**: [entry-hub/handlers/register.go](../entry-hub/handlers/register.go)
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
- **Implementazione**: [security-switch/handlers/register.go](../security-switch/handlers/register.go)
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
- **Implementazione**: [database-vault/handlers/store.go](../database-vault/handlers/store.go)
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
- **Implementazione**: [database-vault/storage/postgresql/postgresql.go](../database-vault/storage/postgresql/postgresql.go)
- **Scopo**: Persistenza sicura con prepared statement e pooling connessioni
- **Flusso Transazione** (metodo `StoreUser`):
  - Controlla se la hash dell'email è già presente usando i prepared statement (righe 112-127): 
  - Controlla se la chiave SSH è già presente (righe 129-144): 
  - Inserimento con prepared statement dell'utente con i suoi attributi (righe 146-160): 
  - Commit della transazione solo se tutti i controlli passano (righe 162-166):
  - Log del successo dell'inserimento con timestamp senza dati sensibili (righe 168-174): 

- **Caratteristiche Sicurezza Database**:
  - I **Prepared Statement** impediscono attacchi basati su SQL-injection via [database-vault/storage/postgresql/queries.go](../database-vault/storage/postgresql/queries.go)
  - Il **Pooling delle connessioni** permette di gestire in maniera efficiente le transazioni riducendo il rischio di crash del database dovuto ad un numero elevato di transazioni.

- [Design Schema-ER](../database-vault/database/ER-diagram.png) per ora c'è solo la tabella Utente
  - [Struttura delle tabelle:](../database-vault/database/schema/001_create_tables.sql) 
  - [Indici per prestazioni](../database-vault/database/schema/002_create_indexes.sql): Indice su email_hash (PK) e ssh_public_key (unique)
  - [Validazione Dati](../database-vault/database/schema/004_create_constraints.sql): Vincoli a livello database per formato hash email, hash password, chiave SSH
  - [Trigger Automatici](../database-vault/database/schema/003_create_triggers.sql): Aggiornamento automatico timestamp updated_at

### **Sistema di Monitoraggio: Flusso Completo delle Metriche**

Il sistema di monitoraggio di RAM-USB rappresenta un'infrastruttura parallela che opera in modo completamente indipendente dal flusso principale delle richieste. 
Seguiamo il percorso completo di una metrica dalla sua raccolta iniziale nel servizio fino alla sua persistenza finale in TimescaleDB.

#### **Entry-Hub -> Collector Interno: Raccolta In-Memory**
- **Implementazione**: [entry-hub/metrics/collector.go](../entry-hub/metrics/collector.go)
- **Scopo**: Aggregazione in-memory di metriche operative senza impattare le performance delle richieste HTTP.  
Il collector lavora come un buffer locale che accumula statistiche prima della trasmissione periodica via MQTT.

- **Architettura del Collector**:
  - **Pattern Singleton** (righe 76-100): La funzione `Initialize()` crea una singola istanza globale `collector` condivisa da tutti gli handler. 
  Questo pattern garantisce che non ci siano duplicazioni di metriche e che tutti i goroutine accedano alla stessa struttura dati.  
  L'inizializzazione è protetta da `sync.Once` per essere thread-safe anche se chiamata da più goroutine contemporaneamente.
  
  - **Struttura Dati** (righe 19-74): Il `MetricsCollector` contiene diverse mappe per diversi tipi di metriche:
    - `requestsTotal map[string]int64`: Chiave composita "method:path:status" per tracciare ogni combinazione (es. "POST:/api/register:201", "GET:/api/health:200")
    - `requestDurations []float64`: Slice che accumula tutte le latenze in millisecondi per calcolare percentili statistici
    - `registrationsTotal map[string]int64`: Contatori separati per registrazioni "success" vs "failed"
    - `validationFailures map[string]int64`: Categorizzazione dei failure per tipo (es. "invalid_email", "weak_password")
    - `activeConnections int64`: Gauge che traccia connessioni HTTP concorrenti in tempo reale
    - `errorsTotal map[string]int64`: Categorizzazione errori interni del servizio

**Recording delle Richieste HTTP**: (righe 102-127)
- Ogni volta che `IncrementRequest(method, path, status)` viene chiamato dal middleware, vengono eseguite tre operazioni di normalizzazione:
  - **Path sanitization**: `sanitizePath(path)` rimuove parti dinamiche dall'URL per prevenire cardinalità esplosiva. Esempio: `/users/12345` diventa `/users/{id}`, altrimenti avremmo migliaia di chiavi uniche (una per ogni user ID)
  - **Status code grouping**: `fmt.Sprintf("%dxx", status/100)` raggruppa gli status code per classe. `201` diventa `2xx`, `404` diventa `4xx`, `503` diventa `5xx`. Questo è fondamentale per ridurre la cardinalità: invece di tracciare ogni singolo status code (200, 201, 202, 204...), raggruppiamo per categoria (2xx = success, 4xx = client error, 5xx = server error)
  - **Chiave composita**: Viene costruita una stringa nel formato `"method:path:statusClass"`, ad esempio `"POST:/api/register:2xx"`
- La mappa `requestsTotal` viene aggiornata atomicamente grazie al mutex lock: `collector.requestsTotal[key]++`
- **Esempio**: 
  - Se riceviamo 100 POST su `/api/register` con status `201 Created`, la chiave sarà `"POST:/api/register:2xx"` con valore `100`
  - Se riceviamo 5 POST su `/api/register` con status `400 Bad Request`, la chiave sarà `"POST:/api/register:4xx"` con valore `5`
  - Se riceviamo 2 POST su `/api/register` con status `409 Conflict`, incrementerà la stessa chiave `"POST:/api/register:4xx"` che diventerà `7`
  - Avremo quindi due entry nella mappa: una per i successi (`2xx`) e una per gli errori client (`4xx`)
- Questo approccio permette di capire quali endpoint ricevono più traffico e quale **categoria** di status code viene restituita, bilanciando utilità e efficienza di memoria.

**Recording della Latenza** (righe 129-152): 
 - `RecordRequestDuration(ms)` viene chiamato dal middleware con la durata totale della richiesta
 - Il valore viene semplicemente appeso allo slice `requestDurations`
 - In questo modo non calcoliamo statistiche ad ogni richiesta (sarebbe troppo costoso), ma accumuliamo i dati raw
 - I percentili vengono calcolati solo durante l'export periodico quando serve davvero
 - Per prevenire memory leak, quando lo slice raggiunge 10000 elementi, vengono rimossi i 5000 più vecchi mantenendo solo gli ultimi 5000

**Calcolo dei Percentili** (righe 464-484):
 - La funzione `calculatePercentile()` implementa un algoritmo semplificato che ordina lo slice e prende l'elemento alla posizione corrispondente
 - **p50 (mediana)**: Se abbiamo 1000 richieste, prendiamo l'elemento in posizione 500 -> metà delle richieste sono più veloci, metà più lente
 - **p95**: Elemento in posizione 950 → il 95% delle richieste è più veloce di questo valore, solo il 5% è più lento
 - **p99**: Elemento in posizione 990 → identifica gli outliers, le richieste più lente che potrebbero indicare problemi
 - Questi valori sono fondamentali per capire la "salute" del servizio: se p50=20ms ma p99=5000ms significa che la maggior parte degli utenti ha un'esperienza ottima, ma c'è un 1% che sperimenta rallentamenti significativi da investigare
  
**Export Periodico** (righe 243-363): 
 - `GetMetrics()` viene chiamato ogni 2 minuti dal publisher MQTT
 - Utilizza `RLock()` (read lock) perché non modifica i dati, li legge solo per serializzarli
 - Crea uno slice di `Metric` strutturati in formato Prometheus-compatible (Prometheus non viene usato, ma è un formato standard)
 - Ogni metrica include: service name, timestamp unix, metric name, valore numerico, labels opzionali, e type (counter/gauge)
 - Le mappe vengono iterate e per ogni entry viene creata una metrica separata con le label appropriate
 - Esempio: Per "POST:/api/register:201" con valore 150, viene creata una metrica con `name="requests_total"`, `value=150`, `labels={"method":"POST", "path":"/api/register", "status":"201"}`

- **Thread-Safety Critico**:
  - Il problema fondamentale qui era che più goroutine (handler HTTP) chiamano simultaneamente `IncrementRequest()` mentre il publisher MQTT chiamava `GetMetrics()`
  - Soluzione: `sync.RWMutex` permette due modalità di accesso:
    - **Read Lock** (`RLock()`): Multipli goroutine possono leggere contemporaneamente durante l'export
    - **Write Lock** (`Lock()`): Accesso esclusivo quando si modifica un contatore
  - Senza questa protezione avremmo race conditions e quindi incrementi persi e letture inconsistenti.

- **Integrazione con Middleware**: [entry-hub/middleware/metrics.go](../entry-hub/middleware/metrics.go)
  - **Wrapping delle richieste** (righe 17-63): Ogni handler HTTP viene wrappato con `MetricsMiddleware()` che agisce come una specie di proxy
  - **Tracking delle connessioni**: 
    - `UpdateActiveConnections(+1)` viene chiamato immediatamente all'inizio della richiesta
    - Il `defer` garantisce che `-1` venga chiamato quando la richiesta termina, anche in caso di panic
    - Questo ci dà una gauge real-time delle connessioni concorrenti.
  - **Misurazione della latenza**: 
    - `startTime := time.Now()` cattura il timestamp iniziale
    - L'handler originale viene eseguito normalmente
    - `duration := time.Since(startTime)` calcola il tempo totale incluso tutto: parsing JSON, validazione, chiamata mTLS al Security-Switch, risposta
    - Conversione in millisecondi per leggibilità sulle dashboard Grafana
  - **Cattura dello Status Code**: 
    - Problema: `http.ResponseWriter` non espone lo status code dopo che è stato scritto
    - Soluzione: Wrapper personalizzato `responseWriter` che intercetta la chiamata a `WriteHeader()`
    - Quando l'handler chiama `w.WriteHeader(201)`, il nostro wrapper salva `201` prima di inoltrare al ResponseWriter vero
    - Default a `200 OK` se l'handler non chiama esplicitamente WriteHeader

#### **MQTT Publisher: Trasmissione sicura**
- **Implementazione**: [entry-hub/mqtt/publisher.go](../entry-hub/mqtt/publisher.go)
- **Scopo**: Pubblicazione periodica e affidabile delle metriche aggregate verso il broker MQTT centrale, con gestione robusta di disconnessioni, retry, e graceful shutdown.

- **Initialization e TLS Setup** (righe 41-105):
  - La funzione `configureTLS()` costruisce una configurazione TLS completa:
    - Avviene la lettura del certificato della Certification Authority per validare il broker MQTT
    - `x509.NewCertPool()` crea un pool di certificati trusted
    - `AppendCertsFromPEM()` aggiunge il CA cert al pool - se fallisce significa che il file è corrotto
    - `tls.LoadX509KeyPair()` carica la coppia cert+key del publisher
    - Questo certificato ha CN=entry-hub-mqtt-publisher e Organization=EntryHubPublisher
    - `MinVersion: tls.VersionTLS13` rifiuta connessioni con TLS 1.2 o inferiore
    - `ServerName: "mqtt-broker"` specifica il CN atteso nel certificato del server per limitare MITM attacks
  
  - **MQTT Client Options** (righe 70-86):
    - `AddBroker()`: URL del broker in formato `ssl://IP:8883` dove 8883 è la porta standard MQTT+TLS
    - `SetClientID()`: Identificatore unico "entry-hub-publisher" usato dal broker per tracking e persistent sessions
    - `SetTLSConfig()`: Associa la configurazione TLS appena creata
    - `SetAutoReconnect(true)`: Abilita reconnection automatica in caso di network failure
    - `SetMaxReconnectInterval(30 * time.Second)`: Cap per il backoff esponenziale
    - `SetKeepAlive(60 * time.Second)`: Ping ogni 60s per mantenere la connessione attiva e rilevare disconnessioni
    - `SetCleanSession(false)`: Il broker mantiene lo stato della sessione anche dopo disconnect, permettendo di ricevere messaggi QoS 1 persi durante downtime

- **Publishing Loop (Il Cuore del Sistema di metriche)** (righe 186-239):
  1. **Staggered Start**: 
     - Problema: Se tutti i servizi (Entry-Hub, Security-Switch, Database-Vault) si avviano simultaneamente, diciamo alle 10:00:00, pubblicheranno tutti alle 10:00:00, 10:02:00, 10:04:00...
     - Questo crea dei picchi di carico ogni 2 minuti sul broker MQTT che deve processare tutti i messaggi insieme
     - Soluzione: `rand.Intn(60)` genera un delay casuale tra 0 e 60 secondi
     - Se Entry-Hub aspetta 23s, Security-Switch 47s, Database-Vault 12s, le pubblicazioni saranno distribuite uniformemente nel tempo
     - 2 minuti è abbastanza frequente per essere quasi real-time e abbastanza infrequente per non sovraccaricare il sistema
  
  2. **Metrics Export e Serialization**:
     - `metrics.GetMetrics()` recupera lo snapshot atomico di tutte le metriche accumulate
     - Se non ci sono metriche (slice vuoto), skip della pubblicazione per risparmiare banda
     - `json.Marshal(metricsToPublish)` converte lo slice di Metric in JSON

  3. **MQTT Publish con QoS 1** (righe 269-294):
     - **Topic**: `metrics/entry-hub` dedicato ed esclusivo per questo servizio grazie alle ACL
     - **QoS 1 (At-Least-Once Delivery)**: Livello di Quality of Service che garantisce la consegna
     - **Flow QoS 1 in dettaglio**:
       1. Publisher chiama `client.Publish()` con il messaggio
       2. Messaggio viene messo in una coda locale (in caso di network failure)
       3. Publisher invia `PUBLISH` packet al broker con un PacketID unico
       4. Broker riceve il messaggio, lo salva, e risponde con `PUBACK` contenente lo stesso PacketID
       5. Publisher riceve il `PUBACK` e rimuove il messaggio dalla coda locale
       6. Se dopo un timeout (default 10s) non arriva il PUBACK, il publisher reinvia automaticamente
     - **Possibile duplicazione**: Se il broker riceve il messaggio ma il PUBACK viene perso, il publisher reinvia lo stesso messaggio 2 volte
     - Questo è accettabile per le metriche.
     - **Retained=false**: Il messaggio non viene salvato dal broker per nuovi subscriber
     - **Token.Wait()**: Chiamata bloccante che aspetta la conferma `PUBACK` dal broker o timeout
     - Se il publish fallisce, viene loggato ma non stoppiamo il servizio, si riprova al prossimo tick

  - **Graceful Shutdown** (righe 320-356):
    - Problema: Se il servizio viene killato durante una publish, i messaggi in coda possono essere persi
    - `Disconnect(5000)`: Aspetta fino a 5000 millisecondi (5 secondi) per:
      - Completare publish in corso
      - Inviare messaggi in coda locale
      - Ricevere PUBACK pendenti
      - Chiudere connessione TCP in maniera pulita
    - Se dopo 5s ci sono ancora messaggi pendenti, vengono scartati (non vogliamo bloccare lo shutdown indefinitamente)
    - `shutdownOnce sync.Once` garantisce che Disconnect venga chiamato una sola volta anche se chiamato da più goroutine

#### **MQTT Broker: Isolamento dei Topic e Certificate-Based ACL**
- **Implementazione**: [mqtt-broker/mosquitto.conf](../mqtt-broker/mosquitto.conf) e [mqtt-broker/acl.conf](../mqtt-broker/acl.conf)
- **Scopo**: Message broker centrale che funge da hub di distribuzione sicuro per tutte le metriche, implementando isolamento topic-based e autenticazione mTLS end-to-end.

- **Configurazione TLS del Broker** (mosquitto.conf):
  - **Listener Configuration**:
    - `listener 8883`: Porta dedicata per MQTT+TLS (standard MQTT usa 1883 non criptato, noi usiamo solo 8883)
    - `protocol mqtt`: Specifica il protocollo MQTT
    - Nessun listener su porta 1883 -> impossibile connettersi senza TLS
  
  - **TLS Enforcement**:
    - `tls_version tlsv1.3`: rifiuta TLS 1.2/1.1/1.0
    - `cafile`: Path al certificato della CA che ha firmato tutti i certificati client e server
    - Durante l'handshake, il broker verifica che il certificato del client sia stato firmato da questa CA
    - Se un attacker prova a connettersi con un certificato self-signed o firmato da un'altra CA, viene immediatamente rifiutato
    - `certfile` e `keyfile`: Certificato e chiave privata del broker per autenticarsi verso i client
    - I client verificano che il certificato del broker sia firmato dalla stessa CA
    - `require_certificate true`: OBBLIGA tutti i client a presentare un certificato, no anonymous connections
    - `use_identity_as_username true`: Estrae il Common Name (CN) dal certificato e lo usa come username MQTT
    - Esempio: Se il certificato ha CN=entry-hub-mqtt-publisher, l'username MQTT diventa "entry-hub-mqtt-publisher"

- **Flusso di Autenticazione Completo**:
  1. **TLS Handshake**:
     - Client invia `ClientHello` con TLS 1.3
     - Broker risponde con `ServerHello` + certificato broker
     - Client verifica il certificato broker contro la sua CA
     - Broker richiede certificato client (`require_certificate true`)
     - Client invia il suo certificato (es. entry-hub-mqtt-publisher.crt)
     - Broker verifica il certificato client contro la sua CA
     - Se tutto OK, handshake completa e connessione è criptata

  2. **Username Extraction**:
     - Broker estrae il CN dal certificato client
     - CN="entry-hub-mqtt-publisher" diventa username MQTT
     - Questo username viene usato per le ACL rules

  3. **MQTT CONNECT**:
     - Client invia MQTT CONNECT packet
     - Broker riceve il CONNECT e ha già l'username dal certificato
     - Broker risponde con CONNACK se tutto OK

  4. **PUBLISH con ACL Check**:
     - Client prova a pubblicare su `metrics/entry-hub`
     - Broker consulta `acl.conf` cercando rules per username "entry-hub-mqtt-publisher"
     - Trova la rule: `user entry-hub-mqtt-publisher` + `topic write metrics/entry-hub`
     - ACL check PASSA -> messaggio viene accettato e inoltrato ai subscriber

- **ACL Rules: Isolamento Topic-Based** (file acl.conf):
  - **Publisher Rules**:
    - Ogni servizio ha il suo certificato dedicato con CN unico
    - Entry-Hub: `user entry-hub-mqtt-publisher` + `topic write metrics/entry-hub`
    - Security-Switch: `user security-switch-mqtt-publisher` + `topic write metrics/security-switch`
    - Database-Vault: `user database-vault-mqtt-publisher` + `topic write metrics/database-vault`
    - Notare la parola `write`: possono SOLO pubblicare, NON leggere
    - Questo previene che un servizio compromesso possa spiare le metriche di altri servizi

  - **Subscriber Rules**:
    - Metrics-Collector: `user metrics-collector-subscriber` + `topic read metrics/+`
    - Il `+` è un wildcard che matcha un singolo livello: `metrics/entry-hub`, `metrics/security-switch`, ecc.
    - Il write è implicitamente negato. Specificando solo `topic read`, il subscriber può solo leggere e non può pubblicare.
    - Metrics-Collector può SOLO leggere, MAI pubblicare
  
  - **Default Deny Rule**:
    - `user *` matcha qualsiasi username
    - `topic deny #` nega accesso a TUTTI i topic per utenti non esplicitamente listati
    - Fail-secure: Se qualcuno crea un nuovo certificato senza aggiungere ACL rules, viene automaticamente bloccato
    - Questo è il principio "default deny": tutto è vietato a meno che esplicitamente permesso

#### **Metrics-Collector Subscriber: Ricezione**
- **Implementazione**: [metrics-collector/mqtt/subscriber.go](../metrics-collector/mqtt/subscriber.go)
- **Scopo**: Sottoscrizione, ricezione e storage di tutte le metriche provenienti dai servizi distribuiti, implementando principi zero-knowledge e resilienza a network failures.

- **Initialization e Connection** (righe 40-90):
  - **TLS Configuration**: Processo identico al publisher ma con certificato subscriber
    - Carica `mqtt-subscriber.crt` con CN=metrics-collector-subscriber
    - Le ACL del broker riconoscono questo CN e permettono solo `topic read metrics/+`
  
  - **MQTT Client Options**: Configurazione ottimizzata per affidabilità
    - `SetAutoReconnect(true)`: Cruciale perché il subscriber non può permettersi di perdere metriche
    - `SetMaxReconnectInterval(30 * time.Second)`: Stesso exponential backoff dei publisher
    - `SetKeepAlive(60 * time.Second)`: Ping ogni 60s
    - **`SetCleanSession(false)`**: Questa è la feature più importante:
      - Quando `false`, il broker mantiene lo stato della sessione anche dopo disconnect
      - Se il subscriber si disconnette per 5 minuti, il broker bufferizza tutti i messaggi QoS 1 ricevuti
      - Quando il subscriber si riconnette, riceve tutti i messaggi persi durante il downtime
      - Senza questo, perderemmo 2-3 cicli di metriche durante ogni restart del Metrics-Collector
    - `SetOrderMatters(true)`: Garantisce che i messaggi vengano processati nell'ordine di ricezione

- **Topic Subscription**:
  - `onConnectHandler` viene chiamato automaticamente dopo successful connection
  - `client.Subscribe("metrics/+", 1, messageHandler)`:
    - `metrics/+`: Wildcard che matcha `metrics/entry-hub`, `metrics/security-switch`, `metrics/database-vault`
    - `1`: QoS level 1: il subscriber conferma ricezione di ogni messaggio al broker
    - `messageHandler`: Callback function invocata per ogni messaggio ricevuto
  - Il subscriber resta connesso e può fare retry della subscription se qualcosa fallisce

- **Message Processing Pipeline**:
  Ogni messaggio attraversa una pipeline di validazione rigorosa prima dello storage:
  
  1. **Metrics Tracking**: `incrementCounter(&metricsReceived)` contatore thread-safe
  
  2. **Topic Parsing e Validation**:
     - Il topic MQTT deve essere esattamente `metrics/{service_name}`
     - Split per "/" e verifica che ci siano esattamente 2 parti
     - Estrae il service name (es. "entry-hub" da "metrics/entry-hub")
     - Se il formato è sbagliato (es. "metrics/entry-hub/subTopic"), reject immediato
     - Questo previene messaggi malformati o tentativi di bypass
  
  3. **JSON Deserialization**:
     - `json.Unmarshal(msg.Payload(), &metric)` tenta di parsare il payload
     - Se il JSON è malformato o mancano campi required, unmarshal fallisce
     - Questo cattura attacchi in cui qualcuno invia payload corrotti per crashare il service
  
  4. **Service Name Consistency Check**:
     - **Questa è la validation più critica per la security**
     - Compara `metric.Service` (dal payload JSON) con `serviceName` (dal topic MQTT)
     - Questa è defense-in-depth: anche se le ACL fossero bypassate, questa validation blocca metric injection

  5. **Timestamp Validation**:
     - Verifica che `metric.Timestamp > 0`
     - Verifica che `metric.Timestamp <= now + 60` (non più di 60 secondi nel futuro)
     - Se un servizio ha il clock 5 minuti avanti, le sue metriche vengono rifiutate
     - Questo previene attacchi dove metriche con timestamp future potrebbero rendere la cosa molto confusa
  
  6. **Storage Operation**:
     - Se tutte le validazioni passano, chiamata a `storage.StoreMetric(metric)`
     - Questa è una chiamata bloccante che aspetta il commit al database
     - Se lo storage fallisce (database down, disk full), logghiamo ma NON incrementiamo `metricsRejected`
     - Il messaggio MQTT è già stato consumato, quindi il broker non lo reinvia
     - Trade-off: Preferiamo perdere alcune metriche durante db downtime piuttosto che far crashare il subscriber

- **Connection Lost Handling**:
  - `onConnectionLostHandler` viene invocato quando la connessione MQTT si interrompe
  - Il client library gestisce automaticamente il reconnect con exponential backoff
  - Durante il la disconnessione, il broker bufferizza i messaggi QoS 1 grazie a `CleanSession=false`
  - Quando la connessione si ripristina:
    1. `onConnectHandler` viene chiamato di nuovo
    2. Re-subscribe a `metrics/+`
    3. Il broker inizia a inviare i messaggi bufferizzati
    4. Il subscriber processa tutti i messaggi persi in ordine

- **Graceful Shutdown**:
  - Chiamato durante service shutdown quando riceviamo SIGTERM/SIGINT (kill<pid>/ctrl+c)
  - **Unsubscribe Esplicito**: `client.Unsubscribe("metrics/+")` informa il broker che non vogliamo più messaggi
  - Senza unsubscribe, il broker continuerebbe a bufferizzare messaggi per una sessione che non ritornerà mai
  - **Disconnect con Timeout**: `client.Disconnect(5000)` aspetta fino a 5 secondi
  - Durante questo tempo, il subscriber:
    - Finisce di processare messaggi in "volo"
    - Invia PUBACK per messaggi ricevuti
    - Chiude la connessione TCP
  - Se dopo 5s ci sono ancora operazioni pendenti, vengono forzatamente interrotte

#### **TimescaleDB Storage: Persistenza Time-Series Ottimizzata**
- **Implementazione**: [metrics-collector/storage/timescaledb.go](../metrics-collector/storage/timescaledb.go)
- **Scopo**: Persistenza efficiente e scalabile di metriche time-series utilizzando PostgreSQL con estensione TimescaleDB, implementando hypertables, compressione e retention policies automatiche.

- **Connection Pool Management**:
  - **Perché un pool?**: Creare una nuova connessione PostgreSQL costa ~10ms (handshake TCP + SSL + auth)
  - Se creassimo una connessione per ogni metrica, il sistema collasserebbe sotto carico
  - Il pool mantiene N connessioni sempre aperte e le riusa
  - Si può fare perché le metriche non sono eccessivamente 
  
  - **Pool Configuration**:
    - `MaxConns: 25`: Massimo 25 connessioni simultanee al database
    - Perché 25? Bilanciamento: 
      - Troppo poche -> waiting time per ottenere connessione dal pool
      - Troppo tante -> overhead di memoria + limite PostgreSQL (default max 100 connessioni totali)
    - `MinConns: 5`: Il pool mantiene sempre almeno 5 connessioni aperte anche se idle
    - Questo evita il "cold start" quando arriva un burst di metriche
    - `MaxConnLifetime: time.Hour`: Ogni connessione viene chiusa e ricreata dopo 1 ora
    - Previene accumulo di memory leaks o connessioni stale
    - `MaxConnIdleTime: 30 * time.Minute`: Connessioni idle > 30 min vengono chiuse
    - Riduce il carico sul database quando il traffic è basso
    - `HealthCheckPeriod: time.Minute`: Ogni minuto, il pool verifica che le connessioni siano ancora valide
    - Se una connessione è "rotta" (network partition, database restart), viene automaticamente rimossa e rimpiazzata
  
  - **Connection Establishment**:
    - `pgxpool.NewWithConfig()` crea il pool e inizia a stabilire connessioni
    - Se il database non risponde entro 10s, fallisce
    - `pool.Ping()` testa la connettività facendo una query `SELECT 1`
    - Se il ping fallisce, il pool viene chiuso e l'erroe propagato

- **Metric Storage: Singolo Insert**:
  - **Conversione e Logica i Retry**:
    - La metrica MQTT viene convertita in `types.StoredMetric` con campi aggiuntivi
    - `Time: time.Unix(metric.Timestamp, 0)`: Conversione da Unix timestamp a PostgreSQL TIMESTAMPTZ
    - `InsertedAt: time.Now()`: Timestamp di quando il Metrics-Collector ha ricevuto la metrica
    - Questo permette di misurare il "lag" tra generazione metrica e storage
  
  - **Strategia dii Retry**:
    - Prova fino a 3 volte prima di dichiarare il fallimento definitivo
    - `isRetryableError()` identifica errori:
      - "connection refused": Database è down temporaneamente
      - "deadlock": Due transazioni stanno modificando gli stessi dati (anche se non dovrebbe essere possibile in teoria con Postgre)
      - "timeout": Query ha impiegato troppo tempo
      - "too many connections": Pool è saturo
    - Per errori non-retryable (es. constraint violation, syntax error), fail immediato
    - **Exponential Backoff**: 
      - Tentativo 1 fallisce -> aspetta 100ms
      - Tentativo 2 fallisce -> aspetta 200ms (2x)
      - Tentativo 3 fallisce -> aspetta 300ms (3x)
    - Questo riduce il "retry storm" quando il database è sotto stress

- **Esecuzione dell'Insert: Flow della Transazione**:
  1. **Query Prefatta**:
     - SQL con placeholders `$1, $2, $3...` invece di stringhe concatenate
     - Previene SQL injection: Anche se `metric.Service` contenesse `'; DROP TABLE metrics; --`, verrebbe trattato come stringa normale
     - PostgreSQL compila la query una volta e la riusa -> performance boost
  
  2. **Labels Serialization**:
     - `json.Marshal(metric.Labels)` converte la mappa Go in JSON
     - PostgreSQL lo salverà come tipo JSONB (JSON Binary)
     - JSONB è indicizzabile e queryable
  
  3. **Transaction Begin**:
     - `pool.Begin()` inizia una transazione
     - Timeout di 5 secondi: se la transazione non completa entro 5s, rollback automatico
     - Grazie al `defer tx.Rollback()` se qualcosa va storto prima del commit, viene fatto un rollback
  
  4. **Exec con Parametri**:
     - `tx.Exec()` esegue l'INSERT con i parametri bound
     - I tipi Go vengono automaticamente convertiti nei tipi PostgreSQL:
       - `time.Time` -> TIMESTAMPTZ
       - `string` -> TEXT o VARCHAR
       - `float64` -> DOUBLE PRECISION
       - `[]byte` (JSON) -> JSONB
  
  5. **Commit della transazione**:
     - `tx.Commit()` rende le modifiche permanenti
     - Solo dopo il commit il record è visibile ad altre transazioni
  
  6. **Success Tracking**:
     - Incremento del contatore `metricsStored` per le statistiche

- **Batch Storage**:
  - **Quando usare batch**: Se riceviamo un burst di metriche (es. 100 messaggi MQTT in 1 secondo)
  - Invece di 100 transazioni separate, viene fatta una singola transazione con 100 INSERT
  
  - **Implementazione dei Batch**:
    - `pgx.Batch` è una struttura che accumula comandi SQL
    - `batch.Queue(query, args...)` aggiunge ogni INSERT alla batch
    - `tx.SendBatch()` invia tutti i comandi insieme al database
    - PostgreSQL esegue tutti gli INSERT in parallelo quando possibile
    - `results.Exec()` per ogni INSERT verifica che non ci siano errori
    - Singolo commit alla fine: tutto o niente (atomicità)
  
  - **Trade-off**:
    - Pro: Throughput molto superiore, meno overhead di transaction
    - Contro: Se un singolo INSERT fallisce, l'intero batch subisce un rollback
    - Per questo usiamo batch solo quando siamo sicuri che le metriche siano già validate

- **Database Schema e Ottimizzazioni TimescaleDB** ([metrics-collector/database/setup.sh](../metrics-collector/database/setup.sh)):
  - **Hypertable Creazione**:
    - `SELECT create_hypertable('metrics', 'time')`:
    - Converte una tabella normale in una hypertable partizionata automaticamente
    - Partizionamento per `time` con chunk di 7 giorni
    - **Benefici**:
      - Query che filtrano per time range toccano solo i chunk rilevanti
      - Retention policy può droppare interi chunk senza eliminare l'intera tabella
      - Chunks diversi possono essere processati da core CPU diversi










- **Aggregazioni Pre-Calcolate per le Dashboard**:
  - **Problema**: Le dashboard Grafana richiedono query come "media delle richieste per ora negli ultimi 7 giorni"
  - Senza aggregazioni: Ogni query deve scandire milioni di valori grezzi e calcolare le medie ogni volta
  - Con aggregazioni continue: Le medie sono già calcolate e salvate in tabelle dedicate
  
  - **Aggregazioni Orarie**:
    - Vista materializzata che raggruppa le metriche in intervalli di 1 ora
    - `time_bucket('1 hour', time)` arrotonda i timestamp all'inizio dell'ora (esempio: 10:23:45 diventa 10:00:00)
    - Per ogni combinazione (ora, servizio, nome_metrica, tipo_metrica) vengono calcolati:
      - `COUNT(*)`: Numero di valori in quell'ora
      - `AVG(value)`: Media aritmetica
      - `MIN(value)` e `MAX(value)`: Valori minimo e massimo
      - `percentile_cont(0.5)`: Mediana (p50)
      - `percentile_cont(0.95)`: 95° percentile
      - `percentile_cont(0.99)`: 99° percentile
    - Questi calcoli sono costosi, ma vengono eseguiti una sola volta e poi salvati
  
  - **Aggregazioni Giornaliere**:
    - Stessa logica ma con intervalli di 1 giorno
    - Utili per analisi di lungo periodo: "andamento mensile delle richieste"
    - Molto più efficienti delle aggregazioni orarie quando si visualizzano settimane o mesi
  
  - **Politiche di Aggiornamento**:
    - `add_continuous_aggregate_policy('metrics_hourly', start_offset => INTERVAL '3 hours', end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '1 hour')`
    - Significa: "Ogni ora, ricalcola le aggregazioni per il periodo tra 3 ore fa e 1 ora fa"

- **Politica di Ritenzione**:
  - `add_retention_policy('metrics', drop_after => INTERVAL '30 days')`
  - Elimina automaticamente i blocchi di dati più vecchi di 30 giorni
  - Eseguita come processo automatico giornaliero
  - **Perché 30 giorni?**:
    - Equilibrio tra costo di archiviazione e disponibilità dei dati storici
    - Per analisi di lungo periodo si usano le aggregazioni continue (che durano più a lungo)
    - I dati grezzi oltre 30 giorni servono raramente
  - **Funzionamento**: Il processo identifica i blocchi con `max(time) < NOW() - INTERVAL '30 days'` ed esegue `DROP TABLE chunk_X`
  - Molto più veloce di `DELETE FROM metrics WHERE time < ...` (che richiederebbe la scansione dell'intera tabella)

- **Politica di Compressione - Ottimizzazione dello Spazio**:
  - `add_compression_policy('metrics', compress_after => INTERVAL '7 days')`
  - I blocchi più vecchi di 7 giorni vengono compressi automaticamente
  - **Compromesso**: I dati compressi sono in sola lettura (niente UPDATE/DELETE) e più lenti da leggere
  - Per dati storici (oltre 7 giorni) questo è accettabile: si consultano raramente, il risparmio di spazio è più importante

### **Visualizzazione delle Metriche con Grafana**

Il sistema utilizza Grafana per visualizzare le metriche raccolte in TimescaleDB. 
Di seguito le query principali per creare una dashboard di monitoraggio dell'Entry-Hub.
Sono molto approssimative, è un inizio

#### **Configurazione Data Source**

- **Host**: `localhost:5432`
- **Database**: `metrics_db`
- **User**: `metrics_user`
- **SSL Mode**: `require`

#### **Query Dashboard**

##### **1. Response Time**

Visualizza i tempi di risposta delle richieste HTTP. Include i percentili p50, p95, p99 calcolati dal metrics collector.

```sql
SELECT 
    time,
    value as "Response Time"
FROM metrics 
WHERE 
    service = 'entry-hub' 
    AND metric_name = 'request_duration_milliseconds'
    AND $__timeFilter(time)
ORDER BY time
```

**Tipo di visualizzazione**: Time series  
**Unità**: milliseconds (ms)

##### **2. Total Requests**

Mostra il volume totale di richieste HTTP ricevute dall'Entry-Hub.

```sql
SELECT 
    time,
    SUM(value) as "Total Requests"
FROM metrics 
WHERE 
    service = 'entry-hub' 
    AND metric_name = 'requests_total'
    AND $__timeFilter(time)
GROUP BY time
ORDER BY time
```

**Tipo di visualizzazione**: Time series o Bar chart  
**Unità**: count

##### **3. Active Connections (Connessioni Simultanee)**

Traccia il numero di connessioni HTTP attive simultaneamente.

```sql
SELECT 
    time,
    value as "Active Connections"
FROM metrics 
WHERE 
    service = 'entry-hub' 
    AND metric_name = 'connections_active'
    AND $__timeFilter(time)
ORDER BY time
```

**Tipo di visualizzazione**: Time series o Gauge  
**Unità**: count
