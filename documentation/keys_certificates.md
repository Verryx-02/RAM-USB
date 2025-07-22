# Create a key and a self-signed certificate
## TLS
### One shot command
```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"
```

### Multi-step command
```bash
openssl req -new -newkey rsa:2024 -nodes -keyout client.key -out client.csr
openssl x509 -req -in client.csr -out client.crt -CA ca.crt -CAkey ca.key
```

<br><br><br>

## SSH
### Create a public and private keys 
```bash
ssh-keygen -t rsa -b 4096 -C "tu@email.com"
```