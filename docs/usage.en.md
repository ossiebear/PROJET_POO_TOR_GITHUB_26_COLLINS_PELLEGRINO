# Usage (EN)
## Main launcher
The [main.py](main.py) file exposes three modes:
- `demo`: starts server and client in one process.
- `server`: starts the server only.
- `client`: starts the client only.

### Demo (recommended)
```bash
python main.py demo "Hello" "RSA protects" "QUIT"
```

Example output (summary):
```
=== TOR Demo ===
Host: 127.0.0.1  Port: 6767  Server: ServeurEcho
[ServeurEcho] En ecoute sur 127.0.0.1:6767
[Client] Envoi : "Hello"
[ServeurEcho] Message recu : "Hello"
[Client] Reponse du serveur : "ECHO : Hello"
```

### Server only
```bash
python main.py server --annuaire-out annuaire.json
```
- The server registers its public key in the global annuaire.
- The `annuaire.json` file is created for a separate client run.

### Client only
```bash
python main.py client --annuaire-in annuaire.json "Hi" "QUIT"
```
- The client loads the annuaire, retrieves the public key, verifies the fingerprint, and sends messages.

## Practical notes
- `QUIT` stops the server.
- The standalone scripts [TOR_client_v3.py](TOR_client_v3.py) and [TOR_serveur_v3.py](TOR_serveur_v3.py) include placeholder `hote` values if used outside the launcher.
