# Utilisation (FR)

## Lanceur principal
Le fichier [main.py](main.py) expose trois modes:
- `demo`: lance serveur et client dans un seul process.
- `server`: lance uniquement le serveur.
- `client`: lance uniquement le client.

### Demo (recommande)
```bash
python main.py demo "Bonjour" "RSA protege" "QUIT"
```

Exemple de sortie (resume):
```
=== TOR Demo ===
Host: 127.0.0.1  Port: 6767  Server: ServeurEcho
[ServeurEcho] En ecoute sur 127.0.0.1:6767
[Client] Envoi : "Bonjour"
[ServeurEcho] Message recu : "Bonjour"
[Client] Reponse du serveur : "ECHO : Bonjour"
```

### Serveur seul
```bash
python main.py server --annuaire-out annuaire.json
```
- Le serveur enregistre sa cle publique dans l'annuaire global.
- Le fichier `annuaire.json` est genere pour une execution client separee.

### Client seul
```bash
python main.py client --annuaire-in annuaire.json "Salut" "QUIT"
```
- Le client charge l'annuaire, recupere la cle publique, verifie le fingerprint, puis envoie les messages.

## Notes pratiques
- `QUIT` stoppe le serveur.
- Les scripts directs [TOR_client_v3.py](TOR_client_v3.py) et [TOR_serveur_v3.py](TOR_serveur_v3.py) ont des valeurs `hote` a completer si vous les utilisez en dehors du lanceur.
