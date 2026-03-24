# Index des modules (FR)

- [main.py](main.py) : lanceur CLI (modes `demo`, `server`, `client`).
- [TOR_client_v3.py](TOR_client_v3.py) : client RSA+AES, envoi et dechiffrement de reponses.
- [TOR_serveur_v3.py](TOR_serveur_v3.py) : serveur echo chiffre, generation de cle RSA, annuaire global.
- [TOR_annuaire_v3.py](TOR_annuaire_v3.py) : annuaire simplifie, enregistrement/chargement JSON.
- [annuaire_cles.py](annuaire_cles.py) : annuaire structure (DirectoryEntry, KeyDirectoryServer).
- [crypto_suites_utiles.py](crypto_suites_utiles.py) : primitives RSA/AES/HKDF/SHA-256.
- [socket_transport.py](socket_transport.py) : framing TCP (longueur + payload) et `send_recv`.
- [onion_node_socket_v2.py](onion_node_socket_v2.py) : couche socket pour noeud Tor (prototype).
- [echo_server_socket_v2.py](echo_server_socket_v2.py) : serveur echo TCP (prototype).
