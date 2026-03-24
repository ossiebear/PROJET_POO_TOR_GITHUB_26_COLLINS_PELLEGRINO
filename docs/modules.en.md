# Module index (EN)

- [main.py](main.py) : CLI launcher (`demo`, `server`, `client`).
- [TOR_client_v3.py](TOR_client_v3.py) : RSA+AES client, send and decrypt responses.
- [TOR_serveur_v3.py](TOR_serveur_v3.py) : encrypted echo server, RSA key generation, global annuaire.
- [TOR_annuaire_v3.py](TOR_annuaire_v3.py) : simplified annuaire, JSON save/load.
- [annuaire_cles.py](annuaire_cles.py) : structured directory (DirectoryEntry, KeyDirectoryServer).
- [crypto_suites_utiles.py](crypto_suites_utiles.py) : RSA/AES/HKDF/SHA-256 primitives.
- [socket_transport.py](socket_transport.py) : TCP framing (length + payload) and `send_recv`.
- [onion_node_socket_v2.py](onion_node_socket_v2.py) : socket layer for Tor node (prototype).
- [echo_server_socket_v2.py](echo_server_socket_v2.py) : TCP echo server (prototype).
