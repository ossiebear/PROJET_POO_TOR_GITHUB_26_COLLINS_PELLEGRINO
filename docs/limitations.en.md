# Limitations and known issues (EN)

## Incomplete features
- `OnionNode` is referenced in [onion_node_socket_v2.py](onion_node_socket_v2.py) but does not exist in this repository. The prototype cannot run as-is.
- [echo_server_socket_v2.py](echo_server_socket_v2.py) calls `self._inner.handle(...)` without initializing `_inner`.

## Cryptographic simplifications
- The server response includes the AES key in cleartext (inside JSON). This is pedagogical, not production-secure.
- The annuaire is in-memory; for separate processes you must export/import `annuaire.json`.

## Network configuration
- [socket_transport.py](socket_transport.py) has a hard-coded `HOST` (192.168.1.67) that must be adapted to your machine/LAN.
- Standalone scripts include placeholder `hote` values if you do not use [main.py](main.py).
