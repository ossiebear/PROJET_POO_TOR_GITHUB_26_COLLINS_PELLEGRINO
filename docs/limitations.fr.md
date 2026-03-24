# Limites et points d'attention (FR)

## Fonctionnalites inachevees
- `OnionNode` est reference dans [onion_node_socket_v2.py](onion_node_socket_v2.py) mais n'existe pas dans le depot. Le prototype ne peut pas etre execute tel quel.
- [echo_server_socket_v2.py](echo_server_socket_v2.py) utilise `self._inner.handle(...)` sans initialiser `_inner`.

## Simplifications cryptographiques
- La reponse du serveur inclut la cle AES en clair (dans le JSON). C'est un choix pedagogique, pas un modele securise pour la production.
- L'annuaire est en memoire; pour des processus separes il faut exporter/importer `annuaire.json`.

## Configuration reseau
- [socket_transport.py](socket_transport.py) contient un `HOST` fixe (192.168.1.67) qui doit etre adapte a votre machine/ LAN.
- Les scripts autonomes ont des valeurs `hote` a completer si vous ne passez pas par [main.py](main.py).
