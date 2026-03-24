# Architecture (EN)

## Overview
The project has three blocks:
1. Public-key directory (simplified PKI).
2. Encrypted echo client/server (RSA + AES-GCM).
3. Onion routing via sockets (prototype).

## Client/server flow (RSA + AES)
1. The server generates an RSA key pair and publishes its public key in the annuaire.
2. The client retrieves the public key and verifies its SHA-256 fingerprint.
3. The client generates an ephemeral AES key and encrypts the message with AES-256-GCM.
4. The client encrypts the AES key with RSA-OAEP and sends a JSON packet.
5. The server decrypts the AES key (RSA), then the message (AES-GCM).
6. The server returns a response encrypted with a new ephemeral AES key.

### Sequence diagram (ASCII)
```
Client           Annuaire                 Serveur
	|                 |                        |
	|---obtenir_cle-->|                        |
	|<--cle+fp--------|                        |
	|---JSON (RSA+AES)----------------------->|
	|<--AES response--------------------------|
```

### Component diagram (ASCII)
```
	[main.py]
		 |  demo/server/client
		 v
	[Serveur] <---- TCP JSON ----> [Client]
		 |                              |
		 | enregister                   | obtenir_cle
		 v                              v
								 [Annuaire]
```


## Annuaire (simplified PKI)
- The annuaire is an in-memory map of `name -> (pem, fingerprint)`.
- The fingerprint is SHA-256 of the PEM bytes.
- The annuaire can be saved/loaded as JSON (base64 for PEM).

## Onion routing (prototype)
- The [onion_node_socket_v2.py](onion_node_socket_v2.py) file wraps a Tor node with sockets.
- It relies on an `OnionNode` object that is not defined in this repository.
