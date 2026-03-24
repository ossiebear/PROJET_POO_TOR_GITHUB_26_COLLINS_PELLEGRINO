# Architecture (FR)

## Vue d'ensemble
Le projet se compose de trois blocs:
1. Annuaire de cles publiques (PKI simplifiee).
2. Client/serveur echo chiffre (RSA + AES-GCM).
3. Essai de routage en oignon via sockets (prototype).

## Flux client/serveur (RSA + AES)
1. Le serveur genere une paire RSA et publie sa cle publique dans l'annuaire.
2. Le client recupere la cle publique et verifie son fingerprint SHA-256.
3. Le client genere une cle AES ephemere et chiffre le message avec AES-256-GCM.
4. Le client chiffre la cle AES avec RSA-OAEP et envoie un paquet JSON.
5. Le serveur dechiffre la cle AES (RSA), puis le message (AES-GCM).
6. Le serveur renvoie une reponse chiffree avec une nouvelle cle AES ephemere.

### Diagramme de sequence (ASCII)
```
Client           Annuaire                 Serveur
	|                 |                        |
	|---obtenir_cle-->|                        |
	|<--cle+fp--------|                        |
	|---JSON (RSA+AES)----------------------->|
	|<--reponse AES---------------------------|
```

### Diagramme de composants (ASCII)
```
	[main.py]
		 |  demo/server/client
		 v
	[Serveur] <---- TCP JSON ----> [Client]
		 |                              |
		 | enregistrer                  | obtenir_cle
		 v                              v
								 [Annuaire]
```


## Annuaire (PKI simplifiee)
- L'annuaire est un dictionnaire en memoire liant `nom -> (cle_pem, fingerprint)`.
- Le fingerprint est un SHA-256 des octets PEM.
- L'annuaire peut etre sauvegarde/charge en JSON (base64 pour PEM).

## Routage en oignon (prototype)
- Le fichier [onion_node_socket_v2.py](onion_node_socket_v2.py) propose une enveloppe socket pour un noeud Tor.
- Il s'appuie sur un objet `OnionNode` non defini dans le depot.
