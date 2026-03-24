# TOR Demo (RSA + AES)

Ce projet est une demonstration pedagogique d'un mini-flux TOR: annuaire de cles publiques, client/serveur echo chiffre, et premiers essais de routage en oignon via sockets.

## Objectifs
- Illustrer RSA-OAEP pour proteger une cle AES ephemere.
- Illustrer AES-256-GCM pour la confidentialite et l'integrite du message.
- Montrer un annuaire (PKI simplifiee) avec fingerprint SHA-256.

## Prerequis
- Python 3.x
- Paquet Python: `cryptography`

Installation rapide:
```bash
pip install cryptography
```

## Demarrage rapide
Exemples avec le lanceur:
```bash
# 1) Mode demo (serveur + client dans un seul process)
python main.py demo "Bonjour" "Test" "QUIT"

# 2) Serveur seul (genere annuaire.json)
python main.py server --annuaire-out annuaire.json

# 3) Client seul (charge annuaire.json)
python main.py client --annuaire-in annuaire.json "Salut" "QUIT"
```

Pour plus de details:
- Utilisation: [docs/usage.fr.md](docs/usage.fr.md)
- Architecture: [docs/architecture.fr.md](docs/architecture.fr.md)
- Index des modules: [docs/modules.fr.md](docs/modules.fr.md)
- Limites connues: [docs/limitations.fr.md](docs/limitations.fr.md)

## Remarques
Ce depot est destine a un contexte d'enseignement. La securite est simplifiee pour la lisibilite et la comprehension.

## Grille d'evaluation (suggestion)
- Correction fonctionnelle: le flux demo fonctionne et l'echange chiffre est coherent.
- Justification crypto: RSA-OAEP, AES-GCM, role du fingerprint SHA-256.
- Structure logicielle: separation client/serveur/annuaire, lisibilite.
- Reproductibilite: commandes de lancement claires et resultats attendus.
- Limites connues: points d'attention et simplifications assumes.
