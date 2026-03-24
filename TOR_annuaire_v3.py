# =============================================================================
#  TOR_annuaire_v3.py  –  Annuaire de clés publiques (PKI simplifié)
#  Notions : dictionnaire Python, hashlib (fingerprint), sérialisation PEM
# =============================================================================

import base64
import hashlib
import json

class Annuaire:
    """
    Stocke des entrées {nom -> (clé_publique_PEM, fingerprint)}.
    """

    def __init__(self):
        # Dictionnaire principal  :  nom_serveur -> dict avec pem + fingerprint
        self._entrees = {}

    # Enregistrement
    # 
    def enregistrer(self, nom, cle_publique_pem):
        """
        Calcule le fingerprint SHA-256 de la clé PEM et
        stocke l'entrée dans l'annuaire.

        Paramètres
        ----------
        nom              : str  – identifiant du serveur
        cle_publique_pem : bytes – clé publique au format PEM
        """
        # Fingerprint = SHA-256 des octets PEM (pratique courante simplifiée)
        empreinte = hashlib.sha256(cle_publique_pem).hexdigest()

        self._entrees[nom] = {
            "cle_pem"     : cle_publique_pem,
            "fingerprint" : empreinte,
        }

        print(f"[Annuaire] '{nom}' enregistré.")
        print(f"           Fingerprint : {empreinte[:32]}...")

    # Consultation
    # 
    def obtenir_cle(self, nom):
        """
        Retourne (cle_publique_pem, fingerprint) pour un nom donné,
        ou (None, None) si absent.
        """
        entree = self._entrees.get(nom)  

        if entree is not None:
            return entree["cle_pem"], entree["fingerprint"]

        return None, None

    # Affichage
    # 
    def lister(self):
        """
        Affiche tous les serveurs enregistrés et leur fingerprint.
        """
        if len(self._entrees) == 0:
            print("[Annuaire] Aucune entrée.")
            return

        print("[Annuaire] ── Liste des clés publiques ──")
        for nom, donnees in self._entrees.items():
            fp = donnees["fingerprint"]
            print(f"  • {nom:20s}  fingerprint : {fp[:16]}...{fp[-8:]}")

    def sauvegarder(self, chemin_fichier):
        """
        Sauvegarde l'annuaire dans un fichier JSON.
        Les cles PEM sont encodees en base64 pour rester ASCII.
        """
        data = {
            nom: {
                "cle_pem": base64.b64encode(donnees["cle_pem"]).decode("ascii"),
                "fingerprint": donnees["fingerprint"],
            }
            for nom, donnees in self._entrees.items()
        }

        with open(chemin_fichier, "w", encoding="utf-8") as fichier:
            json.dump(data, fichier, indent=2)

    def charger(self, chemin_fichier):
        """
        Charge un annuaire depuis un fichier JSON.
        Ecrase les entrees locales si elles existent deja.
        """
        with open(chemin_fichier, "r", encoding="utf-8") as fichier:
            data = json.load(fichier)

        self._entrees = {
            nom: {
                "cle_pem": base64.b64decode(donnees["cle_pem"]),
                "fingerprint": donnees["fingerprint"],
            }
            for nom, donnees in data.items()
        }


# Instance GLOBALE – importée par TOR_client_v3.py et TOR_serveur_v3.py
# 
annuaire_global = Annuaire()
