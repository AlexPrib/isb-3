import json
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding

logger = logging.getLogger()
logger.setLevel('INFO')


class Asymmetric:
    def __init__(self, path: str) -> None:
        """Loading settings

        Args:
            path: the path to the json file with the settings
        """
        self.settings = None
        try:
            with open(path) as json_file:
                self.settings = json.load(json_file)
            logging.info(f'Settings file successfully loaded from file {path}')
        except OSError as err:
            logging.warning(
                f'Settings file was not loaded from file {path}\n{err}')
            raise

    def generate_asymmetric_keys(self) -> tuple:
        """The function creates an asymmetric key for an asymmetric encryption algorithm

        Returns:
            tuple: Asymmetric keys
        """
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048)
        private_key = keys
        public_key = keys.public_key()
        return private_key, public_key

    def save_asymmetric_keys(self, private_key, public_key, private_pem: str, public_pem: str) -> None:
        """Function saves a private key to pem file

        Args:
            private_key: private key for asymmetric encoding algorithm
            public_key: public key for asymmetric encoding algorithm
            private_pem: pem file for private key
            public_pem: pem file for public key
        """
        try:
            with open(private_pem, 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
            logging.info(f' Private key successfully saved to {private_pem}')
        except OSError as err:
            logging.warning(
                f' Private key was not saved to file {private_pem}\n{err}')
            raise
        try:
            with open(public_pem, 'wb') as public_out:
                public_out.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            logging.info(f' Public key successfully saved to {public_pem}')
        except OSError as err:
            logging.warning(
                f' Public key was not saved to file {public_pem}\n{err}')
            raise

    def asymmetric_encrypt(self, public_key, text: bytes) -> bytes:
        """The function applies encryption to an input text using a public key

        Args:
            public_key: public key of asymmetric encryption algorithm
            text: text for encryption

        Returns:
            bytes: encrypted text
        """
        cipher_text = public_key.encrypt(text, asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return cipher_text

    def asymmetric_decrypt(self, private_key, cipher_text: bytes) -> bytes:
        """The function performs decryption on an asymmetric ciphertext using a private key

        Args:
            private_key: private key of asymmetric encryption algorithm
            cipher_text: encrypted text

        Returns:
            bytes: decrypted text
        """
        text = private_key.decrypt(cipher_text, asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return text

    def load_private_key(self, private_pem: str) -> None:
        """The function loads a private key from pem file

        Args:
            private_pem:  Name of pem file

        Returns:
            Private key for asymmetric encoding algorithm
        """
        private_key = None
        try:
            with open(private_pem, 'rb') as pem_in:
                private_bytes = pem_in.read()
            private_key = load_pem_private_key(private_bytes, password=None)
            logging.info(
                f' Private key successfully loaded from {private_pem}')
        except OSError as err:
            logging.warning(
                f' Private key was not loaded from file {private_pem}\n{err}')
            raise
        return private_key

    def load_public_key(self, public_pem: str) -> None:
        """The function loads a public key from pem file

        Args:
            public_pem: Name of pem file

        Returns:
            Public key for asymmetric encoding algorithm
        """
        public_key = None
        try:
            with open(public_pem, 'rb') as pem_in:
                public_bytes = pem_in.read()
            public_key = load_pem_public_key(public_bytes)
            logging.info(f' Public key successfully loaded from {public_pem}')
        except OSError as err:
            logging.warning(
                f' Public key was not loaded from file {public_pem}\n{err}')
            raise
        return public_key
