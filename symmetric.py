import os
import json
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


class symmetric_code:
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

    def generate_symmetric_key(self) -> tuple:
        """The function creates a symmetric key for asymmetric encryption algorithm.

        Args:
            length: Key length in bytes

        Returns:
            bytes: Symmetric key
        """
        symmetric_key = os.urandom(32)
        disposable_number = os.urandom(16)
        return symmetric_key, disposable_number

    def save_symmetric_key(self, key: bytes, file_name: str) -> None:
        """The function saves a symmetric key to txt file

        Args:
            key: Symmetric key
            file_name: Name of txt file
        """
        try:
            with open(file_name, 'wb') as key_file:
                key_file.write(key)
            logging.info(f' Symmetric key successfully saved to {file_name}')
        except OSError as err:
            logging.warning(
                f' Symmetric key was not saved to file {file_name}\n{err}')
            raise

    def save_nonce(self, nonce: bytes, file_name: str) -> None:
        """Saves a one-time random number

        Args:
            nonce: one-time random number
            file_name: the path where saves
        """
        try:
            with open(file_name, 'wb') as file:
                file.write(nonce)
            logging.info(f' Nonce successfully saved to {file_name}')
        except OSError as err:
            logging.error(f' Nonce was not saved to file {file_name}\n{err}')
            raise

    def symmetric_encrypt(self, key: bytes, nonce: bytes, text: bytes) -> bytes:
        """The function encrypts an input text using symmetric key


        Args:
            key: Symmetric key of symmetric encryption algorithm
            text: Text for encryption

        Returns:
            bytes: Encrypted text
        """
        padder = symmetric_padding.ANSIX923(64).padder()
        padded_text = padder.update(text) + padder.finalize()
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_text) + encryptor.finalize()
        return cipher_text

    def symmetric_decrypt(self, key: bytes, nonce: bytes,  cipher_text: bytes) -> bytes:
        """The function decrypts a symmetrical ciphertext using symmetric key

        Args:
            key: Symmetric key of symmetric encryption algorithm
            cipher_text: Encrypted text

        Returns:
            bytes: Decrypted text
        """
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()
        text = decryptor.update(cipher_text) + decryptor.finalize()
        unpadder = symmetric_padding.ANSIX923(64).unpadder()
        unpadded_text = unpadder.update(text) + unpadder.finalize()
        return unpadded_text

    def load_symmetric_key(self, file_name: str) -> bytes:
        """The function loads  a symmetric key from txt file

        Args:
            file_name: Name of txt file

        Returns:
            bytes: Symmetric key for symmetric encoding algorithm
        """
        try:
            with open(file_name, mode='rb') as key_file:
                key = key_file.read()
            logging.info(
                f' Symmetric key successfully loaded from {file_name}')
        except OSError as err:
            logging.warning(
                f' Symmetric key was not loaded from file {file_name}\n{err}')
            raise
        return key

    def load_nonce(self, file_name: str) -> bytes:
        """Reads a one-time random number

        Args:
            file_name: the path from where reads

        Returns:
            bytes: one-time random number
        """
        try:
            with open(file_name, mode='rb') as nonce_file:
                nonce = nonce_file.read()
            logging.info(
                f' Symmetric key successfully loaded from {file_name}')
        except OSError as err:
            logging.warning(
                f' Symmetric key was not loaded from file {file_name}\n{err}')
            raise
        return nonce
