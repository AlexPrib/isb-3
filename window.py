import sys
import logging
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import QWidget
from asymmetric import *
from symmetric import *

logger = logging.getLogger()
logger.setLevel('INFO')


DEFAULT_SETTINGS_WAY = 'files\settings.json'


class CryptoSystemGUI(QMainWindow):
    def __init__(self) -> None:
        """Setting up the application window.
        """
        super().__init__()
        self.settings_are_applied = False
        self.setWindowTitle('CryptoSystem')
        self.setGeometry(100, 100, 500, 250)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.settings_file_label = QLabel(
            'Settings file:', self.central_widget)
        self.settings_file_label.setGeometry(50, 50, 100, 30)
        self.load_settings_file_button = QPushButton(
            'Load', self.central_widget)
        self.load_settings_file_button.setGeometry(200, 50, 100, 30)
        self.load_settings_file_button.clicked.connect(
            self.init_settings)
        self.key_length_label = QLabel('Keys generation:', self.central_widget)
        self.key_length_label.setGeometry(50, 100, 100, 30)
        self.load_keys_file_button = QPushButton(
            'Generate', self.central_widget)
        self.load_keys_file_button.setGeometry(200, 100, 100, 30)
        self.load_keys_file_button.clicked.connect(self.generate_keys)
        self.encrypt_button = QPushButton('Encrypt', self.central_widget)
        self.encrypt_button.setGeometry(140, 170, 100, 30)
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.decrypt_button = QPushButton('Decrypt', self.central_widget)
        self.decrypt_button.setGeometry(260, 170, 100, 30)
        self.decrypt_button.clicked.connect(self.decrypt_text)

    def init_settings(self) -> None:
        """A function that sets up the cryptosystem by giving the user the option to choose a settings file. 
        If there is an issue opening the file, 
        the function will automatically initialize the system with the default file.
        """
        try:
            file_name, _ = QFileDialog.getOpenFileName(
                self, 'Open Settings File', '', 'Settings Files (*.json)')
            self.asymmetric_system = Asymmetric(file_name)
            self.symmetric_system = Symmetric(file_name)
            self.settings = self.symmetric_system.settings
            QMessageBox.information(
                self, 'Settings', f'Settings file loaded successfully from file {file_name}')
        except OSError as err:
            self.asymmetric_system = Asymmetric(DEFAULT_SETTINGS_WAY)
            self.symmetric_system = Symmetric(DEFAULT_SETTINGS_WAY)
            self.settings = self.symmetric_system.settings
            QMessageBox.information(
                self, 'Settings', f'The settings file failed to load from the file {file_name}.'
                f'The default path was applied.\nPath: {DEFAULT_SETTINGS_WAY}')
        finally:
            self.settings_are_applied = True

    def generate_keys(self) -> None:
        """A function that generates keys for encryption,
        then writes them to the specified path.
        """
        if self.settings_are_applied == False:
            self.init_settings()
            QMessageBox.information(
                self, 'Keys Generate', 'Settings file successfully loaded')
            return
        try:
            symmetric_key, nonce = self.symmetric_system.generate_symmetric_key()
            private_key, public_key = self.asymmetric_system.generate_asymmetric_keys()
            self.asymmetric_system.save_asymmetric_keys(
                private_key, public_key, self.settings['secret_key'], self.settings['public_key'])
            ciphered_key = self.asymmetric_system.asymmetric_encrypt(
                public_key, symmetric_key)
            ciphered_nonce = self.asymmetric_system.asymmetric_encrypt(
                public_key, nonce)
            self.symmetric_system.save_symmetric_key(
                ciphered_key, self.settings['symmetric_key'])
            self.symmetric_system.save_nonce(
                ciphered_nonce, self.settings['nonce'])
        except Exception as err:
            QMessageBox.information(
                self, 'Key Generation', f'Error: {err.__str__}')
            pass
        else:
            QMessageBox.information(self, 'File Encryption',
                                    'The keys have been generated and saved successfully')

    def encrypt_text(self) -> None:
        """A function that encrypts text.
        """
        if self.settings_are_applied == False:
            self.init_settings()
            QMessageBox.information(
                self, 'Encrypt', 'Settings file successfully loaded')
            return
        try:
            private_key = self.asymmetric_system.load_private_key(
                self.settings['secret_key'])
            cipher_key = self.symmetric_system.load_symmetric_key(
                self.settings['symmetric_key'])
            cipher_nonce = self.symmetric_system.load_nonce(
                self.settings['nonce'])
            symmetric_key = self.asymmetric_system.asymmetric_decrypt(
                private_key, cipher_key)
            nonce = self.asymmetric_system.asymmetric_decrypt(
                private_key, cipher_nonce)
            text = self.byte_read_text(self.settings['text_file'])
            cipher_text = self.symmetric_system.symmetric_encrypt(
                symmetric_key, nonce, text)
            self.byte_write_text(cipher_text, self.settings['encrypted_file'])
        except Exception as err:
            QMessageBox.information(
                self, 'Encrypt', f'Error: {err.__str__}')
            pass
        else:
            QMessageBox.information(self, 'File Encryption',
                                    'The file has been successfully encrypted')

    def decrypt_text(self) -> None:
        """A function that decrypts text.
        """
        if self.settings_are_applied == False:
            self.init_settings()
            QMessageBox.information(
                self, 'Decrypt', 'Settings file successfully loaded')
            return
        try:
            private_key = self.asymmetric_system.load_private_key(
                self.settings['secret_key'])
            cipher_key = self.symmetric_system.load_symmetric_key(
                self.settings['symmetric_key'])
            cipher_nonce = self.symmetric_system.load_nonce(
                self.settings['nonce'])
            symmetric_key = self.asymmetric_system.asymmetric_decrypt(
                private_key, cipher_key)
            nonce = self.asymmetric_system.asymmetric_decrypt(
                private_key, cipher_nonce)
            cipher_text = self.byte_read_text(self.settings['encrypted_file'])
            text = self.symmetric_system.symmetric_decrypt(
                symmetric_key, nonce,  cipher_text)
            self.byte_write_text(text, self.settings['decrypted_file'])
        except Exception as err:
            QMessageBox.information(
                self, 'Decrypt', f'Error: {err.__str__}')
            pass
        else:
            QMessageBox.information(self, 'File Decryption',
                                    'File has been successfully decrypted.')

    def byte_read_text(self, file_name: str) -> bytes:
        """Function that reads the encrypted text

        Args:
            file_name: file_name

        Returns:
            bytes: text
        """
        try:
            with open(file_name, mode='rb') as text_file:
                text = text_file.read()
            logging.info(f' Text was successfully read from file {file_name}')
        except OSError as err:
            logging.warning(f' Text was not read from file {file_name}\n{err}')
            raise
        return text

    def byte_write_text(self, text: bytes, file_name: str) -> None:
        """Function that records encrypted text

        Args:
            text: text
            file_name: file_name
        """
        try:
            with open(file_name, mode='wb') as text_file:
                text_file.write(text)
            logging.info(f' The text has been successfully written to the file {file_name}')
        except OSError as err:
            logging.warning(
                f' Text was not written to file {file_name}\n{err}')
            raise


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = CryptoSystemGUI()
    win.show()
    sys.exit(app.exec_())
