import unittest
from unittest.mock import MagicMock, patch
import string
import random
from user_interface import generate_strong_password
from connector import Connector
import logging
logging.basicConfig(level=logging.DEBUG)


class TestConnectorEncryptionDecryption(unittest.TestCase):
    def test_generate_strong_password(self):
        password = generate_strong_password()

        self.assertEqual(len(password), 12)

        self.assertTrue(any(c.islower() for c in password), "Password should contain at least one lowercase letter")
        self.assertTrue(any(c.isupper() for c in password), "Password should contain at least one uppercase letter")
        self.assertTrue(any(c.isdigit() for c in password), "Password should contain at least one digit")
        self.assertTrue(any(c in string.punctuation for c in password),
                        "Password should contain at least one special character")

    def setUp(self):
        self.connector = Connector()
        self.connector.select_algorithm("AES")
        self.password = "StrongPassword123!"
        self.test_file_data = [
            ["testfile.txt", b"Sample data to be encrypted and decrypted."]
        ]

    def generate_random_password(self):
        return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=16))

    def test_encrypt_and_decrypt(self):
        encrypt_errors, encrypted_files = self.connector.encrypt_files(self.test_file_data, self.password)

        self.assertEqual(encrypt_errors, "", f"Encryption errors occurred: {encrypt_errors}")
        self.assertTrue(len(encrypted_files) > 0, "No files were encrypted.")

        decrypt_errors, decrypted_files = self.connector.decrypt_files(encrypted_files, self.password)

        self.assertEqual(decrypt_errors, "", f"Decryption errors occurred: {decrypt_errors}")
        self.assertTrue(len(decrypted_files) > 0, "No files were decrypted.")


        original_data = self.test_file_data[0][1]
        decrypted_data = decrypted_files[0][1]
        self.assertEqual(original_data, decrypted_data, "Decrypted data does not match the original data.")




    def test_encryption_with_wrong_password(self):
        _, encrypted_files = self.connector.encrypt_files(self.test_file_data, self.password)

        wrong_password = self.generate_random_password()
        decrypt_errors, decrypted_files = self.connector.decrypt_files(encrypted_files, wrong_password)
        self.assertNotEqual(decrypt_errors, "", "Decryption succeeded with an incorrect password.")
        self.assertEqual(len(decrypted_files), 0, "Decrypted files list should be empty with wrong password.")


if __name__ == '__main__':
    unittest.main()
