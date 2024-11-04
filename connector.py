from encryption_decryption_interface import EncryptionDecryptionInterface
from rc4_algorithm import RC4Algorithm
from aes_algorithm import AESAlgorithm


class Connector:
    def __init__(self):
        self.algorithms = [["RC4", True, RC4Algorithm()], ["AES", True, AESAlgorithm()]]
        self.algorithm = None
        self.TECHNICAL_INFO_LENGTH = 10000
        self.MAX_SIZE = 1024 * 1024 * 1024  # 1 GB in bytes

    def select_algorithm(self, name):
        for el in self.algorithms:
            if el[0] == name:
                self.algorithm = el
                break

    def get_algorithms(self):
        lst_algorithms = []
        for el in self.algorithms:
            lst_algorithms.append(el[0])
        return lst_algorithms

    def technical_bytes_write(self, s):
        byte_data = s.encode('utf-8')
        if len(byte_data) < self.TECHNICAL_INFO_LENGTH:
            byte_data += b'\x00' * (self.TECHNICAL_INFO_LENGTH - len(byte_data))
        elif len(byte_data) > self.TECHNICAL_INFO_LENGTH:
            byte_data = byte_data[:self.TECHNICAL_INFO_LENGTH]
        return byte_data

    def technical_bytes_read(self, b):
        return b.rstrip(b'\x00').decode('utf-8')

    def configure_technical_info(self, filename):
        technical_info = ""
        technical_info += filename+"\n"
        technical_info += self.algorithm[0]+"\n"
        return technical_info

    def read_technical_info(self, s):
        return self.technical_bytes_read(s).split("\n")

    def encrypt_files(self, files_data, password):
        errors = ""
        encrypted_files = []
        for file in files_data:
            encrypted_bytes = ""
            encrypted_keys = ""
            try:
                encrypted_keys, encrypted_bytes = self.algorithm[2].encrypt_bytes(file[1], password)
            except Exception as e:
                errors += str(e)+"\n"
                continue
            new_file_name = file[0].split(".")[0].strip()+".bin"
            tech_info = self.technical_bytes_write(self.configure_technical_info(file[0])+encrypted_keys)
            encrypted_files.append([new_file_name, tech_info + encrypted_bytes])
        return errors, encrypted_files

    def decrypt_files(self, files_data, password):
        errors = ""
        decrypted_files = []
        for file in files_data:
            technical_bytes = file[1][:self.TECHNICAL_INFO_LENGTH]
            tech_info = self.read_technical_info(technical_bytes)
            encrypted_keys = tech_info[2:]
            decrypted_bytes = ""
            new_file_name = tech_info[0]
            alg = tech_info[1]
            self.select_algorithm(alg)
            try:
                decrypted_bytes = self.algorithm[2].decrypt_bytes(encrypted_keys, file[1][self.TECHNICAL_INFO_LENGTH:], password)
            except Exception as e:
                errors += str(e) + "\n"
                continue
            decrypted_files.append([new_file_name,decrypted_bytes])

        return errors, decrypted_files

    def check_files(self, files):
        total_size = 0
        oversize_files = []
        for file in files:
            file_name, file_bytes = file
            file_size = len(file_bytes)

            if file_size > self.MAX_SIZE:
                oversize_files.append(file_name)
            else:
                total_size += file_size

        files[:] = [file for file in files if len(file[1]) <= self.MAX_SIZE]
        errors = [f"File '{file}' exceeds the maximum size limit of 1 GB.\n" for file in oversize_files]
        text_error = ""
        for el in errors:
            text_error += el+"\n"
        return total_size, text_error, files
