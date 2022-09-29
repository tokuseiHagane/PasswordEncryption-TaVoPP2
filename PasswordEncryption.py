import base64
import math
import rsa
from cryptography.fernet import Fernet

KEY = 'mysixteenbytekey'


class PasswordEncryption:
    (rsa_pubkey, rsa_privkey) = rsa.newkeys(512)
    fernet_cipher_key = Fernet.generate_key()
    fernet_cipher = Fernet(fernet_cipher_key)

    # Базовый ключ шифрования
    def key_char_at(self, key, i):
        return key[math.floor(i % len(key))]

    # Кодирование с переданным ключом base64
    def encode_with_key(self, clear, encode_key='mysixteenbytekey') -> str:
        try:
            clear = str(clear)
            encode_key = str(encode_key)
            enc = []
            for i in range(len(clear)):
                enc_c = chr((ord(clear[i]) + ord(self.key_char_at(encode_key, i))) % 256)
                enc.append(enc_c)
            return base64.urlsafe_b64encode("".join(enc).encode()).decode()
        except Exception as e:
            return ''

    # Декодирование с переданным ключом base64
    def decode_with_key(self, enc, encode_key='mysixteenbytekey') -> str:
        try:
            enc = str(enc)
            encode_key = str(encode_key)
            dec = []
            enc = base64.urlsafe_b64decode(enc).decode()
            for i in range(len(enc)):
                dec_c = chr((256 + ord(enc[i]) - ord(self.key_char_at(encode_key, i))) % 256)
                dec.append(dec_c)
            return "".join(dec)
        except Exception as e:
            return ''

    # Кодирование через rsa
    def encode_rsa(self, clear_password):
        if clear_password is None:
            return None
        try:
            encoded = rsa.encrypt(str(clear_password).encode(), self.rsa_pubkey)
            return encoded
        except Exception as e:
            return None

    # Декодирование через rsa
    def decode_rsa(self, enc_password):
        if enc_password is None:
            return None
        try:
            decoded = rsa.decrypt(bytes(enc_password), self.rsa_privkey)
            return decoded
        except Exception as e:
            return None

    # Кодирование через fernet
    def encode_fernet(self, clear_password):
        try:
            encoded = self.fernet_cipher.encrypt(clear_password.encode())
            return encoded
        except Exception as e:
            return None

    # Декодирование через fernet
    def decode_fernet(self, enc_password):
        try:
            decoded = self.fernet_cipher.decrypt(bytes(enc_password))
            return decoded
        except Exception as e:
            return None

    def get_fernet_key(self):
        return self.fernet_cipher_key

    def get_fernet(self):
        return self.fernet_cipher

    def get_rsa_keys(self):
        return self.rsa_pubkey, self.rsa_privkey


if __name__ == '__main__':
    encryptor = PasswordEncryption()
    password_fernet = None
    password_rsa = None
    (rsa_pubkey, rsa_privkey) = encryptor.get_rsa_keys()
    fernet_cipher_key = encryptor.get_fernet_key()
    fernet_cipher = encryptor.get_fernet()
    while True:
        print(' - - Choose an option - - \n\texit - 0\n'
              '\tencode as base64 with key - 1\n'
              '\tdecode as base64 with key - 2\n'
              '\tencode as base64 with default key - 3\n'
              '\tdecode as base64 with default key - 4\n'
              '\tencode use rsa (only pass through mode) - 5\n'
              '\tdecode use rsa (only pass through mode) - 6\n'
              '\tencode use fernet (only pass through mode) - 7\n'
              '\tdecode use fernet (only pass through mode) - 8\n> ', end=' ')
        option = int(input())
        if option == 0:
            break
        elif option == 1:
            print('password:', end=' ')
            password = input()
            print('key:', end=' ')
            key = input()
            encoded_password = encryptor.encode_with_key(password, key) if key else encryptor.encode_with_key(password)
            print(f'\nYour encoded password: {encoded_password}')
        elif option == 2:
            print('password:', end=' ')
            encrypted = input()
            print('key:', end=' ')
            key = input()
            decoded_password = encryptor.decode_with_key(encrypted, key) if key else encryptor.decode_with_key(
                encrypted)
            print(f'\nYour encoded password: {decoded_password}')
        elif option == 3:
            print(f'default key: {KEY}')
            print('password:', end=' ')
            password = input()
            encoded_password = encryptor.encode_with_key(password)
            print(f'\nYour encoded password: {encoded_password}')
        elif option == 4:
            print(f'default key: {KEY}')
            print('password:', end=' ')
            encrypted = input()
            decoded_password = encryptor.decode_with_key(encrypted)
            print(f'\nYour encoded password: {decoded_password}')
        elif option == 5:
            print(f'rsa public and private key:\n\t{rsa_pubkey}\n\t{rsa_privkey}')
            print('password:', end=' ')
            password = input()
            password_rsa = encryptor.encode_rsa(password)
            print(f'\nYour encoded password: {password_rsa}')
        elif option == 6:
            print(f'rsa public and private key:\n\t{rsa_pubkey}\n\t{rsa_privkey}')
            print(f'password: {password_rsa}', end=' ')
            decoded_password = encryptor.decode_rsa(password_rsa) if not None else None
            print(f'\nYour encoded password: {decoded_password.decode("utf-8")}')
        elif option == 7:
            print(f'fernet key: \n\t{fernet_cipher_key}')
            print('password:', end=' ')
            password = input()
            password_fernet = encryptor.encode_fernet(password)
            print(f'\nYour encoded password: {password_fernet}')
        elif option == 8:
            print(f'fernet key: \n\t{fernet_cipher_key}')
            print('password:', end=' ')
            decoded_password = encryptor.decode_fernet(password_fernet) if not None else None
            print(f'\nYour encoded password: {decoded_password.decode("utf-8")}')
