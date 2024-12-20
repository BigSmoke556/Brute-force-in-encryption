import hashlib
from Crypto.Cipher import AES, DES, Blowfish
from cryptography.fernet import Fernet
from base64 import b64decode
from itertools import cycle
from caesarcipher import CaesarCipher
import bcrypt

"""
Este código implementa uma série de funções para descriptografar diferentes tipos de criptografia, 
além de fornecer um hash usando hashlib. As funções abrangem os seguintes métodos de criptografia:

- AES, DES, e Blowfish (usando PyCryptodome)
- Fernet (usando cryptography)
- bcrypt (verificação de hashes)
- Decodificação Base64
- Cifra de César
- Cifra de Vigenère
- Geração de hash SHA-256 com hashlib
"""

# Função para descriptografar usando AES com PyCryptodome
def decrypt_aes(ciphertext, key):
    """
    Descriptografa um texto cifrado usando AES em modo EAX.
    Args:
        ciphertext (bytes): O texto cifrado.
        key (bytes): A chave de descriptografia (16 bytes).
    Returns:
        str: Texto descriptografado ou None em caso de erro.
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=ciphertext[:16])
    try:
        return cipher.decrypt(ciphertext[16:]).decode('utf-8')
    except Exception as e:
        print("AES Error:", e)
        return None

# Função para descriptografar usando Fernet
def decrypt_fernet(ciphertext, key):
    """
    Descriptografa um texto cifrado usando Fernet.
    Args:
        ciphertext (bytes): O texto cifrado.
        key (bytes): A chave Fernet.
    Returns:
        str: Texto descriptografado ou None em caso de erro.
    """
    try:
        fernet = Fernet(key)
        return fernet.decrypt(ciphertext).decode()
    except Exception as e:
        print("Fernet Error:", e)
        return None

# Função para descriptografar usando bcrypt (não descriptografa, mas pode verificar hashes)
def decrypt_bcrypt(ciphertext, key):
    """
    Verifica se um hash bcrypt corresponde a um texto fornecido.
    Args:
        ciphertext (bytes): O texto a ser comparado.
        key (bytes): O hash bcrypt.
    Returns:
        bool: True se os hashes coincidirem, False caso contrário.
    """
    try:
        return bcrypt.checkpw(ciphertext, key)
    except Exception as e:
        print("Bcrypt Error:", e)
        return None

# Função para descriptografar usando DES com PyCryptodome
def decrypt_des(ciphertext, key):
    """
    Descriptografa um texto cifrado usando DES em modo EAX.
    Args:
        ciphertext (bytes): O texto cifrado.
        key (bytes): A chave de descriptografia (8 bytes).
    Returns:
        str: Texto descriptografado ou None em caso de erro.
    """
    cipher = DES.new(key, DES.MODE_EAX, nonce=ciphertext[:8])
    try:
        return cipher.decrypt(ciphertext[8:]).decode('utf-8')
    except Exception as e:
        print("DES Error:", e)
        return None

# Função para descriptografar usando Blowfish com PyCryptodome
def decrypt_blowfish(ciphertext, key):
    """
    Descriptografa um texto cifrado usando Blowfish em modo EAX.
    Args:
        ciphertext (bytes): O texto cifrado.
        key (bytes): A chave de descriptografia (8 a 56 bytes).
    Returns:
        str: Texto descriptografado ou None em caso de erro.
    """
    cipher = Blowfish.new(key, Blowfish.MODE_EAX, nonce=ciphertext[:8])
    try:
        return cipher.decrypt(ciphertext[8:]).decode('utf-8')
    except Exception as e:
        print("Blowfish Error:", e)
        return None

# Função para gerar hash com hashlib
def decrypt_hash(ciphertext, algorithm='sha256'):
    """
    Gera um hash do texto usando o algoritmo especificado.
    Args:
        ciphertext (bytes): O texto de entrada.
        algorithm (str): O algoritmo de hash (padrão: 'sha256').
    Returns:
        str: Hash gerado ou None em caso de erro.
    """
    try:
        h = hashlib.new(algorithm)
        h.update(ciphertext)
        return h.hexdigest()
    except Exception as e:
        print(f"{algorithm} Hash Error:", e)
        return None

# Função para tentativa de descriptografia com Base64
def try_base64_decode(text):
    """
    Tenta decodificar um texto em Base64.
    Args:
        text (str): O texto codificado.
    Returns:
        str: Texto decodificado ou None em caso de erro.
    """
    try:
        return b64decode(text).decode('utf-8')
    except Exception:
        return None

# Função para tentativa de descriptografia com Cifra de César
def try_caesar_cipher(text):
    """
    Tenta decodificar um texto usando a cifra de César com todas as possíveis rotações (1 a 25).
    Args:
        text (str): O texto cifrado.
    Returns:
        list: Lista de possíveis decodificações.
    """
    possible_results = []
    for shift in range(1, 26):
        decoded_text = CaesarCipher(text, offset=shift).decoded
        possible_results.append(decoded_text)
    return possible_results

# Função para tentativa de descriptografia com Cifra de Vigenère
def try_vigenere_cipher(text, keywords=["Vortex", "Orion"]):
    """
    Tenta decodificar um texto usando a cifra de Vigenère com palavras-chave fornecidas.
    Args:
        text (str): O texto cifrado.
        keywords (list): Lista de palavras-chave para tentar.
    Returns:
        list: Lista de tuplas com a palavra-chave e o texto decodificado.
    """
    possible_results = []
    for key in keywords:
        decoded_text = ''.join(
            chr(((ord(char) - ord('a') - (ord(k) - ord('a'))) % 26) + ord('a'))
            if char.isalpha() else char
            for char, k in zip(text, cycle(key))
        )
        possible_results.append((key, decoded_text))
    return possible_results

# Função principal para testar diferentes métodos de criptografia
def try_all_methods(text, key):
    """
    Testa vários métodos de descriptografia no texto fornecido.
    Args:
        text (bytes): Texto cifrado de entrada.
        key (bytes): Chave de descriptografia.
    Returns:
        None
    """
    print("\nTrying Base64 decoding...")
    result = try_base64_decode(text)
    if result:
        print("Base64 Decoding Result:", result)
    else:
        print("Base64 Decoding: Failed")

    print("\nTrying Caesar Cipher Decoding...")
    caesar_results = try_caesar_cipher(text)
    for shift, result in enumerate(caesar_results, start=1):
        print(f"Shift {shift}: {result}")

    print("\nTrying Vigenère Cipher Decoding...")
    vigenere_results = try_vigenere_cipher(text)
    for key, result in vigenere_results:
        print(f"Key '{key}': {result}")

    print("\nTrying AES Decoding...")
    aes_result = decrypt_aes(text, key)
    if aes_result:
        print("AES Decryption Result:", aes_result)
    else:
        print("AES Decryption: Failed")

    print("\nTrying Fernet Decoding...")
    fernet_result = decrypt_fernet(text, key)
    if fernet_result:
        print("Fernet Decryption Result:", fernet_result)
    else:
        print("Fernet Decryption: Failed")

    print("\nTrying bcrypt Decoding (Hash Check)...")
    bcrypt_result = decrypt_bcrypt(text, key)
    if bcrypt_result:
        print("bcrypt Decryption Result: Match Found")
    else:
        print("bcrypt Decryption: Failed")

    print("\nTrying DES Decoding...")
    des_result = decrypt_des(text, key)
    if des_result:
        print("DES Decryption Result:", des_result)
    else:
        print("DES Decryption: Failed")

    print("\nTrying Blowfish Decoding...")
    blowfish_result = decrypt_blowfish(text, key)
    if blowfish_result:
        print("Blowfish Decryption Result:", blowfish_result)
    else:
        print("Blowfish Decryption: Failed")

    print("\nGenerating SHA-256 Hash...")
    sha256_hash = decrypt_hash(text, 'sha256')
    if sha256_hash:
        print("SHA-256 Hash:", sha256_hash)
    else:
        print("SHA-256 Hashing Failed")

# Exemplo de uso
text = b"c126kPtkE9xkpd08ojpDDg"  # Texto cifrado de exemplo
key = b"suachave"  # Chave para AES, DES e Blowfish
try_all_methods(text, key)
