from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization
import os

# Leyenda de las variables usada:
# CK: Clave de Cifrado (Chain Key)
# MK: Clave Maestra (Master Key)
# SSK: Clave de Firma (Signing Secret Key)
# SPK: Clave Pública de Firma (Signing Public Key)
# Signature: Firma 

# Simulación de un grupo con miembros
group_members = ["Hugo", "Javi", "Rafa"]

# Generar Sender Keys (CK, SSK, SPK) para cada miembro
def generate_sender_keys():
    # Crear clave de firma privada (SSK) y pública (SPK)
    ssk = ed25519.Ed25519PrivateKey.generate()
    spk = ssk.public_key()
    
    # Crear clave de cifrado simétrica (CK)
    ck = os.urandom(32)  # Generar clave aleatoria de 256 bits (32 bytes)
    
    return ck, ssk, spk

# Derivar MK a partir de CK usando HKDF (HMAC-SHA256)
def derive_message_key(ck):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Longitud de la clave derivada (256 bits / 32 bytes)
        salt=None,  # Puede usar un salt aleatorio para mayor seguridad
        info=b"group-encryption-key"  # Información contextual
    )
    mk = hkdf.derive(ck)
    return mk

# Función para firmar un mensaje
def sign_message(private_key, message):
    signature = private_key.sign(message.encode())
    return signature

# Función para verificar la firma de un mensaje
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(signature, message.encode())
        return True
    except Exception:
        return False

# Función para cifrar un mensaje
def encrypt_message(mk, message):
    iv = os.urandom(16)  # Vector de inicialización aleatorio
    cipher = Cipher(algorithms.AES(mk), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Aplicar padding para que el mensaje sea múltiplo del tamaño del bloque
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Cifrar el mensaje
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

# Función para descifrar un mensaje
def decrypt_message(mk, encrypted_message):
    iv = encrypted_message[:16]  # Extraer el IV
    ciphertext = encrypted_message[16:]  # Extraer el texto cifrado
    cipher = Cipher(algorithms.AES(mk), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Descifrar y eliminar el padding
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()

# Ejemplo de uso
print("----------------------------EJEMPLO MODIFICADO----------------------------------------")

# Generar claves para Javi
ck, ssk, spk = generate_sender_keys()
print(f"Clave de cifrado (CK) de Javi: {ck.hex()}")

# Derivar clave maestra (MK)
mk = derive_message_key(ck)
print(f"Clave maestra (MK) derivada: {mk.hex()}")

# Mensaje a cifrar
mensaje = "Este es un mensaje secreto."

# Cifrar mensaje
encrypted_message = encrypt_message(mk, mensaje)
print(f"Mensaje cifrado: {encrypted_message.hex()}")

# Descifrar mensaje
decrypted_message = decrypt_message(mk, encrypted_message)
print(f"Mensaje descifrado: {decrypted_message}")
