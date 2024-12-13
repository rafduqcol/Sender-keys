from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization
import os
import secrets


# Leyenda de las variables usada:
# CK: Clave de Cifrado (Chain Key)
# MK: Clave Maestra (Master Key)
# SSK: Clave de Firma (Signing Secret Key)
# SPK: Clave Pública de Firma (Signing Public Key)
# Signature: Firma 

# Simulación de un grupo con miembros
group_members = ["Hugo", "Javi", "Rafa"]

# Generar Sender Keys (CK, SPK) y SSK para cada miembro
def generate_sender_keys():
    # Crear clave de firma privada (SSK) y pública (SPK)
    ssk = ed25519.Ed25519PrivateKey.generate()
    spk = ssk.public_key()
    
    # IMPLEMENTA UNA DE LAS SOLUCIONES PROPUESTAS
    # Crear la chain key (CK) utilizando una fuente de entropía criptográficamente segura
    ck = secrets.token_bytes(32)
    return ck, ssk, spk

# Se usa para calcular el message ley para cifrar y el próximo ck (HMAC-SHA256)
def derive_keys(key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Longitud de la clave derivada (256 bits / 32 bytes)
        salt=None,  
        info=b"group-encryption-key"  # Información contextual
    )
    derived_key = hkdf.derive(key)
    return derived_key

# IMPLEMENTA UNA DE LAS SOLUCIONES PROPUESTAS
# Función para aplicar ratcheting a la clave de firma
def derive_signature_key(current_ssk):
    # Verifica que current_ssk sea un objeto de tipo bytes
    if not isinstance(current_ssk, bytes):
        raise TypeError("current_ssk debe ser un objeto de tipo bytes.")
    
    # Derivar nueva clave usando HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=None,  
        info=b"signature-ratcheting"  
    )
    new_ssk_bytes = hkdf.derive(current_ssk)
    
    # Generar una nueva clave privada a partir de los bytes derivados
    next_ssk = ed25519.Ed25519PrivateKey.from_private_bytes(new_ssk_bytes)
    
    # Obtener la clave pública a partir de la clave privada
    next_spk = next_ssk.public_key()
    
    return next_ssk, next_spk

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
mk = derive_keys(ck)
print(f"Clave maestra (MK) derivada: {mk.hex()}")

# Mensaje a cifrar
mensaje = "Este es un mensaje secreto."

# Cifrar mensaje
encrypted_message = encrypt_message(mk, mensaje)
print(f"Mensaje cifrado: {encrypted_message.hex()}")

# Descifrar mensaje
decrypted_message = decrypt_message(mk, encrypted_message)
print(f"Mensaje descifrado: {decrypted_message}")
