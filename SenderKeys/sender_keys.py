from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization
import os

# EJEMPLO MODIFICADO: TODOS LOS MIEMBROS COMPARTEN SUS SK


# Leyenda de las variables usada:
# CK: Clave de Cifrado(Chain Key)
# SSK: Clave de Firma(Signing Secret Key)
# SPK: Clave Pública de Firma(Signing Public Key)
# Signature: Firma 


print("----------------------------EJEMPLO MODIFICADO----------------------------------------")

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
def encrypt_message(ck, message):
    iv = os.urandom(16)  # Vector de inicialización aleatorio
    cipher = Cipher(algorithms.AES(ck), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Aplicar padding para que el mensaje sea múltiplo del tamaño del bloque
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Cifrar el mensaje
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

# Función para descifrar un mensaje
def decrypt_message(ck, encrypted_message):
    iv = encrypted_message[:16]  # Extraer el IV
    ciphertext = encrypted_message[16:]  # Extraer el texto cifrado
    cipher = Cipher(algorithms.AES(ck), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Descifrar y eliminar el padding
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()

# Generar y compartir SK para cada miembro
group_keys = {
    member: generate_sender_keys()
    for member in group_members
}

print("\nSender Keys generados y compartidos:\n")
for member, (ck, ssk, spk) in group_keys.items():
    print(f"Miembro: {member}")
    print(f"  CK: {ck.hex()}")
    print(f"  SSK (clave privada de firma): {ssk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()}")
    print(f"  SPK (clave pública de firma): {spk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}")

# Solicitar mensaje de entrada del usuario
message = input("\nEscribe un mensaje que enviará Javi al grupo: ")
print("\nMensaje enviado por Javi:", message)

# Javi firma y cifra el mensaje
javi_ck, javi_ssk, javi_spk = group_keys["Javi"]
signature = sign_message(javi_ssk, message)
encrypted_message = encrypt_message(javi_ck, message)

# Cada miembro del grupo descifra y verifica el mensaje
print("\nMensajes descifrados y verificados por los miembros del grupo:\n")
for member, (ck, ssk, spk) in group_keys.items():
    if member != "Javi":
        decrypted_message = decrypt_message(javi_ck, encrypted_message)
        
        # Verificar la firma con la SPK de Javi
        is_valid = verify_signature(javi_spk, decrypted_message, signature)
        status = "válida" if is_valid else "inválida"
        
        print(f"Miembro: {member}")
        print(f"  Mensaje: {decrypted_message}")
        print(f"  Firma: {status}\n")

print("----------------------------FIN DEL EJEMPLO----------------------------------------")
