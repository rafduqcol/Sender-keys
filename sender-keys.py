from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os

# Simulación de un grupo con miembros
group_members = ["Hugo", "Javi", "Rafa"]

# Generar las claves del remitente (Sender Key)
def generate_sender_key():
    # Usar X25519 para claves de intercambio
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    # Usar Ed25519 para firmar mensajes
    signing_private_key = ed25519.Ed25519PrivateKey.generate()
    signing_public_key = signing_private_key.public_key()
    return private_key, public_key, signing_private_key, signing_public_key

# Derivar claves compartidas para cada miembro del grupo
def derive_shared_keys(sender_private_key, member_public_key):
    shared_key = sender_private_key.exchange(member_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SenderKey derivation",
    ).derive(shared_key)
    return derived_key

# Función para firmar un mensaje (Usando Ed25519)
def sign_message(private_key, message):
    signature = private_key.sign(message.encode())
    return signature

# Función para verificar la firma de un mensaje (Usando Ed25519)
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(signature, message.encode())
        return True
    except Exception:
        return False

# Función para cifrar un mensaje
def encrypt_message(shared_key, message):
    iv = os.urandom(16)  # Vector de inicialización aleatorio
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Aplicar padding para que el mensaje sea múltiplo del tamaño del bloque
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Cifrar el mensaje
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

# Función para descifrar un mensaje
def decrypt_message(shared_key, encrypted_message):
    iv = encrypted_message[:16]  # Extraer el IV
    ciphertext = encrypted_message[16:]  # Extraer el texto cifrado
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Descifrar y eliminar el padding
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()

# Simulación: Crear claves públicas para los miembros del grupo
member_keys = {
    member: x25519.X25519PrivateKey.generate().public_key()
    for member in group_members
}

# Generar la clave del remitente (Javi)
sender_private_key, sender_public_key, signing_private_key, signing_public_key = generate_sender_key()

# Compartir la clave pública del remitente con el grupo
print("Sender Public Key:", sender_public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
).decode())

# Derivar claves compartidas para cada miembro
shared_keys = {
    member: derive_shared_keys(sender_private_key, public_key)
    for member, public_key in member_keys.items()
}

# Simulación: Javi envía un mensaje a Rafa y Hugo
message = "Ejemplo de Sender-keys, enviado por javi al grupo"

# Firmar el mensaje con Ed25519 (Javi firma el mensaje)
signature = sign_message(signing_private_key, message)

# Cifrar el mensaje para Rafa y Hugo (Usando sus claves compartidas)
encrypted_messages = {
    member: encrypt_message(shared_key, message)
    for member, shared_key in shared_keys.items() if member != "Javi"  # Javi no recibe el mensaje
}

print("\nMensajes cifrados enviados por Javi al resto del grupo: \n")
for member, encrypted in encrypted_messages.items():
    print(f"{member}: {encrypted}")

# Descifrar y verificar los mensajes (Rafa y Hugo)
print("--------------------------------------------------------------------------------------------------------------------")
print("\nMensajes descifrados y verificados: \n")
for member, encrypted in encrypted_messages.items():
    decrypted_message = decrypt_message(shared_keys[member], encrypted)

    # Verificar la firma
    is_valid = verify_signature(signing_public_key, decrypted_message, signature)
    status = "válido" if is_valid else "inválido"
    print(f"{member}: {decrypted_message} (Firma: {status})")
