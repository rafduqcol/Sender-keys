from django.shortcuts import render
from django.http import JsonResponse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization
import os
from app.sender_keys import generate_sender_keys, sign_message, verify_signature, encrypt_message, decrypt_message

def clean_key(key):
    # Eliminar las partes BEGIN y END
    clean = key.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '')
    key_cleaned = clean.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '')
    return key_cleaned.strip()

from cryptography.hazmat.primitives import serialization

def cryptography_view(request):
    if request.method == 'POST':
        # Recoger el mensaje ingresado por el usuario
        message = request.POST.get('message', '')

        if message:
            group_members = ["Hugo", "Javi", "Rafa"]
            
            # Generar y compartir SK para cada miembro
            group_keys = {
                member: generate_sender_keys()
                for member in group_members
            }

            # Javi firma y cifra el mensaje
            javi_ck, javi_ssk, javi_spk = group_keys["Javi"]
            signature = sign_message(javi_ssk, message)
            encrypted_message = encrypt_message(javi_ck, message)

            # Descifrar el mensaje cifrado por Javi
            decrypted_message_by_javi = decrypt_message(javi_ck, encrypted_message)

            results = []

            # Cada miembro del grupo descifra y verifica el mensaje
            for member, (ck, ssk, spk) in group_keys.items():
                if member != "Javi":
                    decrypted_message = decrypt_message(javi_ck, encrypted_message)
                    is_valid = verify_signature(javi_spk, decrypted_message, signature)
                    status = "válida" if is_valid else "inválida"
                    ssk = ssk.private_bytes(
                        encoding=serialization.Encoding.PEM, 
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )

                    # Si spk es bytes, cargar la clave pública desde PEM
                    if isinstance(spk, bytes):
                        spk = serialization.load_pem_public_key(spk)

                    # Obtener la clave pública de firma de Javi como bytes y convertir a hexadecimal
                    spk_bytes = spk.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    spk_hex = spk_bytes.hex()
                    spk_hex_preview = spk_hex[:20] + '...' + spk_hex[-20:]

                    # Crear un diccionario con los resultados de cada miembro
                    results.append({
                        'member': member,
                        'message': decrypted_message,
                        'signature': signature.hex(),  # Puedes convertir la firma a un formato legible (hex)
                        'signature_status': status,
                        'ck': ck.hex(),
                        'ssk': clean_key(ssk.decode()),
                        'spk': spk_hex_preview  # Pasamos la clave pública de Javi (spk) como hex
                    })

            # Incluir la clave de Javi (ck) y el ssk de Javi en los resultados
            javi_ck_hex = javi_ck.hex()  # Convertir la clave a hexadecimal para mostrarla
            javi_ssk_hex = clean_key(ssk.decode())  # Limpiar y convertir la ssk de Javi
            javi_spk_hex = spk.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()  # Convertir la clave pública de Javi a hexadecimal
            javi_spk_hex_preview = javi_spk_hex[:20] + '...' + javi_spk_hex[-20:]


            # Pasar los resultados, la clave de Javi (ck), la clave privada de firma de Javi (ssk), 
            # el mensaje cifrado y el mensaje descifrado a la plantilla
            return render(request, 'results.html', {
                'results': results, 
                'message': message,
                'javi_ck': javi_ck_hex,  # Pasamos la clave de cifrado de Javi a la plantilla
                'javi_ssk': javi_ssk_hex,  # Pasamos la clave privada de firma de Javi (ssk) a la plantilla
                'javi_spk': javi_spk_hex_preview,  # Pasamos la clave pública de firma de Javi (spk) a la plantilla
                'javi_encrypted_message': encrypted_message.hex(),  # Pasamos el mensaje cifrado
                'javi_signed_message': signature.hex(),  # Pasamos el mensaje firmado
                'javi_decrypted_message': decrypted_message_by_javi  # Pasamos el mensaje descifrado por Javi
            })

    # Si es una solicitud GET (mostrando el formulario)
    return render(request, 'index.html')
