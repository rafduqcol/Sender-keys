from django.shortcuts import render
from django.http import JsonResponse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization
from app.sender_keys import derive_keys, derive_signature_key, generate_sender_keys, sign_message, verify_signature, encrypt_message, decrypt_message

import os

def clean_key(key):
    # Eliminar las partes BEGIN y END
    clean = key.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '')
    key_cleaned = clean.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '')
    return key_cleaned.strip()

def truncate_key_hex(key_bytes):
    # Verificar si key_bytes es de tipo bytes
    if isinstance(key_bytes, bytes):
        hex_key = key_bytes.hex()  # Solo llamar a hex() si es un objeto bytes
    else:
        hex_key = key_bytes  # Si es una cadena, usarla directamente
    return hex_key[:20] + '...' + hex_key[-20:]


def view_information(request):
    
    return render(request,'information.html')


def truncate_message(message, max_length=40):
    if len(message) > max_length:
        return message[:20] + '...' + message[-20:]
    return message

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

            # Javi firma el mensaje y cifra utilizando MK derivada de CK
            javi_ck, javi_ssk, javi_spk = group_keys["Javi"]
            javi_mk = derive_keys(javi_ck)  # Derivar clave maestra (MK) de CK
            signature = sign_message(javi_ssk, message)
            encrypted_message = encrypt_message(javi_mk, message)

            # Descifrar el mensaje cifrado por Javi
            decrypted_message_by_javi = decrypt_message(javi_mk, encrypted_message)

            results = []

            # Cada miembro del grupo descifra y verifica el mensaje
            for member, (ck, ssk, spk) in group_keys.items():
                if member != "Javi":
                    # Derivar MK de CK del miembro (aunque no se use aquí, es buena práctica para consistencia)
                    mk_derived_from_member = derive_keys(javi_ck)
                    decrypted_message = decrypt_message(mk_derived_from_member, encrypted_message)
                    is_valid = verify_signature(javi_spk, decrypted_message, signature)
                    status = "Válida" if is_valid else "Inválida"

                    # Convertir claves a bytes (private_bytes y public_bytes)
                    ssk_bytes = ssk.private_bytes(
                        encoding=serialization.Encoding.PEM, 
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    spk_bytes = spk.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

                    # Crear un diccionario con los resultados de cada miembro
                    results.append({
                        'member': truncate_message(member),
                        'signature_status': status,
                        'ck': truncate_key_hex(ck),
                        'ssk': truncate_key_hex(ssk_bytes),
                        'spk': truncate_key_hex(spk_bytes),
                        'mk_derived_by_member': truncate_key_hex(mk_derived_from_member),
                        'decrypted_message_by_member': truncate_message(decrypted_message),
                    })
                    
            # Aquí convertimos javi_ssk a bytes
            javi_ssk_bytes = javi_ssk.private_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
    
            # Formatear las claves de Javi para la vista
            javi_spk = javi_spk.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            javi_next_ck = derive_keys(javi_ck)
            
            javi_next_ssk, javi_next_spk = derive_signature_key(javi_ssk_bytes)  # Ahora pasamos los bytes

            javi_next_ssk_bytes = javi_next_ssk.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            javi_next_spk_bytes = javi_next_spk.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,  # Usa SubjectPublicKeyInfo para claves públicas
            )

                   
                
            javi_next_ssk_hex = javi_next_ssk_bytes.hex()
            javi_next_spk_hex = javi_next_spk_bytes.hex()

            
            # Pasar los resultados y datos a la plantilla
            return render(request, 'results.html', {
                'results': results,
                'message': truncate_message(message),
                'javi_ck': truncate_key_hex(javi_ck),
                'javi_mk': truncate_key_hex(javi_mk),
                'javi_ssk': (javi_ssk_bytes.hex()),  # Usar la versión en bytes de javi_ssk
                'javi_spk': (javi_spk.hex()),
                'javi_ssk_truncated': truncate_key_hex(javi_ssk_bytes),
                'javi_spk_truncated': truncate_key_hex(javi_spk),
                'javi_encrypted_message': truncate_key_hex(encrypted_message),
                'javi_signed_message': truncate_key_hex(signature),
                'javi_next_ck': truncate_key_hex(javi_next_ck),
                'javi_next_ssk': (javi_next_ssk_hex),
                'javi_next_spk': (javi_next_spk_hex),
            })

    # Si es una solicitud GET (mostrando el formulario)
    return render(request, 'index.html')
