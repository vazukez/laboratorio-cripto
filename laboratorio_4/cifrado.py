from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def ajustar_clave(clave, tamaño_requerido):
    clave_bytes = clave.encode()
    if len(clave_bytes) < tamaño_requerido:
        clave_bytes += get_random_bytes(tamaño_requerido - len(clave_bytes))
    elif len(clave_bytes) > tamaño_requerido:
        clave_bytes = clave_bytes[:tamaño_requerido]
    return clave_bytes

def ajustar_iv(iv, tamaño_requerido):
    iv_bytes = iv.encode()
    if len(iv_bytes) < tamaño_requerido:
        iv_bytes += get_random_bytes(tamaño_requerido - len(iv_bytes))
    elif len(iv_bytes) > tamaño_requerido:
        iv_bytes = iv_bytes[:tamaño_requerido]
    return iv_bytes

def cifrar_descifrar(mensaje, clave, iv, algoritmo):
    if algoritmo == "DES":
        key = ajustar_clave(clave, 8)
        iv = ajustar_iv(iv, 8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algoritmo == "3DES":
        key = ajustar_clave(clave, 24)
        key = DES3.adjust_key_parity(key)  # Necesario para 3DES
        iv = ajustar_iv(iv, 8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algoritmo == "AES":
        key = ajustar_clave(clave, 32)
        iv = ajustar_iv(iv, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Algoritmo no válido.")

    # Cifrado
    texto_padded = pad(mensaje.encode(), cipher.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    texto_cifrado_b64 = base64.b64encode(texto_cifrado).decode()

    # Descifrado
    cipher_dec = None
    if algoritmo == "DES":
        cipher_dec = DES.new(key, DES.MODE_CBC, iv)
    elif algoritmo == "3DES":
        cipher_dec = DES3.new(key, DES3.MODE_CBC, iv)
    elif algoritmo == "AES":
        cipher_dec = AES.new(key, AES.MODE_CBC, iv)

    descifrado = unpad(cipher_dec.decrypt(base64.b64decode(texto_cifrado_b64)), cipher_dec.block_size).decode()

    print(f"\n[{algoritmo}]")
    print(f"Clave final usada (hex): {key.hex()}")
    print(f"IV usado (hex): {iv.hex()}")
    print(f"Texto cifrado (Base64): {texto_cifrado_b64}")
    print(f"Texto descifrado: {descifrado}")

# Entrada del usuario
clave = input("Ingrese la clave: ")
iv = input("Ingrese el IV: ")
mensaje = input("Ingrese el texto a cifrar: ")

# Ejecutar para los tres algoritmos
cifrar_descifrar(mensaje, clave, iv, "DES")
cifrar_descifrar(mensaje, clave, iv, "3DES")
cifrar_descifrar(mensaje, clave, iv, "AES")
