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

def cifrar(texto, clave, iv, algoritmo, tamaño_clave_3des=None):
    if algoritmo == "DES":
        key = ajustar_clave(clave, 8)
        iv = ajustar_iv(iv, 8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algoritmo == "3DES":
        key_size = 16 if tamaño_clave_3des == 16 else 24
        key = ajustar_clave(clave, key_size)
        key = DES3.adjust_key_parity(key)
        iv = ajustar_iv(iv, 8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algoritmo == "AES":
        key = ajustar_clave(clave, 32)
        iv = ajustar_iv(iv, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Algoritmo no válido.")

    texto_padded = pad(texto.encode(), cipher.block_size)
    cifrado = cipher.encrypt(texto_padded)
    return base64.b64encode(cifrado).decode(), key, iv

def descifrar(texto_b64, clave, iv, algoritmo, tamaño_clave_3des=None):
    texto_cifrado = base64.b64decode(texto_b64)
    
    if algoritmo == "DES":
        key = ajustar_clave(clave, 8)
        iv = ajustar_iv(iv, 8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algoritmo == "3DES":
        key_size = 16 if tamaño_clave_3des == 16 else 24
        key = ajustar_clave(clave, key_size)
        key = DES3.adjust_key_parity(key)
        iv = ajustar_iv(iv, 8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algoritmo == "AES":
        key = ajustar_clave(clave, 32)
        iv = ajustar_iv(iv, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Algoritmo no válido.")

    descifrado = unpad(cipher.decrypt(texto_cifrado), cipher.block_size)
    return descifrado.decode(), key, iv

# === MENÚ DE USUARIO ===
print("Seleccione una operación:")
print("1. Cifrar texto")
print("2. Descifrar texto")
op = input("Opción (1 o 2): ")

print("\nSeleccione el algoritmo:")
print("1. DES")
print("2. 3DES")
print("3. AES-256")
algoritmo_op = input("Opción (1, 2 o 3): ")

algoritmo = {"1": "DES", "2": "3DES", "3": "AES"}[algoritmo_op]
tamaño_clave_3des = None

if algoritmo == "3DES":
    tipo = input("¿Desea usar 2 claves (16 bytes) o 3 claves (24 bytes)? (Ingrese 16 o 24): ")
    tamaño_clave_3des = 16 if tipo == "16" else 24

clave = input("\nIngrese la clave: ")
iv = input("Ingrese el IV: ")

if op == "1":
    mensaje = input("Ingrese el texto a cifrar: ")
    texto_cifrado, key_final, iv_final = cifrar(mensaje, clave, iv, algoritmo, tamaño_clave_3des)
    print(f"\n[{algoritmo}] Cifrado")
    print(f"Clave final usada (hex): {key_final.hex()}")
    print(f"IV usado (hex): {iv_final.hex()}")
    print(f"Texto cifrado (Base64): {texto_cifrado}")
elif op == "2":
    mensaje = input("Ingrese el texto cifrado (Base64): ")
    texto_descifrado, key_final, iv_final = descifrar(mensaje, clave, iv, algoritmo, tamaño_clave_3des)
    print(f"\n[{algoritmo}] Descifrado")
    print(f"Clave final usada (hex): {key_final.hex()}")
    print(f"IV usado (hex): {iv_final.hex()}")
    print(f"Texto descifrado: {texto_descifrado}")
else:
    print("Opción no válida.")
