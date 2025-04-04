from scapy.all import sniff, ICMP
from collections import Counter
import re

# Almacenar los caracteres recibidos con sus números de secuencia
mensaje_cifrado = {}

def capturar_icmp(paquete):
    global mensaje_cifrado
    if paquete.haslayer(ICMP) and paquete[ICMP].payload:
        datos = bytes(paquete[ICMP].payload).decode(errors='ignore')

        if len(datos) < 2:
            return

        secuencia = int(datos[0])  # Primer byte es el número de secuencia
        caracter = datos[1]        # Segundo byte es el carácter transmitido

        mensaje_cifrado[secuencia] = caracter
        print(f"Carácter recibido: {caracter} (Secuencia {secuencia})")

def cesar_descifrar(texto):
    """ Intenta descifrar el mensaje probando todos los desplazamientos """
    mejores_resultados = []
    
    for desplazamiento in range(26):  # Probar todas las claves
        descifrado = "".join(
            chr(((ord(c) - ord('a') - desplazamiento) % 26) + ord('a')) if 'a' <= c <= 'z' else c
            for c in texto
        )

        # Evaluar la probabilidad del mensaje
        score = calcular_probabilidad(descifrado)
        mejores_resultados.append((score, desplazamiento, descifrado))

    # Ordenar por mejor puntaje
    mejores_resultados.sort(reverse=True, key=lambda x: x[0])

    print("\n--- Mensajes descifrados ---")
    for score, desplazamiento, mensaje in mejores_resultados:
        if desplazamiento == mejores_resultados[0][1]:  # Mejor opción en verde
            print(f"\033[92m[Desplazamiento {desplazamiento}]: {mensaje}\033[0m") 
        else:
            print(f"[Desplazamiento {desplazamiento}]: {mensaje}")

def calcular_probabilidad(texto):
    """ Compara la frecuencia de letras del texto con el español """
    frecuencia_esperada = {
        'a': 12.53, 'b': 1.42, 'c': 4.68, 'd': 5.86, 'e': 13.68, 'f': 0.69, 'g': 1.01,
        'h': 0.70, 'i': 6.25, 'j': 0.44, 'k': 0.02, 'l': 4.97, 'm': 3.15, 'n': 6.71,
        'o': 8.68, 'p': 2.51, 'q': 0.88, 'r': 6.87, 's': 7.98, 't': 4.63, 'u': 3.93,
        'v': 0.90, 'w': 0.02, 'x': 0.22, 'y': 0.90, 'z': 0.52
    }

    texto_limpio = re.sub(r'[^a-z]', '', texto)
    if not texto_limpio:
        return 0

    contador = Counter(texto_limpio)
    total_letras = sum(contador.values())

    diferencia_total = 0
    for letra, esperada in frecuencia_esperada.items():
        frecuencia_real = (contador.get(letra, 0) / total_letras) * 100
        diferencia_total += abs(esperada - frecuencia_real)

    return -diferencia_total  # Menor diferencia = mejor ajuste

if __name__ == "__main__":
    print("Escuchando paquetes ICMP tiene 50 segundos")
    sniff(filter="icmp", prn=capturar_icmp, store=False, timeout=50)  # Captura por 50 segundos

    if mensaje_cifrado:
        mensaje_ordenado = "".join(mensaje_cifrado[i] for i in sorted(mensaje_cifrado.keys()))
        print("\nMensaje capturado ordenado:", mensaje_ordenado)
        cesar_descifrar(mensaje_ordenado)
    else:
        print("No se capturaron caracteres ICMP.")
