def cifrado_cesar(texto, desplazamiento):
    if not texto.isalpha():
        return "Texto inválido. Use solo letras de la a-z."
    
    texto = texto.lower()  # Convertir a minúsculas
    resultado = ""
    
    desplazamiento = desplazamiento % 26  # Asegurar desplazamiento cíclico
    
    for caracter in texto:
        nueva_letra = chr(((ord(caracter) - ord('a') + desplazamiento) % 26) + ord('a'))
        resultado += nueva_letra
    
    return resultado

# Solicitar entrada del usuario
while True:
    texto = input("Ingrese el texto a cifrar (solo letras a-z): ")
    if texto.isalpha():
        break
    print("Texto inválido. Use solo letras de la a-z.")

desplazamiento = int(input("Ingrese el número de desplazamiento: "))

cifrado = cifrado_cesar(texto, desplazamiento)
print("Texto cifrado:", cifrado)

