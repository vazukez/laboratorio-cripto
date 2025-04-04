from scapy.all import ICMP, IP, send

def enviar_icmp(texto):
    destino = "8.8.8.8"  # Dirección IP fija de destino (Google DNS)
    
    print(f"Enviando paquetes ICMP a {destino}...")

    for i, caracter in enumerate(texto):
        datos = f"{i}{caracter}".encode()  # Agregar número de secuencia
        paquete = IP(dst=destino)/ICMP()/datos
        send(paquete, verbose=False)
    
    print(f"Paquetes ICMP enviados correctamente a {destino}.")

if __name__ == "__main__":
    print("La IP de destino está fijada en 8.8.8.8")
    texto = input("Ingrese el texto a enviar: ")

    if not texto.isalpha():
        print("Texto inválido. Use solo letras de la a-z.")
    else:
        enviar_icmp(texto)
