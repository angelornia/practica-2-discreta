"""
criptochat.py

Chat de texto con cifrado y descifrado RSA.
"""

import os
import sys

import rsa


def cargar_clave_publica(nombre):
    """Carga n, e y el número de cifras de padding de un usuario."""
    ruta = os.path.join("Usuarios", f"pub_{nombre}.txt")

    with open(ruta, "r", encoding="utf-8") as fichero:
        lineas = fichero.readlines()

    if len(lineas) != 3:
        raise ValueError("El fichero de clave pública no tiene el formato correcto")

    n = int(lineas[0].strip())
    e = int(lineas[1].strip())
    digitos_padding = int(lineas[2].strip())

    return n, e, digitos_padding


def cargar_clave_privada(nombre):
    """Carga el exponente privado d de un usuario."""
    ruta = os.path.join("Usuarios", f"priv_{nombre}.txt")

    with open(ruta, "r", encoding="utf-8") as fichero:
        d = int(fichero.readline().strip())

    return d


def convertir_cifrado(texto):
    """Convierte una cadena de enteros separados por espacios en una lista."""
    partes = texto.split()
    cifrado = []

    for parte in partes:
        cifrado.append(int(parte))

    return cifrado


def mostrar_cifrado(cifrado):
    """Convierte una lista de enteros cifrados al formato pedido."""
    partes = []

    for numero in cifrado:
        partes.append(str(numero))

    return " ".join(partes)


def criptochat(usuario_1, usuario_2):
    """Inicia el chat entre el usuario local y el destinatario."""
    n_1, _, padding_1 = cargar_clave_publica(usuario_1)
    d_1 = cargar_clave_privada(usuario_1)
    n_2, e_2, padding_2 = cargar_clave_publica(usuario_2)

    opcion = ""

    while opcion != "S":
        opcion = input("¿Desea cifrar (C), descifrar (D) o salir (S)? ").upper()

        if opcion == "C":
            texto = input("Introduzca el texto que desea cifrar: ")
            cifrado = rsa.cifrar_cadena_rsa(texto, n_2, e_2, padding_2)
            print(mostrar_cifrado(cifrado))

        elif opcion == "D":
            texto_cifrado = input("Introduzca los números cifrados separados por espacios: ")

            try:
                cifrado = convertir_cifrado(texto_cifrado)
                texto = rsa.descifrar_cadena_rsa(cifrado, n_1, d_1, padding_1)
                print(texto)
            except ValueError:
                print("El mensaje cifrado introducido no es válido")

        elif opcion != "S":
            print("Opción no válida. Escriba C, D o S")


def main():
    if len(sys.argv) != 3:
        print("Uso: python criptochat.py <usuario1> <usuario2>")
        return

    usuario_1 = sys.argv[1]
    usuario_2 = sys.argv[2]

    try:
        criptochat(usuario_1, usuario_2)
    except FileNotFoundError:
        print("No se han encontrado todos los ficheros de claves necesarios")
    except ValueError:
        print("Alguno de los ficheros de claves no tiene un formato válido")


if __name__ == "__main__":
    main()
