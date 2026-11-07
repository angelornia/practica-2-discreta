import rsa as r
import os

def crear_usuario():
    nombre = input("Introduzca su nombre: ")
    valor_min = int(input("Introduzca el valor mínimo del primo para generar sus claves: "))
    valor_max = int(input("Introduzca el valor máximo del primo para generar sus claves: "))
    cifras_padding = input("Introduzca el número de cifras padding deseadas: ")

    n, e, d = r.generar_claves(valor_min, valor_max)

    if not os.path.exists("Usuarios"):
        os.makedirs("Usuarios")

    nombre_fichero_pub = f"Usuarios/pub_{nombre}.txt"
    with open(nombre_fichero_pub, "w", encoding="utf-8") as fichero:

        fichero.write(f"{n}\n")
        fichero.write(f"{e}\n")
        fichero.write(f"{cifras_padding}\n")

    nombre_fichero_priv = f"Usuarios/priv_{nombre}.txt"
    with open(nombre_fichero_priv, "w", encoding = "utf-8") as fichero:

        fichero.write(f"{d}")

if __name__=="__main__":
        crear_usuario()


