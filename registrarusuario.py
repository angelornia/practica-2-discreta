import rsa as r
import os

def crear_usuario():
    try:
        nombre = input("Introduzca su nombre: ")
        valor_min = int(input("Introduzca el valor mínimo del primo para generar sus claves: "))
        valor_max = int(input("Introduzca el valor máximo del primo para generar sus claves: "))
        cifras_padding = int(input("Introduzca el número de cifras padding deseadas: "))

        if valor_min < 2 or valor_min >= valor_max:
            raise ValueError("El intervalo de primos no es válido")

        if cifras_padding < 0:
            raise ValueError("El padding no puede ser negativo")

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
    except ValueError as error:
        print("Error:", error)

if __name__=="__main__":
    crear_usuario()


