from rsa import ataque_texto_elegido

with open("X.txt", "r", encoding="utf-8") as archivo:
    lineas = archivo.readlines()

n, e = lineas[0].split(":")[1].split()

n = int(n)
e = int(e)

cList = []

for numero in lineas[3].split():
    cList.append(int(numero))

mensaje = ataque_texto_elegido(cList, n, e)

print(mensaje)