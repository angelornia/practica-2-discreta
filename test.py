import rsa as r
import time

import time

inicio = time.time()

n, e, d = r.generar_claves(10**10, 10**11)

fin = time.time()

print("n:", n)
print("Número de cifras:", len(str(n)))
print("Tiempo:", fin - inicio, "segundos")