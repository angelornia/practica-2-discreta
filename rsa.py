"""
rsa.py

Matemática Discreta - IMAT
ICAI, Universidad Pontificia Comillas

Grupo: GPxxx
Integrantes:
    - Ángel Ornia Rodríguez
    - David Puente Zulueta

Descripción:
Librería para la realización de cifrado y descifrado usando el algoritmo RSA.
"""
import modular as m
from typing import Tuple, List
import random


def generar_claves(min_primo:int,max_primo:int)-> Tuple[int,int,int]:
    """Toma dos primos entre min_primo (incluido) y max_primo (excluido) y devuelve
    n,e,d
    donde (n,e) es la clave pública y d la clave privada para RSA

    Args:
        min_primo (int): Límite inferior para los primo p1 y p2 usados en la clave
        max_primo (int): Límite superior para los primo p1 y p2 usados en la clave
    
    Returns:
        n (int): Módulo para RSA, formado por el producto de dos primos p1 y p2 tales que
            min_primo<=p1, p2 < max_primo
        e (int): Exponente de la clave pública para RSA con módulo n=p1*p2
        d (int): Exponente de la clave privada para RSA con módulo n

    Raises:
        ValueError: Si no es posible encontrar una pareja de primos distintos p1,p2 entre min_primo y max_primo
    """

    primos_potenciales = m.lista_primos(min_primo, max_primo)

    if len(primos_potenciales) < 2:
        raise ValueError
    
    aleatorio_p1 = random.randint(0, (len(primos_potenciales)-1))
    aleatorio_p2 = random.randint(0, (len(primos_potenciales)-1))

    while aleatorio_p1 == aleatorio_p2:
        aleatorio_p2=random.randint(0, (len(primos_potenciales)-1))

    p_1= primos_potenciales[aleatorio_p1]
    p_2 = primos_potenciales[aleatorio_p2]

    n = p_1 * p_2

    euler_n = (p_1 - 1) * (p_2 -1)

    e = random.randint(2, (euler_n - 1))
    while not m.coprimos(euler_n, e):
        e = random.randint(2, (euler_n - 1))

    d = m.inversa_mod_p(e, euler_n)

    return (n, e, d)

def aplicar_padding(m:int,digitos_padding:int)->int:
    """Dado un mensaje y un número de dígitos de padding, añade
    digitos_padding cifras aleatorias a la derecha del mensaje
    
    Args:
        m (int): Mensaje sin padding
        digitos_padding (int): Número no negativo de cifras de padding
    
    Returns:
        int: entero formado por los dígitos de m seguidos de digitos_padding cifras aleatorias.

    Raises: None

    Example:
        aplicar_padding(24,2)=2419
        aplicar_padding(24,2)=2403
        aplicar_padding(24,3)=24718
        aplicar_padding(24,3)=24845
        aplicar_padding(24,0)=24
    """
    m_padding = str(m)

    
    for i in range(digitos_padding):
            m_padding += str(random.randint(0, 9))
    
    
    return int(m_padding)
    


def eliminar_padding(m:int,digitos_padding:int)->int:
    """Dado un mensaje con padding de digitos_padding cifras al
    final del mismo, elimina dichas cifras aleatorias y devuelve
    el resto de cifras del mensaje

    Args:
        m (int): Mensaje con padding
        digitos_padding (int): Número no negativo de cifras de padding
    
    Returns:
        int: entero resultante de eliminar las últimas digitos_padding cifras de m.

    Raises: None
    
    Example:
        eliminar_padding(2454,1)=245
        eliminar_padding(2454,2)=24
        eliminar_padding(2454,3)=2
        eliminar_padding(2432,2)=24
        eliminar_padding(2432,0)=2432
    """

    
    if digitos_padding < 0:
        raise ValueError

    return m // (10 ** digitos_padding)


def cifrar_rsa(m:int,n:int,e:int,digitos_padding:int)->int:
    """Dado un mensaje m entero, un módulo y exponente que formen parte
    de una clave pública de RSA, con m<n*10^{-digitos_padding}, y un número
    de dígitos de padding, aplica el padding al mensaje y lo cifra
    usando RSA con módulo n y exponente e.
    
    Args:
        m (int): Mensaje original claro (sin padding)
        n (int): Módulo de la clave pública de RSA
        e (int): Exponente de la clave pública de RSA
        digitos_padding (int): Número no negativo de cifras de padding
    
    Returns:
        int: entero resultante de agregar el padding a m y aplicar RSA.

    Raises: None
    """
    mensaje_con_padding = aplicar_padding(m, digitos_padding)
    return m.potencia_mod_p(mensaje_con_padding, e, n)


def descifrar_rsa(c:int,n:int,d:int,digitos_padding:int)->int:
    """Dado un cifrado c entero que haya sido cifrado con RSA usando
    digitos_padding cifras de padding al final del mensaje y el 
    módulo y exponente privado, n y d que formen la clave privada de RSA cuya pareja se
    utilizó para cifrar c, descifra c y elimina el padding, devolviendo
    el mensaje original.

    Args:
        c (int): Mensaje original claro (sin padding)
        n (int): Módulo de la clave pública de RSA usado para cifrar
        d (int): Exponente de la clave privada de RSA cuya pareja se utilizó para cifrar c
        digitos_padding (int): Número no negativo de cifras de padding usados para cifrar c
    
    Returns:
        int: entero resultante de descifrar c usando RSA con módulo m y exponente e y después eliminar el padding al resultado.

    Raises: None
    """
    mensaje_con_padding = m.potencia_mod_p(c, d, n)
    return eliminar_padding(mensaje_con_padding, digitos_padding)


def codificar_cadena(s:str)->List[int]:
    """Convierte una cadena de caracteres a la lista de
    enteros que representa el valor unicode cada uno de sus caracteres.

    Args:
        s (str): cadena en texto plano

    Returns:
        int: lista de enteros que representan el código unicode de cada carácter de la cadena s.

    Raises: None.

    Example:
        codificar_cadena("¡Hola mundo!")=[161, 72, 111, 108, 97, 32, 109, 117, 110, 100, 111, 33]
    """
    codigos = []

    for caracter in s:
        codigos.append(ord(caracter))

    return codigos


def decodificar_cadena(m:List[int])->str:
    """Convierte una lista de enteros que representen caracteres unicode
    en la cadena que representan.
    
    Args:
        m (List[int]): lisa de enteros que representan los códigos unicode de una cadena de caracteres.
    
    Returns:
        str: cadena que representan

    Raises:
        ValueError: Si alguno de los enteros no representa un caracter unicode válido.
    
    Example:
        decodificar_cadena([161, 72, 111, 108, 97, 32, 109, 117, 110, 100, 111, 33])="¡Hola mundo!"
    """
    cadena = ""

    for codigo in m:
        cadena += chr(codigo)

    return cadena



def cifrar_cadena_rsa(s:str,n:int,e:int,digitos_padding:int)->List[int]:
    """Cifra carácter a carácter una cadena de caracteres usando RSA con clave púbica (n,e)
    y digitos_padding cifras de padding al final del mensaje y devuelve la lista de enteros
    que representan el mensaje cifrado correspondiente.
    Args:
        s (str): texto claro
        n (int): módulo para RSA
        e (int): clave pública para RSA
        digitos_padding (int): número no negativo de dígitos de padding que deben usarse para el cifrado del mensaje.
    
    Returns:
        List[int]: lista de enteros que representa el mensaje cifrado con RSA para la clave dada.

    Raises: None
    """
    mensaje_codificado = codificar_cadena(s)
    mensaje_cifrado = []

    for codigo in mensaje_codificado:
        mensaje_cifrado.append(cifrar_rsa(codigo, n, e, digitos_padding))

    return mensaje_cifrado


def descifrar_cadena_rsa(cList:List[int],n:int,d:int,digitos_padding:int)->str:
    """Dado un mensaje cifrado con RSA usando la clave pública cuya clave privada asociada es (n,d)
    y digitos_padding cifras de padding al final del mensaje, devuelve la cadena orignal.
    Args:
        cList (List[int]): lisa de enteros que representan el mensaje cifrado
        n (int): módulo para RSA
        d (int): clave privada para RSA
        digitos_padding (int): número no negativo de dígitos de padding usados para el cifrado de cList.
    
    Returns:
        str: cadena que representa el texto claro correspondiente al mensaje cifrado cList.

    Raises:
        ValueError: Si, tras decodificar, alguno de los enteros del mensaje no representa un caracter unicode válido.    
    """
    mensaje_descifrado = []

    for codigo_cifrado in cList:
        mensaje_descifrado.append(descifrar_rsa(codigo_cifrado, n, d, digitos_padding))

    return decodificar_cadena(mensaje_descifrado)


def romper_clave(n:int,e:int)->int:
    """A partir de una clave pública válida (n,e), recupera la clave privada d tal que
    de = 1 (mod phi(n)).
    
    Args:
        n (int): módulo para RSA
        e (int): clave pública para RSA
    
    Returns:
        int: clave privada d

    Raises:
        ValueError: Si no existe ninguna clave privada d compatible con la clave pública (n,e).
    """
    factores = m.factorizar(n)

    if len(factores) != 2:
        raise ValueError

    primos = list(factores.keys())
    p_1 = primos[0]
    p_2 = primos[1]

    if factores[p_1] != 1 or factores[p_2] != 1:
        raise ValueError

    euler_n = (p_1 - 1) * (p_2 - 1)

    if not m.coprimos(e, euler_n):
        raise ValueError

    return m.inversa_mod_p(e, euler_n)


def ataque_texto_elegido(cList:List[int],n:int,e:int)->str:
    """Ejecuta un ataque de texto claro elegido sobre un mensaje que ha sido cifrado
    con RSA plano sin usar padding a partir de su clave pública.

    Args:
        cList (List[int]): lisa de enteros que representan el mensaje cifrado
        n (int): módulo para RSA
        e (int): clave pública para RSA
    
    Returns:
        str: texto plano descifrado para el mensaje cifrado cList

    Raises:
        ValueError: Si el mensaje no se corresponde con ningún texto plano que haya sido codificado con RSA sin padding.
    """

    mensaje_interceptado = ""
    letras_descifradas = {}

    for letra in cList:
        if letra in letras_descifradas:
            mensaje_interceptado += letras_descifradas[letra]

        else:
            for i in range(min(n, 1114112)):
                if m.potencia_mod_p(i, e, n) == letra:
                    letra_interceptada = chr(i)
                    letras_descifradas[letra] = letra_interceptada
                    mensaje_interceptado += letra_interceptada
                    break

    return mensaje_interceptado






    