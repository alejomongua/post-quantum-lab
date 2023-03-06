# Funciones para intercambio de llaves
from kyber import Kyber512

# Funciones para cifrado y decifrado simétrico
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def generar_llaves():
    """
    Genera el par de llaves usando el método Kyber512.keygen

    Retorna la llave pública y la llave privada en ese orden
    """
    pub_key, priv_key = Kyber512.keygen()

    # Retorna las llaves en base64
    return b64encode(pub_key).decode(), b64encode(priv_key).decode()


def encapsular(llave_publica):
    """
    Genera el par de llaves usando el método Kyber512.enc

    Recibe la llave pública

    Retorna cyphertext y la llave simétrica para cifrar
    """
    # Convertimos la llave pública en bytes desde base64
    llave_publica = b64decode(llave_publica)

    cyphertext, key = Kyber512.enc(llave_publica)

    # Retorna el cyphertext y la llave en base64
    return b64encode(cyphertext).decode(), b64encode(key).decode()


def desencapsular(cyphertext, llave_secreta):
    """
    Recupera la llave simétrica usando el algoritmo Kyber512.dec

    Recibe: cyphertext y la llave privada

    Retorna la llave simétrica para el cifrado
    """
    # Convertimos la llave secreta en bytes desde base64
    llave_secreta = b64decode(llave_secreta)
    # Convertimos el cyphertext en bytes desde base64
    cyphertext = b64decode(cyphertext)

    key = Kyber512.dec(cyphertext, llave_secreta)

    # Retorna la llave en base64
    return b64encode(key).decode()


def cifrar_aes(mensaje, llave):
    """
    Cifra un texto con una llave usando AES CBC

    Recibe: el mensaje y la llave de cifrado

    Retorna un string en base64 con el texto cifrado y otro
    string en base64 con el vector de inicialización
    """
    # Si el mensaje no es un string, lo convertimos a bytes
    if isinstance(mensaje, str):
        mensaje = mensaje.encode('utf-8')

    # Convertimos la llave desde base64
    llave = b64decode(llave)

    iv = get_random_bytes(16)
    cipher = AES.new(llave, AES.MODE_CBC, iv)
    texto_cifrado = cipher.encrypt(pad(mensaje, AES.block_size))
    return b64encode(texto_cifrado).decode(), b64encode(iv).decode()


def decifrar_aes(texto_cifrado, llave, iv):
    """
    Descifra un texto con una llave usando AES CBC

    Recibe: el mensaje cifrado en formato base64, la llave de
    cifrado y el vector de inicialización (iv)

    Retorna el mensaje original
    """
    # Convertimos la llave desde base64
    llave = b64decode(llave)

    cipher = AES.new(llave, AES.MODE_CBC, b64decode(iv))
    texto_descifrado = unpad(cipher.decrypt(
        b64decode(texto_cifrado)), AES.block_size)
    return texto_descifrado.decode('utf-8')


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-g", "--generar", dest="generar",
                        action="store_true", help="Generar llaves")
    parser.add_argument("-E", "--encapsular", dest="encapsular",
                        action="store_true", help="Encapsular llave " +
                        "pública, necesita -p")
    parser.add_argument("-D", "--desencapsular", dest="desencapsular",
                        action="store_true", help="Desencapsular llave " +
                        "pública, necesita -c y -s")
    parser.add_argument("-c", "--cifrar", dest="cifrar",
                        action="store_true", help="Cifrar el mensaje, " +
                        "necesita -m y -k")
    parser.add_argument("-d", "--descifrar", dest="descifrar",
                        action="store_true", help="Descifrar el mensaje, " +
                        "necesita -m, -k y -i")
    parser.add_argument("-m", "--mensaje", dest="mensaje",
                        help="Mensaje a cifrar o decifrar")
    parser.add_argument("-k", "--llave", dest="llave", help="Llave de cifrado")
    parser.add_argument("-i", "--iv", dest="iv",
                        help="Vector de inicialización")
    parser.add_argument("-p", "--publica", dest="publica",
                        help="Llave pública")
    parser.add_argument("-s", "--secreta", dest="secreta",
                        help="Llave secreta")
    parser.add_argument("-C", "--cyphertext", dest="cyphertext",
                        help="Cyphertext para generar llave simétrica")

    args = parser.parse_args()

    # Primero Alicia genera el par de llaves y le envía la llave pública a
    # Roberto
    if args.generar:
        llave_publica, llave_secreta = generar_llaves()
        print("Llave pública (público):")
        print("---------------------")
        print(llave_publica)
        print("---------------------")
        print("Llave secreta (privado):")
        print("---------------------")
        print(llave_secreta)
        print("---------------------")
        print()
        print("Ahora debe llamar al programa con la opción -E y pasar la " +
              "llave pública")
        print(f"python3 main.py -E -p {llave_publica}")
        exit()

    # Después, Roberto debe que encapsular la llave simétrica y enviar
    # el cyphertext a Alicia
    if args.encapsular:
        if not args.publica:
            print("Debe pasar la llave pública con la opción -p")
            exit()
        cyphertext, llave = encapsular(args.publica)
        print("Cyphertext (público):")
        print("---------------------")
        print(cyphertext)
        print("---------------------")
        print("Llave (privado):")
        print("---------------------")
        print(llave)
        print("---------------------")
        print()
        print("Ahora debe llamar al programa con la opción -D y pasar la " +
              "llave privada y el cyphertext")
        print(f"python3 main.py -D -C {cyphertext} -s <llave_privada>")
        exit()

    # Seguido, Alicia debe desencapsular el cyphertext con su llave secreta
    if args.desencapsular:
        if not args.cyphertext or not args.secreta:
            print(
                "Debe pasar el cyphertext con la opción -C y la llave " +
                "secreta con la opción -s")
            exit()
        llave = desencapsular(args.cyphertext, args.secreta)
        print("Llave (privado):")
        print("---------------------")
        print(llave)
        print("---------------------")
        print()
        print(
            "Ya se tiene compartida la llave secreta, se puede usar para " +
            "cifrar un mensaje")
        print(f"python3 main.py -c -k {llave} -m 'Hola mundo!!'")
        exit()

    # Finalmente, ambos pueden cifrar y descifrar mensajes
    if args.cifrar:
        if not args.mensaje or not args.llave:
            print("Debe pasar el mensaje con la opción -m y la llave con la " +
                  "opción -k")
            exit()
        texto_cifrado, iv = cifrar_aes(args.mensaje, args.llave)
        print("Texto cifrado (público):")
        print("---------------------")
        print(texto_cifrado)
        print("---------------------")
        print("IV (público):")
        print("---------------------")
        print(iv)
        print("---------------------")
        print()
        print("El mensaje se debe decifrar con la misma llave y el mismo IV")
        print(f"python3 main.py -d -k {args.llave} -m {texto_cifrado} -i {iv}")
        exit()

    if args.descifrar:
        if not args.mensaje or not args.llave or not args.iv:
            print(
                "Debe pasar el mensaje cifrado con la opción -m, la llave " +
                "con la opción -k y el IV con la opción -i")
            exit()
        texto_descifrado = decifrar_aes(args.mensaje, args.llave, args.iv)
        print("Texto descifrado:")
        print("---------------------")
        print(texto_descifrado)
        print("---------------------")
        exit()

    # Si llega hasta aquí, muestre la ayuda
    parser.print_help()
    print()
    print("Puede usar la opción -g para generar un par de llaves y " +
          "continuar con las instrucciones que se dan desde allí")
    print()
    exit()
