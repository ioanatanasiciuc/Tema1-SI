import socket

import Aes
import os

KMPort = 2512
KMIP = "127.0.0.1"

#luam 16 bytes random pentru K`
K = os.urandom(16)
K_prim= b"ANAAAAAAAREMEREE"
cheieCriptata = Aes.AESModeOfOperationOFB(K_prim).encrypt(K)

def NodA(conexiuneNodA):
    while True:
        bufferA = conexiuneNodA.recv(10000000)
        if not bufferA:
            print("Am iesit!")
            break
        conexiuneNodA.sendall(cheieCriptata)
        print("Am trimis cheia nodului A! ")
        break


if __name__ == '__main__':

    KMSocket = socket.socket()
    print("Socketul pentru Key Manager a fost creat cu succes ! Astept nodul A sa-mi ceara cheia!")

    KMSocket.bind((KMIP, KMPort))

    KMSocket.listen(3)

    ASocket= KMSocket.accept()[0]

    print("S-a conectat nodul A!")
    NodA(ASocket)

    KMSocket.close()
