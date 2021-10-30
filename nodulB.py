import socket
import Aes

K_prim= b"ANAAAAAAAREMEREE"
iv=b"vectorPENTRUOFBE"
BPort = 2132
BIP = "127.0.0.1"

def xor(bloc1, bloc2):
    xorred= (i ^ j for i, j in zip(bloc1, bloc2))
    return xorred


def decriptare_ofb(blocuriCipherText,cheie,iv):
    blocuriTextDecriptat = []
    blocAnterior = iv
    pos = 0
    while pos + 16 <= len(blocuriCipherText):
        nextPos = pos + 16
        blocCurent = blocuriCipherText[pos:nextPos]
        blocDecriptat = bytes(
            Aes.AESModeOfOperationOFB(cheie).decrypt(bytes(xor(blocCurent,blocAnterior))))
        blocuriTextDecriptat.append(blocDecriptat)
        pos += 16
        blocAnterior = blocCurent
    return b"".join(blocuriTextDecriptat)


def asteptModComunicareDeLaNodulA(ASocket):
    while True:
        bufferDeLaA = ASocket.recv(10000000)
        print("A: ", bufferDeLaA)
        if bufferDeLaA == b"OFB":
            print("Am primit modul de comunicare de la nodul A")
            break
        else:
            bufferSpreA = "Nume gresit. Mai incearca!"
            ASocket.sendall(bufferSpreA.encode())


def iauCheieCriptataDeLaA(ASocket):
    while True:
        bufferDeLaA= ASocket.recv(10000000)
        print("Am primit cheia criptata de la A : ", bufferDeLaA)
        return bufferDeLaA

def decriptareFisierDatDeA(ASocket):

    bufferCatreA = input("Confirmati comunicarea cu nodul A?: ")
    ASocket.sendall(bufferCatreA.encode())
    print("Am inceput comunicarea cu nodul A!")
    if bufferCatreA == "da":
        bufferDeLaA = ASocket.recv(10000000)
        print("Continutul fisierului trimis de nodul A (CRIPTAT): ", bufferDeLaA)
        mesaj_decriptat_de_la_a = decriptare_ofb(bufferDeLaA, cheieDecriptata, iv)
        print("Continutul fisierului trimis de nodul A (DECRIPTAT): ", mesaj_decriptat_de_la_a)

if __name__ == '__main__':
    BSocket = socket.socket()
    print("Socketul pentru nodul B a fost creat cu succes ! Astept nodul A sa-mi comunice modul de operare!")

    BSocket.bind((BIP, BPort))

    BSocket.listen(3)
    ASocket= BSocket.accept()[0]

    asteptModComunicareDeLaNodulA(ASocket)
    print("Astept cheia de la nodul A..")

    bufferSpreA = "Te rog trimite-mi cheia - nodul B!"
    ASocket.sendall(bufferSpreA.encode())

    cheieCriptataPrimitaDeLaA = iauCheieCriptataDeLaA(ASocket)
    cheieDecriptata = Aes.AESModeOfOperationOFB(K_prim).decrypt(cheieCriptataPrimitaDeLaA)

    print("Cheia decriptata: ", cheieDecriptata)

    decriptareFisierDatDeA(ASocket)

    BSocket.close()
