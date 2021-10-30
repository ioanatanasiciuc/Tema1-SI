import socket
import Aes
KMPort = 2512
BPort = 2132

bufferCatreKM=""
K_prim= b"ANAAAAAAAREMEREE"
iv=b"vectorPENTRUOFBE"

def xor(bloc1, bloc2):
    xorred= (i ^ j for i, j in zip(bloc1, bloc2))
    return xorred

def criptare_ofb(plaintext,cheie,iv):
    while len(plaintext) % 16 != 0:
        plaintext += b"0"
    pos = 0
    blocAnterior = iv
    blocuriCipherText = []
    while pos + 16 <= len(plaintext):
        nextPos = pos + 16
        blocCurent = plaintext[pos:nextPos]
        blocCipherText = bytes(Aes.AESModeOfOperationOFB(cheie).encrypt(bytes(xor(blocCurent,blocAnterior))))
        blocuriCipherText .append( blocCipherText )
        pos += 16
        blocAnterior = blocCipherText
    return b"".join(blocuriCipherText)

def trimitModOperareNoduluiB(BSocket):
    while True:
        bufferCatreB= input("Introduceti modul de operare: ")
        if bufferCatreB == "OFB":
            BSocket.sendall(bufferCatreB.encode())
            bufferDeLaB = BSocket.recv(10000000)
            print("B:  ", bufferDeLaB)
            break
        bufferDeLaB = BSocket.recv(10000000)
        print("B:  ", bufferDeLaB)


def iauCheieCriptataDeLaKM():
    KMSocket = socket.socket()
    KMSocket.connect(('127.0.0.1', KMPort))
    while True:
        bufferSpreKM = "OFB"
        if KMSocket.sendall(bufferSpreKM.encode()):
            print("Eroare la comunicarea cu KeyManager")
        else:
            print("Am cerut cheia nodului KeyManager")
        bufferDeLAKM = KMSocket.recv(10000000)
        print("Am primit cheia criptata de la KeyManager : ", bufferDeLAKM)
        KMSocket.close()
        return bufferDeLAKM

def trimitCheieCriptataPrimitaDeLaKMCatreB(BSocket,bufferCatreB):
    BSocket.sendall(bufferCatreB)
    print("I-am trimis cheia si nodului B.")


def trimitContinutulFisieruluiCriptat(BSocket, bufferCatreB):
    print("Incep comunicarea criptata cu nodul B!")
    while True:
        BSocket.sendall(bufferCatreB)
        print("Mesaj trimis cu succes!")
        break


if __name__ == '__main__':

   #comunicarea se face cu nodul B prima oara
   BSocket=socket.socket()
   BSocket.connect(('127.0.0.1', BPort))

   trimitModOperareNoduluiB(BSocket)

   cheieCriptataPrimitaDeLaKM = iauCheieCriptataDeLaKM();
   trimitCheieCriptataPrimitaDeLaKMCatreB(BSocket,cheieCriptataPrimitaDeLaKM)

   cheieDecriptata=Aes.AESModeOfOperationOFB(K_prim).decrypt(cheieCriptataPrimitaDeLaKM)
   print("Cheia decriptata: ",cheieDecriptata)

   file = open("file", "rb")
   continutFisier =file.read()
   continutFisierCriptat=criptare_ofb(continutFisier,cheieDecriptata,iv)


   print("Astept confirmare de la nodul B pentru a putea incepe comunicarea")
   bufferDeLaB = BSocket.recv(10000000)
   print("Mesaj de la B: ", bufferDeLaB)
   if bufferDeLaB==b"da":
     trimitContinutulFisieruluiCriptat(BSocket,continutFisierCriptat)
   else:
     print("Nodul b nu a confirmart faptul ca se poate comunica!")
   BSocket.close()



