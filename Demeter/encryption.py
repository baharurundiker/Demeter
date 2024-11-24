from getpass import getpass
import pyAesCrypt
import os


def Sifrele(dosya_yolu):
    password = getpass("Şifreyi girin: ")
    bufferSize = 512 * 1024
    dosya_adı, dosya_uzantısı = os.path.splitext(dosya_yolu)
    sifreli_dosya_yolu = dosya_yolu + ".aes"
    pyAesCrypt.encryptFile(dosya_yolu, sifreli_dosya_yolu, password, bufferSize)
    print(f"Dosyanız şifrelendi: {sifreli_dosya_yolu}")
    input("Menüye dönmek için Enter'a basınız...")


def Sifrecoz(dosya_yolu):
    password = getpass("Şifreyi girin: ")
    bufferSize = 512 * 1024
    sifreli_dosya_yolu = dosya_yolu + ".aes"
    dosya_adı, dosya_uzantısı = os.path.splitext(dosya_yolu)
    acilan_dosya_yolu = dosya_adı + ".decrypted" + dosya_uzantısı
    pyAesCrypt.decryptFile(sifreli_dosya_yolu, acilan_dosya_yolu, password, bufferSize)
    print(f"Dosyanız açıldı: {acilan_dosya_yolu}")
    input("Menüye dönmek için Enter'a basınız...")


def main():
    print("Şifreleme veya şifre çözme işlemi yapmak için aşağıdaki seçeneklerden birini seçin:")
    print("1. Şifrele")
    print("2. Şifre Çöz")

    secim = input("Seçiminizi yapın (1/2): ").strip()
    if secim not in ["1", "2"]:
        print("Geçersiz seçim. Lütfen 1 veya 2 girin.")
        return

    dosya_yolu = input("Dosya yolunu girin: ").strip()

    if secim == "1":
        Sifrele(dosya_yolu)
    elif secim == "2":
        Sifrecoz(dosya_yolu)


if __name__ == "__main__":
    main()
