import socket
import re


def is_valid_ip(ip):
    """IP adresinin geçerli olup olmadığını kontrol eder."""
    # IPv4 formatında olup olmadığını kontrol eder
    ip_regex = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    return re.match(ip_regex, ip) is not None



def Thread_scan(ip,port_rnge):

    def portScan(ip,port):
        # 1'den 65535'e kadar olan portları taramak için bir döngü oluştur
            try:
                # TCP bağlantısı kurmak için bir socket oluştur
                sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sckt.settimeout(1)  # Zaman aşımını 1 saniye olarak ayarla

                # IP adresine belirtilen port üzerinden bağlanmayı dene
                result = sckt.connect_ex((ip, port))

                # Eğer bağlantı başarılı olursa, portun açık olduğunu bildir
                if result == 0:
                    print(f"Port {port}: açık")
                # İstisnai durumlar için detaylı çıktı sağlayabiliriz
                elif result == 111:  # Connection refused (Bağlantı reddedildi)
                    print(f"Port {port}: kapalı")
                else:
                    print(f"Port {port}: bilinmiyor (Hata kodu: {result})")
            except Exception as e:
                # Hata mesajını da yazdırarak, sorunun ne olduğunu anlamamıza yardımcı olur
                print(f"Port {port}: kapalı ({str(e)})")
            finally:
                # Socket'i kapat
                sckt.close()


def main():
    # Kullanıcıdan IP adresi al
    ip = input("Tarama yapmak istediğiniz IP adresini girin: ")

    if not is_valid_ip(ip):
        print(f"Geçersiz IP adresi: {ip}")
        exit(1)


    try:
        sPort = int(input("Başlangıç portunu giriniz: \n"))
        ePort = int(input("Bitiş portunu giriniz: \n"))
        if sPort < 1 or ePort > 65535 or sPort > ePort:
            raise ValueError
    except ValueError:
        print("Geçersiz port aralığı girdiniz lütfen tekrar deneyiniz")
        exit(1)




















