from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import ipaddress
import logging
import warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
logging.basicConfig(filename='host_discovery_arp.log', level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
def logEvent(event):
    logging.info(event)

def scan(ip_network):
    # Ethernet çerçevesi oluşturuluyor
    eth = Ether()
    eth.dst = "ff:ff:ff:ff:ff:ff"  # Yayın (broadcast) adresi

    # ARP paketi oluşturuluyor
    arp = ARP()
    arp.pdst = str(ip_network)  # Kullanıcının girdiği IP aralığı

    # Ethernet ve ARP paketleri birleştiriliyor
    broadcast_pckt = eth / arp

    # Paketi gönderip yanıtları bekliyoruz
    ans, unans = srp(broadcast_pckt, timeout=1, verbose=False)
    return ans,unans




def main():
    while True:
        try:
            # Kullanıcıdan IP adresi aralığını alma
            ip_range = input("Taranacak IP aralığını girin (örneğin 192.168.116.1/24): ")

            # IP aralığının geçerliliğini kontrol etme
            ip_network = ipaddress.ip_network(ip_range, strict=False)
            break  # Geçerli bir IP aralığı ise döngüden çık

        except ValueError:
            print("Geçersiz IP aralığı! Lütfen geçerli bir IP aralığı girin.")

    ans, unans = scan(ip_network)

    # Yanıtları işleme
    print("#" * 50)
    print("IP Adresi" + " " * 18 + "MAC Adresi")
    print("-" * 50)

    for snd, rcv in ans:
        logEvent(print(rcv.psrc.ljust(20) + rcv.hwsrc))

    # Yanıt vermeyen cihazlar
    if unans:
        print("\nYanıt Vermeyen Cihazlar:")
        for pkt in unans:
            print(pkt[ARP].pdst)

    print("-" * 50)

    # yeniden deneme
    retry = input("Yanıt vermeyen cihazlar için yeniden denemek isterseniz 'e' / Ana menüye dönmek için 'h' \n")
    if retry.lower() == 'e':
        print("Yeniden deneme yapılıyor...")
        ans, unans = scan(ip_network)
        for snd, rcv in ans:
            output = f"{rcv.psrc.ljust(20)} {rcv.hwsrc}"
            print(output)
            logEvent(output)
    elif retry.lower() == 'h':
        input("Enter'a basınız...")

if __name__ == "__main__":
    main()






















