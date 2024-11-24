import random
import re
import subprocess

def generate_mac():
    # İlk byte'ın en düşük bitini sıfır yaparak yerel yönetim bitini ayarla
    mac = [0x00, random.randint(0x00, 0x7F), 0x00, 0x00, 0x00, 0x00]
    for i in range(1, 6):
        mac[i] = random.randint(0x00, 0xFF)
    return ':'.join(map(lambda x: f"{x:02x}", mac))

new_mac = generate_mac()

# Eski MAC adresini almak için ifconfig komutunu çalıştır
ifconfig_response = subprocess.check_output("ifconfig eth0", shell=True).decode()

# Mevcut MAC adresini regex ile al
old_mac = re.search(r"ether ([\da-fA-F:]+)", ifconfig_response).group(1).strip()

try:
    # Ağ arayüzünü kapat
    subprocess.check_output("sudo ifconfig eth0 down", shell=True)

    # Yeni MAC adresini ayarla
    subprocess.check_output(f"sudo ifconfig eth0 hw ether {new_mac}", shell=True)

    # Ağ arayüzünü aç
    subprocess.check_output("sudo ifconfig eth0 up", shell=True)

    # Başarılı bir şekilde değiştiğinde eski ve yeni MAC adresini yazdır
    print("Eski MAC:", old_mac)
    print("Yeni MAC:", new_mac)
    input("Menüye dönmek için Enter'a basınız...")
except subprocess.CalledProcessError as e:
    print(f"Bir hata oluştu: {e}")
