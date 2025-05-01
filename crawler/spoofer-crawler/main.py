from db_utils import init_db
from mqtt_parser import listar_interfaces, parse_mqtt, captured
from spoof_utils import spoof_and_send
from scapy.all import sniff
from tabulate import tabulate
import time

if __name__ == "__main__":
    iface = listar_interfaces()
    conn = init_db()
    tiempo = int(input("¿Cuántos segundos deseas capturar mensajes MQTT? [default 30]: ") or 30)
    print(f"\n[*] Capturando durante {tiempo} segundos en {iface} (puerto 1883)...")
    end_time = time.time() + tiempo
    while time.time() < end_time:
        sniff(filter="tcp port 1883", iface=iface, prn=lambda pkt: parse_mqtt(pkt, conn), timeout=1)
    print("[✓] Captura completada.")

    if not captured:
        print("[!] No se capturaron mensajes.")
        exit(0)

    tabla = [[i, x['src_ip'], x['topic'], x['payload'], "✔" if x['editable'] else "✖"]
             for i, x in enumerate(captured)]
    print(tabulate(tabla, headers=["#", "IP", "Topic", "Payload", "Editable"], tablefmt="fancy_grid"))

    sel = int(input("\nSelecciona el mensaje a modificar y reenviar: "))
    spoof_and_send(sel, iface)

