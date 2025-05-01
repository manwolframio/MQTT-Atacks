import sqlite3
import scapy.all as scapy
import subprocess
import sys
from scapy.layers.inet import TCP
from tabulate import tabulate

# Mostrar interfaces disponibles con tabulate
def listar_interfaces():
    interfaces = scapy.get_if_list()
    tabla = [[i, iface] for i, iface in enumerate(interfaces)]
    print(tabulate(tabla, headers=["#", "Interfaz"], tablefmt="grid"))
    idx = int(input("Selecciona una interfaz: "))
    return interfaces[idx]

# Activar modo promiscuo si no es un bridge de Docker
def activar_promiscuo(iface):
    if iface.startswith("br-") or iface.startswith("docker") or iface.startswith("virbr"):
        print(f"[INFO] No se activa modo promiscuo en {iface} (bridge virtual).")
        return
    try:
        subprocess.run(["ip", "link", "set", iface, "promisc", "on"], check=True)
        print(f"[INFO] Interfaz {iface} en modo promiscuo.")
    except Exception as e:
        print(f"[ERROR] No se pudo activar el modo promiscuo en {iface}: {e}")

# Inicializar base de datos SQLite
def init_db():
    conn = sqlite3.connect("mqtt_packets.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS mqtt_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT,
            payload TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn

# Extraer MQTT topic y payload correctamente
def parse_mqtt_payload(pkt, conn):
    raw = bytes(pkt[TCP].payload)
    if len(raw) < 4:
        return

    msg_type = (raw[0] >> 4) & 0x0F
    if msg_type != 3:  # Solo mensajes PUBLISH
        return

    # Parsear Remaining Length (MQTT variable-length encoding)
    remaining_length = 0
    multiplier = 1
    index = 1
    while True:
        if index >= len(raw):
            return
        encoded_byte = raw[index]
        remaining_length += (encoded_byte & 127) * multiplier
        multiplier *= 128
        index += 1
        if encoded_byte & 128 == 0:
            break

    if index + 2 > len(raw):
        return

    # Topic
    topic_len = int.from_bytes(raw[index:index+2], byteorder='big')
    topic_start = index + 2
    topic_end = topic_start + topic_len
    if topic_end > len(raw):
        return
    topic = raw[topic_start:topic_end].decode('utf-8', errors='ignore')

    # Payload
    payload = raw[topic_end:].decode('utf-8', errors='ignore')

    tabla = [
        ["Topic", topic],
        ["Payload", payload]
    ]
    print(tabulate(tabla, headers=["Campo", "Valor"], tablefmt="grid"))
    print()
    conn.execute("INSERT INTO mqtt_messages (topic, payload) VALUES (?, ?)", (topic, payload))
    conn.commit()

# Callback de Scapy
def captura(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 1883:
        parse_mqtt_payload(pkt, conn)

# Main
if __name__ == "__main__":
    iface = listar_interfaces()
    activar_promiscuo(iface)
    conn = init_db()
    print(f"[INFO] Capturando en {iface} (puerto 1883)...")
    try:
        scapy.sniff(iface=iface, prn=captura, filter="tcp port 1883", store=0)
    except KeyboardInterrupt:
        print("\n[FIN] Captura detenida por el usuario.")
        conn.close()
        sys.exit(0)
