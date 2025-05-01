from scapy.all import *
import json
from tabulate import tabulate

captured = []

def decode_variable_length(data, index):
    multiplier = 1
    value = 0
    bytes_used = 0
    while True:
        byte = data[index]
        value += (byte & 127) * multiplier
        bytes_used += 1
        if (byte & 128) == 0:
            break
        index += 1
        multiplier *= 128
    return value, bytes_used

def parse_mqtt(pkt, *args, **kwargs):
    if not pkt.haslayer(TCP):
        return

    tcp_payload = bytes(pkt[TCP].payload)
    if not tcp_payload or tcp_payload[0] >> 4 != 3:  # Not a PUBLISH
        return

    index = 0
    fixed_header = tcp_payload[index]
    index += 1

    remaining_length, rl_bytes = decode_variable_length(tcp_payload, index)
    index += rl_bytes

    # Topic
    topic_len = int.from_bytes(tcp_payload[index:index+2], 'big')
    index += 2
    topic = tcp_payload[index:index+topic_len].decode('utf-8')
    index += topic_len

    qos = (fixed_header & 0b00000110) >> 1
    packet_id = None
    if qos > 0:
        packet_id = int.from_bytes(tcp_payload[index:index+2], 'big')
        index += 2

    # MQTT v5: Properties Length + Properties
    try:
        properties_length, pl_bytes = decode_variable_length(tcp_payload, index)
        properties_length_bytes = tcp_payload[index:index+pl_bytes]
        index += pl_bytes
        properties_raw = tcp_payload[index:index+properties_length]
        index += properties_length
    except IndexError:
        properties_length_bytes = b''
        properties_raw = b''

    # Payload
    payload = tcp_payload[index:].decode('utf-8', errors='replace')

    captured.append({
        "fixed_header": fixed_header,
        "remaining_length": remaining_length,
        "topic": topic,
        "topic_len": topic_len,
        "packet_id": packet_id,
        "qos": qos,
        "properties_length_bytes": properties_length_bytes,
        "properties_raw": properties_raw,
        "payload": payload,
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "src_port": pkt[TCP].sport,
        "dst_port": pkt[TCP].dport,
        "src_mac": pkt[Ether].src,
        "dst_mac": pkt[Ether].dst,
        "raw": tcp_payload,
        "editable": True
    })

def start_capture(iface):
    sniff(iface=iface, filter="tcp port 1883", prn=parse_mqtt, store=0)

def listar_interfaces():
    interfaces = get_if_list()
    tabla = [[i, iface] for i, iface in enumerate(interfaces)]
    print(tabulate(tabla, headers=["#", "Interfaz"], tablefmt="grid"))
    idx = int(input("Selecciona la interfaz de red a usar: "))
    return interfaces[idx]