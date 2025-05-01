import os
import json
import time
import signal
import socket
import queue
from tabulate import tabulate
import paho.mqtt.client as mqtt

MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "uci/patients/#")
CLIENT_ID = os.getenv("MQTT_CLIENT_ID", "subscriber-console")

message_queue = queue.Queue()

def handle_exit(sig, frame):
    print("\n[INFO] Subscriber detenido.")
    client.disconnect()
    exit(0)

signal.signal(signal.SIGINT, handle_exit)

# Espera activa al broker
def wait_for_broker(host, port, timeout=30):
    print(f"[ESPERA] Esperando al broker en {host}:{port}...")
    start_time = time.time()
    while True:
        try:
            with socket.create_connection((host, port), timeout=2):
                print("[ESPERA] Broker disponible.")
                return
        except OSError:
            if time.time() - start_time > timeout:
                print("[ERROR] Tiempo de espera agotado para conectar al broker.")
                exit(1)
            time.sleep(1)

def on_message(client, userdata, msg):
    try:
        topic = msg.topic
        payload = msg.payload.decode()
        data = json.loads(payload)
        message_queue.put((topic, data))
    except Exception as e:
        print(f"[ERROR] al procesar mensaje: {e}")

def on_connect(client, userdata, flags, reasonCode, properties):
    if reasonCode == 0:
        print(f"[MQTT] Conectado a {MQTT_BROKER}:{MQTT_PORT}")
        client.subscribe(MQTT_TOPIC)
        print(f"[MQTT] Suscrito a: {MQTT_TOPIC}")
    else:
        print(f"[MQTT] Error de conexión: {reasonCode}")

client = mqtt.Client(
    client_id=CLIENT_ID,
    protocol=mqtt.MQTTv5
)

client.on_connect = on_connect
client.on_message = on_message

wait_for_broker(MQTT_BROKER, MQTT_PORT)
client.connect(MQTT_BROKER, MQTT_PORT)
client.loop_start()

def display_loop():
    print("\nEsperando mensajes... Presiona Ctrl+C para salir.\n")
    while True:
        try:
            topic, data = message_queue.get(timeout=1)
            parts = topic.split('/')
            patient_id = parts[3] if len(parts) > 3 else "desconocido"
            measurement = parts[4] if len(parts) > 4 else "desconocido"
            zone = parts[5] if len(parts) > 5 else "?"

            table = [
                ["Topic", topic],
                ["Patient ID", patient_id],
                ["Measurement", measurement],
                ["Zone", zone],
                ["Timestamp", data.get("timestamp", "?")],
                ["Value", data.get("value", "?")],
                ["Status", data.get("sensor_status", "?")],
                ["Priority", data.get("priority", "?")],
                ["Alarm", data.get("alarm", "?")]
            ]

            print(tabulate(table, headers=["Campo", "Valor"], tablefmt="grid"))
            print("\n\n")
        except queue.Empty:
            continue

display_loop()
