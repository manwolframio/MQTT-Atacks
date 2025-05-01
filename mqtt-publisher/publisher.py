import os
import time
import json
import ntplib
import random
import socket
import paho.mqtt.client as mqtt
from datetime import datetime

# Configuración desde variables de entorno
broker = os.getenv("MQTT_BROKER", "localhost")
port = int(os.getenv("MQTT_PORT", "1883"))
client_id = os.getenv("MQTT_CLIENT_ID", "sensor:temperature:001")
patient_id = os.getenv("PATIENT_ID", "001")
measurement = os.getenv("MEASUREMENT_TYPE", "temperature")
interval_ms = int(os.getenv("MQTT_INTERVAL", "1000"))
username = os.getenv("MQTT_USERNAME", "")
password = os.getenv("MQTT_PASSWORD", "")

# Espera activa hasta que el broker esté disponible
def wait_for_broker(host, port, timeout=30):
    print(f"[ESPERA] Esperando al broker MQTT en {host}:{port}...")
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

# Obtener hora desde NTP
def get_ntp_time():
    try:
        client = ntplib.NTPClient()
        response = client.request('pool.ntp.org', version=3)
        return datetime.fromtimestamp(response.tx_time)
    except Exception as e:
        print(f"[NTP] Error: {e}")
        return None

# Generar valor según el tipo de sensor
def build_payload(zone=1, alarm=0, priority=1, status=1):
    if measurement == "temperature":
        value = round(random.uniform(36.0, 39.0), 2)
    elif measurement == "heartrate":
        value = round(random.uniform(60, 120), 1)
    elif measurement == "spo2":
        value = round(random.uniform(90, 100), 1)
    else:
        value = round(random.uniform(0, 100), 2)

    timestamp = get_ntp_time()
    ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S") if timestamp else "NTP_UNSYNCED"

    return {
        "timestamp": ts_str,
        "sensor_status": status,
        "zone": zone,
        "value": value,
        "priority": priority,
        "alarm": alarm
    }

# Construir el topic de publicación
def build_topic(patient_id, measurement):
    return f"uci/patients/patient-{patient_id}/{measurement}/1"

# Callback de conexión MQTT
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("[MQTT] Conectado al broker.")
    else:
        print(f"[MQTT] Error de conexión. Código: {rc}")

# Cliente MQTT v5
client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv5)
if username and password:
    client.username_pw_set(username, password)
client.on_connect = on_connect

# Esperar al broker antes de conectar
wait_for_broker(broker, port)
client.connect(broker, port,keepalive=5)
client.loop_start()

# Bucle principal de publicación
publicaciones = 0

try:
    while True:
        payload = build_payload()
        topic = build_topic(patient_id, measurement)
        message = json.dumps(payload)

        result = client.publish(topic, message)
        if result.rc == 0:
            print(f"[Publicado] → Topic: {topic}")
            print(f"[Mensaje]  → {message}")
        else:
            print(f"[Error] Falló la publicación. Código: {result.rc}")

        publicaciones += 1
        if publicaciones % 10 == 0:
            try:
                if not client.is_connected():
                    raise ConnectionError("Cliente desconectado.")
            except Exception as e:
                print(f"[PING] Error: {e}")
                print("[RECONEXIÓN] Reintentando conexión con el broker...")
                client.loop_stop()
                wait_for_broker(broker, port)
                client.reconnect()
                client.loop_start()
                print("[RECONEXIÓN] Reconexión completa.")

        time.sleep(interval_ms / 1000.0)

except KeyboardInterrupt:
    print("\n[FIN] Publicador detenido por el usuario.")
    client.loop_stop()
    client.disconnect()
