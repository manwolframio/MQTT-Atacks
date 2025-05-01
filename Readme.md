# Evaluacion de la seguridad en MQTT - MUIT-EPS-UAH

## 1. Descripción general

Este proyecto permite la captura pasiva y activa de mensajes MQTT en una red local, su almacenamiento en una base de datos SQLite, su visualización estructurada y la capacidad de modificar y reenviar mensajes MQTT conservando la fidelidad binaria del paquete original. Se emplean técnicas de spoofing en capa 2 y capa 3 (Ethernet/IP) para falsificar origen MAC/IP de los paquetes transmitidos.

## 2. Componentes del sistema

- **`crawler.py`**: Captura pasivamente mensajes MQTT PUBLISH en una interfaz seleccionada usando `scapy`. Extrae el topic y el payload y los guarda en `mqtt_packets.db`.
- **`crawler_viewer.py`**: Visualiza mensajes almacenados en `mqtt_packets.db` en forma paginada y formateada usando `tabulate`.
- **`active-crawler.py`**: Captura mensajes MQTT, permite seleccionar y modificar campos del topic y del JSON del payload, y reenvía el paquete falsificando origen MAC/IP, preservando el resto del paquete MQTT.
- **`publisher.py`**: Publicador MQTT emulando sensores médicos. Obtiene hora vía NTP y publica periódicamente mensajes JSON estructurados.
- **`subscriber.py`**: Cliente MQTT que se suscribe a `uci/patients/#`, mostrando los datos de forma estructurada en consola.
- **`docker-compose.yaml`**: Orquesta servicios MQTT (`emqx`), publisher y subscriber. Asigna IPs fijas en red `mi_red`.

## 3. Requisitos

- Linux (necesario para modo promiscuo con Scapy)
- Python 3.8+
- Paquetes: `scapy`, `tabulate`, `paho-mqtt`, `ntplib`, `sqlite3`
- Permisos de superusuario para captura con `scapy`

## 4. Instalación

### 4.1 Python y dependencias

```bash
sudo apt update
sudo apt install python3 python3-pip sqlite3
pip3 install scapy tabulate paho-mqtt ntplib
```

### 4.2 Permisos para Scapy

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### 4.3 Base de datos

Se generan automáticamente al ejecutar los scripts:
- `mqtt_packets.db`: crawler pasivo
- `mqtt_spoofer.db`: crawler activo (spoof)

## 5. Uso

### 5.1 Captura pasiva

```bash
sudo python3 crawler.py
```

Selecciona una interfaz, activa el modo promiscuo y guarda los mensajes MQTT `PUBLISH`.

### 5.2 Visualización

```bash
python3 crawler_viewer.py
```

Muestra los mensajes de `mqtt_packets.db` ordenados por timestamp, paginados.

### 5.3 Spoof y modificación de mensajes

```bash
sudo python3 active-crawler.py
```

- Captura tráfico durante el tiempo definido por el usuario.
- Permite seleccionar un mensaje, editar el topic y payload JSON.
- Reenvía el paquete falsificando MAC/IP y reutilizando headers TCP sincronizados dinámicamente.

## 6. Seguridad

Este sistema simula ataques de inyección en entornos controlados con el objetivo de:
- Evaluar la resistencia de sistemas MQTT ante spoofing y replay attacks.
- Estudiar la seguridad de redes hospitalarias basadas en MQTT.

**Advertencia**: está prohibido utilizar este sistema en redes no autorizadas o productivas.

## 7. Bibliografía

- Banks, A., & Gupta, R. (2014). *MQTT Version 3.1.1*. OASIS Standard.
- Thangavel, D. et al. (2014). *Performance Evaluation of MQTT and CoAP via a Common Middleware*. IEEE ICC.
- Scapy Project. https://scapy.net
- EMQX MQTT Broker. https://www.emqx.io
- Paho MQTT. https://www.eclipse.org/paho/
- SQLite3. https://sqlite.org
- Python Socket Library. https://docs.python.org/3/library/socket.html

## 8. Licencia

Este proyecto es de uso académico y está licenciado bajo los términos de uso personal para investigación y docencia. No se autoriza su uso en entornos comerciales o con fines maliciosos.
