import sqlite3
from tabulate import tabulate

DB_PATH = "mqtt_packets.db"

def mostrar_mensajes(pagina=1, por_pagina=20):
    offset = (pagina - 1) * por_pagina
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id, topic, payload, timestamp
        FROM mqtt_messages
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """, (por_pagina, offset))
    resultados = c.fetchall()
    conn.close()

    if not resultados:
        print("[INFO] No hay más mensajes para mostrar.")
        return False

    tabla = tabulate(resultados, headers=["ID", "Topic", "Payload", "Timestamp"],
                     tablefmt="grid", maxcolwidths=[None, 40, 60, None])
    print(tabla)
    return True

if __name__ == "__main__":
    pagina = 1
    while True:
        tiene_datos = mostrar_mensajes(pagina)
        if not tiene_datos:
            break
        opcion = input("\nPresiona [Enter] para ver más, o escribe 'q' para salir: ").strip().lower()
        if opcion == "q":
            break
        pagina += 1

