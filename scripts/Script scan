import paramiko
import time
import re
from datetime import datetime

# ---------- CONFIGURACIÓN ----------
HOST = "10.8.46.1"
USUARIO = "user10"
CLAVE = "AQUI_PONES_LA_CLAVE_DE_USER10"      # ← cambia esto
REPORTE_ARCHIVO = "informe_hardening_r1.txt"
CONFIG_BACKUP = "r1_running.txt"
# -----------------------------------

def auditar_hardening_cis(config_text):
    reglas = [
        {
            "id": "CIS-1.1",
            "titulo": "Servicio de cifrado de contraseñas activado",
            "comando_esperado": "service password-encryption",
            "patron": r"^service password-encryption",
            "inverso": False,
            "severidad": "MEDIA",
        },
        {
            "id": "CIS-1.2",
            "titulo": "Deshabilitar servicios tcp/udp-small-servers",
            "comando_esperado": "no service tcp-small-servers / no service udp-small-servers",
            "patron": r"^service (tcp|udp)-small-servers",
            "inverso": True,
            "severidad": "BAJA",
        },
        {
            "id": "CIS-2.1",
            "titulo": "AAA Habilitado globalmente",
            "comando_esperado": "aaa new-model",
            "patron": r"^aaa new-model",
            "inverso": False,
            "severidad": "ALTA",
        },
        {
            "id": "CIS-3.1",
            "titulo": "Deshabilitar CDP globalmente",
            "comando_esperado": "no cdp run",
            "patron": r"^no cdp run",
            "inverso": False,
            "severidad": "MEDIA",
        },
        {
            "id": "CIS-3.2",
            "titulo": "Deshabilitar servidor HTTP no seguro",
            "comando_esperado": "no ip http server",
            "patron": r"^no ip http server",
            "inverso": False,
            "severidad": "MEDIA",
        },
        {
            "id": "CIS-3.3",
            "titulo": "Deshabilitar IP Source Routing",
            "comando_esperado": "no ip source-route",
            "patron": r"^no ip source-route",
            "inverso": False,
            "severidad": "MEDIA",
        },
        {
            "id": "CIS-3.4",
            "titulo": "Deshabilitar respuestas ICMP Redirects",
            "comando_esperado": "no ip redirects",
            "patron": r"no ip redirects",
            "inverso": False,
            "severidad": "BAJA",
        },
        {
            "id": "CIS-4.1",
            "titulo": "Registro de eventos (Logging) en buffer",
            "comando_esperado": "logging buffered",
            "patron": r"^logging buffered",
            "inverso": False,
            "severidad": "MEDIA",
        },
        {
            "id": "CIS-4.2",
            "titulo": "Sellado de tiempo en logs (Timestamps)",
            "comando_esperado": "service timestamps log datetime msec",
            "patron": r"^service timestamps log datetime",
            "inverso": False,
            "severidad": "BAJA",
        },
        {
            "id": "CIS-5.1",
            "titulo": "Banner de advertencia configurado (MOTD / Login)",
            "comando_esperado": "banner motd / banner login",
            "patron": r"^banner (motd|login)",
            "inverso": False,
            "severidad": "BAJA",
        },
        {
            "id": "CIS-6.1",
            "titulo": "Restricción de transporte SSH en líneas VTY",
            "comando_esperado": "transport input ssh",
            "patron": r"transport input ssh",
            "inverso": False,
            "severidad": "ALTA",
        },
        {
            "id": "CIS-6.2",
            "titulo": "Timeout de inactividad configurado en líneas",
            "comando_esperado": "exec-timeout",
            "patron": r"exec-timeout \d+",
            "inverso": False,
            "severidad": "MEDIA",
        },
    ]

    resultados = []
    puntos_cumplidos = 0

    for r in reglas:
        match = re.search(r["patron"], config_text, re.MULTILINE | re.IGNORECASE)
        cumple = not bool(match) if r.get("inverso") else bool(match)

        if cumple:
            puntos_cumplidos += 1
            estado = "CUMPLE"
        else:
            estado = "NO CUMPLE"

        resultados.append({
            "id": r["id"],
            "titulo": r["titulo"],
            "severidad": r["severidad"],
            "esperado": r["comando_esperado"],
            "estado": estado,
        })

    total = len(reglas)
    porcentaje = (puntos_cumplidos / total) * 100

    lineas = [
        "=" * 80,
        "       INFORME DE AUDITORÍA DE HARDENING CIS - CISCO IOS",
        "=" * 80,
        f"Dispositivo Objetivo : {HOST}",
        f"Fecha de Auditoría   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Modo de Operación    : SOLO LECTURA (Sin aplicar reglas)",
        f"Puntuación Obtenida  : {puntos_cumplidos}/{total} ({porcentaje:.1f}%)",
        "-" * 80,
        f"{'ID':<10} | {'SEVERIDAD':<10} | {'ESTADO':<10} | {'CONTROL EVALUADO'}",
        "-" * 80,
    ]

    for item in resultados:
        lineas.append(
            f"{item['id']:<10} | {item['severidad']:<10} | {item['estado']:<10} | {item['titulo']}"
        )
        if item["estado"] == "NO CUMPLE":
            lineas.append(f"  └─ Remedio recomendado: {item['esperado']}")

    lineas.append("=" * 80)
    lineas.append("Fin del reporte de auditoría.")

    return "\n".join(lineas)


def conectar_y_leer():
    print("[*] Conectando a R1...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=HOST,
        username=USUARIO,
        password=CLAVE,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
        disabled_algorithms={
            "kex": [
                "diffie-hellman-group-exchange-sha256",
                "diffie-hellman-group16-sha512",
                "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384",
                "ecdh-sha2-nistp521",
                "curve25519-sha256",
                "curve25519-sha256@libssh.org",
            ],
            "ciphers": [
                "aes128-ctr",
                "aes192-ctr",
                "aes256-ctr",
                "aes128-gcm@openssh.com",
                "aes256-gcm@openssh.com",
                "chacha20-poly1305@openssh.com",
            ],
        },
    )

    print("[+] Conectado. Abriendo shell...")
    shell = client.invoke_shell()
    time.sleep(2)

    # Limpiar banner inicial
    while shell.recv_ready():
        shell.recv(65535)
        time.sleep(0.2)

    # Desactivar paginación
    print("[*] Enviando terminal length 0...")
    shell.send("terminal length 0\n")
    time.sleep(1)
    while shell.recv_ready():
        shell.recv(65535)
        time.sleep(0.2)

    # Pedir la configuración
    print("[*] Pidiendo show running-config...")
    shell.send("show running-config\n")
    time.sleep(2)

    # Leer todo el output
    output = ""
    vacio = 0
    while vacio < 12:
        if shell.recv_ready():
            trozo = shell.recv(65535).decode("utf-8", errors="ignore")
            output += trozo
            vacio = 0
            print(f"  → +{len(trozo)} caracteres (total: {len(output)})")
        else:
            vacio += 1
            time.sleep(0.4)

    # Guardar running-config original
    with open(CONFIG_BACKUP, "w") as f:
        f.write(output)

    print(f"\n[+] Guardado en {CONFIG_BACKUP}")
    print(f"[+] Tamaño: {len(output)} caracteres")
    print("\n--- Últimas 8 líneas ---")
    print("\n".join(output.strip().splitlines()[-8:]))

    shell.close()
    client.close()

    # Generación y guardado del informe
    print("\n[*] Generando informe de hardening CIS...")
    informe = auditar_hardening_cis(output)

    print("\n" + informe + "\n")

    with open(REPORTE_ARCHIVO, "w", encoding="utf-8") as f:
        f.write(informe)

    print(f"[+] Informe guardado en {REPORTE_ARCHIVO}")


if __name__ == "__main__":
    conectar_y_leer()
