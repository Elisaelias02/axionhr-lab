"""
AxionHR API - Vulnerable Lab Environment
=========================================
Vulnerabilidades demostradas:
  [1] UUID4 con PRNG débil (random.seed(time) en lugar de os.urandom)
  [2] BOLA — acceso a expedientes de empleados de otros tenants
  [3] Mass Assignment — asignación de rol via PATCH sin whitelist
  [4] Exfiltración masiva post-escalada

Diseñado para demostración educativa — Cinn4mor0ll / AEGIS Security
"""

from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flasgger import Swagger
import sqlite3, jwt, datetime, uuid, os, random, time

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'axionhr-secret-2026'

DATABASE = 'axionhr.db'

# ─── Swagger ──────────────────────────────────────────────────
swagger_template = {
    "info": {
        "title": "AxionHR API",
        "description": "Plataforma SaaS de Recursos Humanos B2B — API REST v3",
        "version": "3.0.1",
        "contact": {"email": "api@axionhr.io"}
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT: Bearer <token>"
        }
    },
    "host": "localhost:5000",
    "basePath": "/api/v1",
    "schemes": ["http", "https"]
}

swagger_config = {
    "headers": [],
    "specs": [{"endpoint": "apispec", "route": "/apispec.json"}],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs/"
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)

# ─── DB helpers ───────────────────────────────────────────────
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur

# ─── UUID4 VULNERABLE ─────────────────────────────────────────
def generate_weak_uuid4():
    """
    ⚠️  VULNERABLE: usa random.seed(int(time.time()))
    El seed es el timestamp en segundos — espacio de búsqueda
    colapsado a ~300 valores para una ventana de 5 minutos.
    Un atacante que conoce la ventana de registro puede
    reproducir todos los UUIDs generados en ese período.
    """
    random.seed(int(time.time()))
    return str(uuid.UUID(int=random.getrandbits(128), version=4))

# ─── JWT helpers ──────────────────────────────────────────────
def generate_token(user_id, tenant_id, rol):
    payload = {
        'user_id': user_id,
        'tenant_id': tenant_id,
        'rol': rol,
        'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=8),
        'iat': datetime.datetime.now(datetime.UTC)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        return None

def get_current_user():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    return decode_token(auth.split(' ')[1])

# ─── Init DB ──────────────────────────────────────────────────
def init_db():
    with app.app_context():
        db = get_db()
        db.executescript('''
            DROP TABLE IF EXISTS usuarios;
            DROP TABLE IF EXISTS tenants;
            DROP TABLE IF EXISTS empleados;
            DROP TABLE IF EXISTS expedientes;
            DROP TABLE IF EXISTS incidencias;

            CREATE TABLE tenants (
                id TEXT PRIMARY KEY,
                nombre TEXT NOT NULL,
                rfc TEXT UNIQUE NOT NULL,
                plan TEXT DEFAULT 'basico',
                fecha_alta TEXT,
                activo INTEGER DEFAULT 1
            );

            CREATE TABLE usuarios (
                id TEXT PRIMARY KEY,
                nombre TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                rol TEXT NOT NULL,
                tenant_id TEXT,
                empleado_id TEXT,
                activo INTEGER DEFAULT 1,
                fecha_registro TEXT
            );

            CREATE TABLE empleados (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                nombre TEXT NOT NULL,
                apellido_paterno TEXT NOT NULL,
                apellido_materno TEXT NOT NULL,
                curp TEXT UNIQUE NOT NULL,
                nss TEXT UNIQUE NOT NULL,
                rfc TEXT NOT NULL,
                puesto TEXT NOT NULL,
                departamento TEXT,
                fecha_ingreso TEXT,
                estatus TEXT DEFAULT 'activo'
            );

            CREATE TABLE expedientes (
                id TEXT PRIMARY KEY,
                empleado_id TEXT UNIQUE NOT NULL,
                tenant_id TEXT NOT NULL,
                salario_mensual REAL NOT NULL,
                banco TEXT,
                clabe TEXT,
                tipo_contrato TEXT,
                fecha_contrato TEXT,
                num_imss TEXT,
                regimen_fiscal TEXT,
                contacto_emergencia TEXT,
                telefono_personal TEXT
            );

            CREATE TABLE incidencias (
                id TEXT PRIMARY KEY,
                empleado_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                tipo TEXT NOT NULL,
                descripcion TEXT,
                fecha TEXT,
                resolucion TEXT
            );
        ''')

        # ── Tenants seed ──────────────────────────────────────
        tenants = [
            ('tenant-meridian-001', 'Constructora Meridian S.A. de C.V.', 'CME801215AB1', 'enterprise', '2022-03-10'),
            ('tenant-vertex-002',   'Logística Vértex S.A. de C.V.',      'LVE190520CD3', 'pro',        '2023-06-15'),
            ('tenant-axionhr-000',  'AxionHR Operadora S.A.P.I.',         'AHO150901XY9', 'admin',      '2021-01-01'),
        ]
        db.executemany('INSERT INTO tenants VALUES (?,?,?,?,?,1)', tenants)

        # ── Seed de empleados con UUIDs "débiles" simulados ───
        # En producción estos se generarían con generate_weak_uuid4()
        # Para el lab usamos UUIDs fijos pero el endpoint de registro
        # usa el generador débil real

        empleados = [
            # Constructora Meridian
            ('emp-mer-001-uuid4w', 'tenant-meridian-001', 'Carlos',    'Ramírez',   'Orozco',   'RAOC850312HDFRRL08', '45612378901', 'RAOC850312AB1', 'Gerente de Obra',        'Operaciones',  '2022-03-15', 'activo'),
            ('emp-mer-002-uuid4w', 'tenant-meridian-001', 'Sofía',     'Herrera',   'Leal',     'HELS920605MDFRRN02', '45698712340', 'HELS920605CD2', 'Contadora',              'Finanzas',     '2022-04-01', 'activo'),
            ('emp-mer-003-uuid4w', 'tenant-meridian-001', 'Miguel',    'Torres',    'Vega',     'TOVM780901HDFRRS07', '45634567890', 'TOVM780901EF3', 'Director de Proyectos',  'Dirección',    '2022-03-10', 'activo'),
            ('emp-mer-004-uuid4w', 'tenant-meridian-001', 'Ana',       'Gutiérrez', 'Flores',   'GUFA950215MDFLTL05', '45623456789', 'GUFA950215GH4', 'Arquitecta',             'Diseño',       '2023-01-10', 'activo'),
            ('emp-mer-005-uuid4w', 'tenant-meridian-001', 'Roberto',   'Sánchez',   'Morales',  'SAMR881120HDFRNB04', '45645678901', 'SAMR881120IJ5', 'Residente de Obra',      'Operaciones',  '2023-03-20', 'activo'),
            # Logística Vértex
            ('emp-ver-001-uuid4w', 'tenant-vertex-002',   'Diana',     'Mendoza',   'Castro',   'MECD910808MDFNSI01', '67823456789', 'MECD910808KL6', 'Coordinadora Logística', 'Operaciones',  '2023-06-20', 'activo'),
            ('emp-ver-002-uuid4w', 'tenant-vertex-002',   'Jorge',     'López',     'Ruiz',     'LORJ870330HDFPZR06', '67834567890', 'LORJ870330MN7', 'Chofer Senior',          'Transporte',   '2023-07-01', 'activo'),
            ('emp-ver-003-uuid4w', 'tenant-vertex-002',   'Valentina', 'Cruz',      'Jiménez',  'CUJV001115MDFRZL09', '67845678901', 'CUJV001115OP8', 'Analista de Rutas',      'Planeación',   '2024-01-15', 'activo'),
        ]
        db.executemany('INSERT INTO empleados VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', empleados)

        # ── Expedientes con datos sensibles ───────────────────
        expedientes = [
            ('exp-mer-001', 'emp-mer-001-uuid4w', 'tenant-meridian-001', 87_500.00,  'BBVA',     '012180045678901234', 'indefinido',  '2022-03-15', '45612378901', '605', 'María Ramírez — 5512345678', '5598765432'),
            ('exp-mer-002', 'emp-mer-002-uuid4w', 'tenant-meridian-001', 52_000.00,  'Santander','014180056789012345', 'indefinido',  '2022-04-01', '45698712340', '612', 'Pedro Herrera — 5523456789',  '5587654321'),
            ('exp-mer-003', 'emp-mer-003-uuid4w', 'tenant-meridian-001', 135_000.00, 'Banamex',  '021180067890123456', 'indefinido',  '2022-03-10', '45634567890', '611', 'Laura Torres — 5534567890',   '5576543210'),
            ('exp-mer-004', 'emp-mer-004-uuid4w', 'tenant-meridian-001', 68_000.00,  'Banorte',  '006180078901234567', 'indefinido',  '2023-01-10', '45623456789', '612', 'Luis Gutiérrez — 5545678901', '5565432109'),
            ('exp-mer-005', 'emp-mer-005-uuid4w', 'tenant-meridian-001', 45_000.00,  'BBVA',     '012180089012345678', 'determinado', '2023-03-20', '45645678901', '605', 'Rosa Sánchez — 5556789012',   '5554321098'),
            ('exp-ver-001', 'emp-ver-001-uuid4w', 'tenant-vertex-002',   61_500.00,  'HSBC',     '021180090123456789', 'indefinido',  '2023-06-20', '67823456789', '612', 'Carlos Mendoza — 5567890123', '5543210987'),
            ('exp-ver-002', 'emp-ver-002-uuid4w', 'tenant-vertex-002',   38_000.00,  'Azteca',   '127180001234567890', 'indefinido',  '2023-07-01', '67834567890', '605', 'Ana López — 5578901234',      '5532109876'),
            ('exp-ver-003', 'emp-ver-003-uuid4w', 'tenant-vertex-002',   55_000.00,  'BBVA',     '012180012345678901', 'determinado', '2024-01-15', '67845678901', '612', 'Mario Cruz — 5589012345',     '5521098765'),
        ]
        db.executemany('INSERT INTO expedientes VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', expedientes)

        # ── Usuarios seed ─────────────────────────────────────
        now = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        usuarios = [
            # Admin AxionHR
            ('usr-axion-admin', 'Admin AxionHR', 'admin@axionhr.io', 'axion2026', 'super_admin', 'tenant-axionhr-000', None, 1, now),
            # HR Admin Meridian
            ('usr-mer-admin', 'Ingrid Salazar Torres', 'i.salazar@meridian.com.mx', 'meridian2026', 'hr_admin', 'tenant-meridian-001', None, 1, now),
            # Empleados Meridian
            ('usr-mer-emp1', 'Carlos Ramírez Orozco',  'c.ramirez@meridian.com.mx',  'emp2026', 'empleado', 'tenant-meridian-001', 'emp-mer-001-uuid4w', 1, now),
            ('usr-mer-emp2', 'Sofía Herrera Leal',     's.herrera@meridian.com.mx',  'emp2026', 'empleado', 'tenant-meridian-001', 'emp-mer-002-uuid4w', 1, now),
            # HR Admin Vértex
            ('usr-ver-admin', 'Jorge Fuentes Ríos', 'j.fuentes@vertexlog.com.mx', 'vertex2026', 'hr_admin', 'tenant-vertex-002', None, 1, now),
            # Empleados Vértex
            ('usr-ver-emp1', 'Diana Mendoza Castro',  'd.mendoza@vertexlog.com.mx', 'emp2026', 'empleado', 'tenant-vertex-002', 'emp-ver-001-uuid4w', 1, now),
        ]
        db.executemany('INSERT INTO usuarios VALUES (?,?,?,?,?,?,?,?,?)', usuarios)

        # ── Incidencias ───────────────────────────────────────
        incidencias = [
            ('inc-001', 'emp-mer-001-uuid4w', 'tenant-meridian-001', 'ausencia', 'Falta injustificada', '2026-03-15', 'Amonestación verbal'),
            ('inc-002', 'emp-mer-003-uuid4w', 'tenant-meridian-001', 'sancion',  'Retraso en entrega de proyecto Q1', '2026-04-10', 'Descuento de bono'),
            ('inc-003', 'emp-ver-002-uuid4w', 'tenant-vertex-002',   'ausencia', 'Incapacidad IMSS 3 días', '2026-02-20', 'Justificada'),
        ]
        db.executemany('INSERT INTO incidencias VALUES (?,?,?,?,?,?,?)', incidencias)

        db.commit()
        print("✅ AxionHR — Base de datos inicializada")


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════

# ─── Auth: Registro público ───────────────────────────────────
@app.route('/api/v1/auth/registro', methods=['POST'])
def registro():
    """
    Registro público de empleado en AxionHR
    ---
    tags:
      - Autenticación
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [nombre, email, password, tenant_code, curp, nss]
          properties:
            nombre:       { type: string, example: "Ana Torres Reyes" }
            email:        { type: string, example: "ana@empresa.com" }
            password:     { type: string, example: "MiPass2026!" }
            tenant_code:  { type: string, example: "CME801215AB1" }
            curp:         { type: string, example: "TORA990812MDFRRN01" }
            nss:          { type: string, example: "12345678901" }
            puesto:       { type: string, example: "Desarrolladora" }
    responses:
      201:
        description: |
          Empleado registrado. Retorna JWT y empleado_id generado.
          **NOTA TÉCNICA**: El empleado_id se genera con UUID4.
      400:
        description: Campos faltantes o duplicados
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body requerido'}), 400

    required = ['nombre', 'email', 'password', 'tenant_code', 'curp', 'nss']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({'error': f'Campos requeridos: {", ".join(missing)}'}), 400

    tenant = query_db('SELECT * FROM tenants WHERE rfc=?', [data['tenant_code']], one=True)
    if not tenant:
        return jsonify({'error': 'Código de empresa no válido'}), 400

    if query_db('SELECT id FROM usuarios WHERE email=?', [data['email']], one=True):
        return jsonify({'error': 'El correo ya está registrado'}), 400

    if query_db('SELECT id FROM empleados WHERE curp=?', [data['curp']], one=True):
        return jsonify({'error': 'CURP ya registrada'}), 400

    # ⚠️  VULNERABLE: UUID4 generado con PRNG débil
    #     random.seed(int(time.time())) — seed predecible
    empleado_id = generate_weak_uuid4()
    user_id     = generate_weak_uuid4()
    fecha_hoy   = datetime.datetime.now().strftime('%Y-%m-%d')
    fecha_reg   = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

    nombre_split = data['nombre'].split(' ')
    nombre       = nombre_split[0]
    ap_pat       = nombre_split[1] if len(nombre_split) > 1 else ''
    ap_mat       = nombre_split[2] if len(nombre_split) > 2 else ''

    execute_db(
        'INSERT INTO empleados VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
        [empleado_id, tenant['id'], nombre, ap_pat, ap_mat,
         data['curp'].upper(), data['nss'],
         data['curp'][:4].upper() + data['curp'][4:10] + 'XX1',
         data.get('puesto', 'Empleado'), 'General', fecha_hoy, 'activo']
    )

    execute_db(
        'INSERT INTO usuarios VALUES (?,?,?,?,?,?,?,?,?)',
        [user_id, data['nombre'], data['email'], data['password'],
         'empleado', tenant['id'], empleado_id, 1, fecha_reg]
    )

    # Expediente básico
    exp_id = generate_weak_uuid4()
    execute_db(
        'INSERT INTO expedientes VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
        [exp_id, empleado_id, tenant['id'], 0.0, '', '', 'determinado',
         fecha_hoy, data['nss'], '612', '', '']
    )

    token = generate_token(user_id, tenant['id'], 'empleado')

    return jsonify({
        'mensaje': 'Empleado registrado exitosamente',
        'token': token,
        'empleado': {
            'id': empleado_id,
            'nombre': data['nombre'],
            'tenant_id': tenant['id'],
            'tenant_nombre': tenant['nombre'],
            'rol': 'empleado',
            'fecha_registro': fecha_reg
        }
    }), 201


# ─── Auth: Login ──────────────────────────────────────────────
@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """
    Login de usuarios
    ---
    tags:
      - Autenticación
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            email:    { type: string, example: "c.ramirez@meridian.com.mx" }
            password: { type: string, example: "emp2026" }
    responses:
      200:
        description: JWT de sesión
      401:
        description: Credenciales inválidas
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body requerido'}), 400

    user = query_db(
        'SELECT * FROM usuarios WHERE email=? AND password=?',
        [data.get('email'), data.get('password')], one=True
    )
    if not user:
        return jsonify({'error': 'Credenciales inválidas'}), 401

    token = generate_token(user['id'], user['tenant_id'], user['rol'])
    return jsonify({
        'token': token,
        'usuario': {
            'id': user['id'],
            'nombre': user['nombre'],
            'email': user['email'],
            'rol': user['rol'],
            'tenant_id': user['tenant_id'],
            'empleado_id': user['empleado_id']
        }
    })


# ─── Empleados ────────────────────────────────────────────────
@app.route('/api/v1/empleados/<empleado_id>', methods=['GET'])
def get_empleado(empleado_id):
    """
    Perfil básico de un empleado
    ---
    tags:
      - Empleados
    security:
      - Bearer: []
    parameters:
      - in: path
        name: empleado_id
        type: string
        required: true
    responses:
      200:
        description: |
          Perfil del empleado.
          La respuesta incluye tenant_id para operaciones internas.
      401:
        description: No autorizado
      404:
        description: Empleado no encontrado
    """
    user = get_current_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 401

    # ⚠️  BOLA: no valida que empleado_id pertenezca al tenant del usuario
    emp = query_db('SELECT * FROM empleados WHERE id=?', [empleado_id], one=True)
    if not emp:
        return jsonify({'error': 'Empleado no encontrado'}), 404

    return jsonify({
        'id': emp['id'],
        'tenant_id': emp['tenant_id'],          # ← expuesto innecesariamente
        'nombre_completo': f"{emp['nombre']} {emp['apellido_paterno']} {emp['apellido_materno']}",
        'curp': emp['curp'],
        'nss': emp['nss'],
        'puesto': emp['puesto'],
        'departamento': emp['departamento'],
        'fecha_ingreso': emp['fecha_ingreso'],
        'estatus': emp['estatus']
    })


@app.route('/api/v1/empleados/<empleado_id>/expediente', methods=['GET'])
def get_expediente(empleado_id):
    """
    Expediente completo de un empleado (datos sensibles)
    ---
    tags:
      - Empleados
    security:
      - Bearer: []
    parameters:
      - in: path
        name: empleado_id
        type: string
        required: true
    responses:
      200:
        description: Expediente con salario, CLABE, IMSS y datos personales
      401:
        description: No autorizado
    """
    user = get_current_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 401

    # ⚠️  BOLA: cualquier usuario autenticado accede al expediente de cualquier empleado
    emp = query_db('SELECT * FROM empleados WHERE id=?', [empleado_id], one=True)
    if not emp:
        return jsonify({'error': 'Empleado no encontrado'}), 404

    exp = query_db('SELECT * FROM expedientes WHERE empleado_id=?', [empleado_id], one=True)

    incidencias = query_db(
        'SELECT tipo, descripcion, fecha, resolucion FROM incidencias WHERE empleado_id=?',
        [empleado_id]
    )

    return jsonify({
        'empleado': {
            'id': emp['id'],
            'nombre_completo': f"{emp['nombre']} {emp['apellido_paterno']} {emp['apellido_materno']}",
            'curp': emp['curp'],
            'nss': emp['nss'],
            'rfc': emp['rfc'],
            'puesto': emp['puesto'],
            'departamento': emp['departamento'],
            'fecha_ingreso': emp['fecha_ingreso'],
        },
        'datos_laborales': {
            'salario_mensual': exp['salario_mensual'] if exp else 0,
            'tipo_contrato': exp['tipo_contrato'] if exp else '',
            'fecha_contrato': exp['fecha_contrato'] if exp else '',
            'regimen_fiscal': exp['regimen_fiscal'] if exp else '',
        },
        'datos_bancarios': {
            'banco': exp['banco'] if exp else '',
            'clabe': exp['clabe'] if exp else '',
            'num_imss': exp['num_imss'] if exp else '',
        },
        'datos_personales': {
            'contacto_emergencia': exp['contacto_emergencia'] if exp else '',
            'telefono_personal': exp['telefono_personal'] if exp else '',
        },
        'incidencias': [dict(i) for i in incidencias]
    })


@app.route('/api/v1/empleados/<empleado_id>', methods=['PATCH'])
def update_empleado(empleado_id):
    """
    Actualiza datos de un empleado
    ---
    tags:
      - Empleados
    security:
      - Bearer: []
    parameters:
      - in: path
        name: empleado_id
        type: string
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            puesto:     { type: string }
            telefono:   { type: string }
            rol:        { type: string, description: "Solo para hr_admin" }
            tenant_id:  { type: string, description: "Solo para super_admin" }
    responses:
      200:
        description: Empleado actualizado
      401:
        description: No autorizado
    """
    user = get_current_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Body requerido'}), 400

    emp = query_db('SELECT * FROM empleados WHERE id=?', [empleado_id], one=True)
    if not emp:
        return jsonify({'error': 'Empleado no encontrado'}), 404

    # ⚠️  BOLA: no valida ownership del empleado
    # ⚠️  MASS ASSIGNMENT: acepta cualquier campo sin whitelist
    #     incluyendo rol y tenant_id que NO deberían ser modificables
    #     por un usuario regular

    allowed_emp = ['puesto', 'departamento', 'estatus']
    emp_updates = []
    emp_values  = []

    for field in allowed_emp:
        if field in data:
            emp_updates.append(f'{field}=?')
            emp_values.append(data[field])

    if emp_updates:
        emp_values.append(empleado_id)
        execute_db(f'UPDATE empleados SET {", ".join(emp_updates)} WHERE id=?', emp_values)

    # ⚠️  MASS ASSIGNMENT sobre usuarios:
    #     acepta 'rol' y 'tenant_id' sin validar si el solicitante tiene permiso
    usr_updates = []
    usr_values  = []

    for field in ['rol', 'tenant_id']:
        if field in data:
            usr_updates.append(f'{field}=?')
            usr_values.append(data[field])

    if usr_updates:
        usr_values.append(empleado_id)
        execute_db(
            f'UPDATE usuarios SET {", ".join(usr_updates)} WHERE empleado_id=?',
            usr_values
        )

    updated_emp = query_db('SELECT * FROM empleados WHERE id=?', [empleado_id], one=True)
    updated_usr = query_db('SELECT rol, tenant_id FROM usuarios WHERE empleado_id=?', [empleado_id], one=True)

    return jsonify({
        'mensaje': 'Empleado actualizado',
        'empleado': {
            'id': updated_emp['id'],
            'puesto': updated_emp['puesto'],
            'estatus': updated_emp['estatus'],
            'rol': updated_usr['rol'] if updated_usr else None,
            'tenant_id': updated_usr['tenant_id'] if updated_usr else None,
        }
    })


# ─── Tenant: listado de empleados (post-escalada) ─────────────
@app.route('/api/v1/tenant/<tenant_id>/empleados', methods=['GET'])
def get_tenant_empleados(tenant_id):
    """
    Lista todos los empleados de un tenant
    ---
    tags:
      - Tenant
    security:
      - Bearer: []
    parameters:
      - in: path
        name: tenant_id
        type: string
        required: true
    responses:
      200:
        description: |
          Lista de empleados con datos básicos.
          Requiere rol hr_admin o superior.
      401:
        description: No autorizado
      403:
        description: Rol insuficiente
    """
    user = get_current_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 401

    # ⚠️  BOLA: valida rol pero NO valida que el tenant_id corresponda al tenant del usuario
    #     Un empleado que escaló su rol a hr_admin puede acceder a cualquier tenant
    if user['rol'] not in ['hr_admin', 'super_admin']:
        return jsonify({'error': 'Acceso denegado — rol insuficiente'}), 403

    empleados = query_db(
        '''SELECT e.id, e.nombre, e.apellido_paterno, e.apellido_materno,
                  e.curp, e.nss, e.rfc, e.puesto, e.departamento,
                  ex.salario_mensual, ex.clabe, ex.banco, ex.num_imss
           FROM empleados e
           LEFT JOIN expedientes ex ON e.id = ex.empleado_id
           WHERE e.tenant_id = ?
           ORDER BY e.apellido_paterno''',
        [tenant_id]
    )

    return jsonify({
        'tenant_id': tenant_id,
        'total': len(empleados),
        'empleados': [dict(e) for e in empleados]
    })


# ─── Usuarios: directorio ─────────────────────────────────────
@app.route('/api/v1/usuarios/buscar', methods=['GET'])
def buscar_usuarios():
    """
    Busca usuarios por nombre (para menciones en comentarios)
    ---
    tags:
      - Usuarios
    security:
      - Bearer: []
    parameters:
      - in: query
        name: q
        type: string
        required: true
        example: admin
    responses:
      200:
        description: Lista de usuarios encontrados con sus IDs y roles
    """
    user = get_current_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 401

    q = request.args.get('q', '')

    # ⚠️  Sin scope de tenant — busca en todos los usuarios del sistema
    usuarios = query_db(
        "SELECT id, nombre, email, rol, tenant_id, empleado_id FROM usuarios WHERE nombre LIKE ?",
        [f'%{q}%']
    )

    return jsonify({'usuarios': [dict(u) for u in usuarios]})


# ─── Dashboard stats ──────────────────────────────────────────
@app.route('/api/v1/dashboard', methods=['GET'])
def dashboard():
    """
    KPIs del dashboard para el empleado autenticado
    ---
    tags:
      - Dashboard
    security:
      - Bearer: []
    responses:
      200:
        description: Estadísticas del dashboard
    """
    user = get_current_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 401

    tenant = query_db('SELECT * FROM tenants WHERE id=?', [user['tenant_id']], one=True)
    emp_count = query_db(
        'SELECT COUNT(*) as c FROM empleados WHERE tenant_id=?',
        [user['tenant_id']], one=True
    )

    mi_emp = None
    if user.get('empleado_id'):
        mi_emp = query_db('SELECT * FROM empleados WHERE id=?', [user['empleado_id']], one=True)
        exp    = query_db('SELECT * FROM expedientes WHERE empleado_id=?', [user['empleado_id']], one=True)

    return jsonify({
        'tenant': {
            'nombre': tenant['nombre'] if tenant else '',
            'plan': tenant['plan'] if tenant else '',
            'empleados': emp_count['c'] if emp_count else 0
        },
        'mi_perfil': {
            'nombre': mi_emp['nombre'] + ' ' + mi_emp['apellido_paterno'] if mi_emp else user['nombre'],
            'puesto': mi_emp['puesto'] if mi_emp else '',
            'empleado_id': user.get('empleado_id', ''),
        } if mi_emp else None
    })


if __name__ == '__main__':
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    init_db()
    app.run(debug=False, port=5000, use_reloader=False)
