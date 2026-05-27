import os
from flask import Flask, render_template, session, redirect, url_for, request, flash, flash
from itsdangerous import URLSafeSerializer
from flask import jsonify
from models import db  # Asegúrate de que este archivo exista y esté configurado correctamente
from dotenv import load_dotenv
from models import db, Usuario, Area, Reporte, AccesoReporte, BitacoraReporte, SolicitudReporte
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import msal
import logging
import requests
import pytz
from zoneinfo import ZoneInfo
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func, and_
from werkzeug.middleware.proxy_fix import ProxyFix
import urllib.parse

load_dotenv()  # Carga las variables desde el archivo .env

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Configuración de Flask y SQLAlchemy desde variables de entorno
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

db_user = os.getenv("DB_USER")
db_pass = urllib.parse.quote_plus(os.getenv("DB_PASSWORD"))
db_name = os.getenv("DB_NAME")
instance = os.getenv("INSTANCE_CONNECTION_NAME")

DATABASE_URI = (
    f"mysql+pymysql://{db_user}:{db_pass}@/{db_name}"
    f"?unix_socket=/cloudsql/{instance}"
)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

serializer = URLSafeSerializer(os.getenv('SERIALIZER_SECRET_KEY'))

# Configuración de Microsoft OAuth
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
TENANT_ID = os.getenv('TENANT_ID')
AUTHORITY = os.getenv('AUTHORITY')
REDIRECT_URI = os.getenv('REDIRECT_URI')
SCOPE = ['User.Read']

# Crear aplicación MSAL
msal_app = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET
)


# Simulamos datos de "BD"
areas = {
    
}

# Crear el usuario admin solo si no existe
def inicializar_admin():
    with app.app_context():

        admin_user = os.getenv('USER_ADMIN', 'admin')
        admin_password = os.getenv('USER_ADMIN_PASSWORD', 'admin')

        db.create_all()

        if not Usuario.query.filter_by(user=admin_user).first():

            contrasena_hash = generate_password_hash(admin_password)

            usuario_admin = Usuario(
                nombre="Admin",
                apellido=" ",
                user=admin_user,
                contrasena_hash=contrasena_hash,
                es_admin=True,
                ver_metricas=True,
                ver_solicitudes_reportes=True
            )

            db.session.add(usuario_admin)
            db.session.commit()

            print(f"✅ Usuario administrador '{admin_user}' creado correctamente.")

        else:
            print(f"ℹ️ Usuario administrador '{admin_user}' ya existe.")



@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si el usuario ya está logueado, redirigir a donde corresponda
    if session.get('logged_in'):
        redirect_url = session.get('redirect_after_login')
        if redirect_url:
            # ⚠️ No usar pop todavía, así no se borra si redirige de nuevo
            return redirect(redirect_url)
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        user = request.form.get('username')
        password = request.form.get('password')
        
        usuario = Usuario.query.filter_by(user=user).first()
        
        if usuario and usuario.contrasena_hash and check_password_hash(usuario.contrasena_hash, password):
            session['logged_in'] = True
            session['user_id'] = usuario.id
            session['user_name'] = f"{usuario.nombre} {usuario.apellido}"
            session['user_email'] = usuario.email
            session['user'] = usuario.user
            session['es_admin'] = usuario.es_admin
            session['auth_method'] = 'local'
            session['last_activity'] = datetime.now().isoformat()
            session['ver_metricas'] = usuario.ver_metricas
            session['ver_solicitudes_reportes'] = usuario.ver_solicitudes_reportes

            flash("Inicio de sesión exitoso.", "success")

            # ✅ Aquí sí usamos pop, para limpiar después del login
            redirect_url = session.pop('redirect_after_login', None)
            if redirect_url:
                return redirect(redirect_url)
            return redirect(url_for('dashboard'))
        else:
            flash("Credenciales incorrectas. Intenta de nuevo.", "danger")
    
    return render_template('login.html', year=datetime.now().year)


@app.route('/login/microsoft')
def login_microsoft():
    """Redirige al usuario a Microsoft para autenticarse."""
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    
    auth_url = msal_app.get_authorization_request_url(
        scopes=SCOPE,
        redirect_uri=REDIRECT_URI
    )
    logger.debug(f"Redirigiendo a: {auth_url}")
    return redirect(auth_url)

@app.route('/auth/microsoft/callback')
def microsoft_callback():
    logger.debug("Entrando al callback de Microsoft")
    
    if 'error' in request.args:
        logger.error(f"Error de Microsoft: {request.args['error']} - {request.args.get('error_description')}")
        flash(f"Error de autenticación: {request.args.get('error_description', 'Desconocido')}", "danger")
        return redirect(url_for('login'))
    
    if 'code' not in request.args:
        logger.error("No se recibió el código en los parámetros")
        flash("Error en la autenticación con Microsoft: No se recibió código.", "danger")
        return redirect(url_for('login'))
    
    try:
        logger.debug(f"Procesando código: {request.args['code']}")
        result = msal_app.acquire_token_by_authorization_code(
            request.args['code'],
            scopes=SCOPE,
            redirect_uri=REDIRECT_URI
        )
        logger.debug(f"Resultado de MSAL: {result}")
        
        if 'access_token' not in result:
            logger.error(f"No se obtuvo access_token: {result}")
            flash("Error al obtener el token de acceso.", "danger")
            return redirect(url_for('login'))
        
        # Obtener información del usuario de Microsoft Graph
        graph_data = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {result['access_token']}"}
        ).json()
        logger.debug(f"Información del usuario desde Graph: {graph_data}")
        
        if 'error' in graph_data:
            logger.error(f"Error en Graph API: {graph_data['error']}")
            flash(f"Error al obtener datos del usuario: {graph_data['error']['message']}", "danger")
            return redirect(url_for('login'))
        
        email = graph_data.get('mail') or graph_data.get('userPrincipalName')
        nombre = graph_data.get('givenName', 'Usuario')
        apellido = graph_data.get('surname', '')
        
        if not email:
            logger.error("No se pudo obtener el correo del usuario")
            flash("No se pudo obtener el correo del usuario.", "danger")
            return redirect(url_for('login'))
        
        try:
            # Generar nombre de usuario a partir del email (parte antes del @)
            username = email.split('@')[0]
            
            usuario = Usuario.query.filter_by(email=email).first()
            if not usuario:
                # Crear nuevo usuario si no existe
                usuario = Usuario(
                    nombre=nombre,
                    apellido=apellido,
                    user=username,
                    email=email,
                    contrasena_hash=None,  # No se usa contraseña para autenticación Microsoft
                    es_admin=False
                )
                db.session.add(usuario)
                db.session.commit()
                logger.info(f"Usuario creado: {username}")
                flash(f"Usuario {username} creado con autenticación de Microsoft.", "info")
            
            # Configurar sesión
            session['logged_in'] = True
            session['user_id'] = usuario.id
            session['user_name'] = f"{nombre} {apellido}"
            session['user_email'] = email
            session['user'] = usuario.user
            session['es_admin'] = usuario.es_admin
            session['auth_method'] = 'microsoft'
            session['last_activity'] = datetime.now().isoformat()
            session['ver_metricas'] = usuario.ver_metricas
            session['ver_solicitudes_reportes'] = usuario.ver_solicitudes_reportes
            
            logger.info(f"Sesión iniciada para {email}")
            flash("Inicio de sesión con Microsoft exitoso.", "success")
            
            # AGREGAR ESTO: Redirigir a la URL guardada o al dashboard
            redirect_url = session.pop('redirect_after_login', None)
            if redirect_url:
                return redirect(redirect_url)
            return redirect(url_for('dashboard'))
        
        except Exception as e:
            logger.error(f"Error en la base de datos: {str(e)}")
            flash(f"Error al procesar el usuario en la base de datos: {str(e)}", "danger")
            return redirect(url_for('login'))
    
    except Exception as e:
        logger.error(f"Excepción en el callback: {str(e)}")
        flash(f"Error interno al procesar la autenticación: {str(e)}", "danger")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    
    return redirect(url_for('login'))



@app.route('/go/<token>')
def go(token):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    try:
        data = serializer.loads(token)
        reporte_id = data.get('id')
        logger.debug(f"Token decodificado: reporte_id={reporte_id}")
        
        acceso = db.session.query(AccesoReporte).filter(
            AccesoReporte.usuario_id == session['user_id'],
            AccesoReporte.reporte_id == reporte_id
        ).first()
        
        if not acceso:
            logger.error(f"Acceso denegado para usuario_id={session['user_id']}, reporte_id={reporte_id}")
            return "Acceso denegado", 403

        reporte = Reporte.query.get(reporte_id)
        if not reporte:
            logger.error(f"Reporte no encontrado: reporte_id={reporte_id}")
            return "Reporte no encontrado", 404

        logger.debug(f"Redirigiendo a: {reporte.url}")
        
        
        zona = pytz.timezone("America/Guatemala")
        fecha_actual = datetime.now(zona).replace(tzinfo=None)
        
        nuevo_registro = BitacoraReporte(
            usuario_id=session['user_id'],
            reporte_id=reporte_id,
            fecha_hora=fecha_actual
        )
        db.session.add(nuevo_registro)
        db.session.commit()
        return redirect(reporte.url)

    except Exception as e:
        logger.error(f"Error procesando token: {str(e)}")
        return "Token inválido", 400
    
    
@app.route('/token/<reporte_id>')
def generar_token(reporte_id):
    if not session.get('logged_in'):
        return jsonify({'error': 'No autenticado'}), 401
    
    # Verify access
    acceso = db.session.query(AccesoReporte).filter(
        AccesoReporte.usuario_id == session['user_id'],
        AccesoReporte.reporte_id == reporte_id
    ).first()
    
    if not acceso:
        return jsonify({'error': 'No autorizado'}), 403

    token = serializer.dumps({'id': reporte_id})
    return jsonify({'token': token})


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    reporte_url = os.getenv("REPORTE_INDICADORES")
    return render_template("dashboard.html", reporte_url=reporte_url,
                           nombre=session['user_name'],
                        user=session['user'],
                        es_admin=session.get('es_admin', False),
                        ver_metricas=session.get('ver_metricas', False),
                        ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False))


@app.route('/reportes')
def reportes():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    areas_data = obtener_areas_usuario(session['user_id'])
    
    return render_template('reportes.html', 
                        nombre=session['user_name'],
                        user=session['user'],
                        es_admin=session.get('es_admin', False),
                        ver_metricas=session.get('ver_metricas', False),
                        ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False),
                        areas=areas_data,
                        reporte_directo=None,  # No hay reporte directo
                        area_nombre=None)

@app.context_processor
def inject_current_year():
    from datetime import datetime
    return {'current_year': datetime.now().year}

@app.context_processor
def inject_version():
    return {'app_version': '1.2.0'}


@app.route('/admin_accesos', methods=['GET', 'POST'])
def admin_accesos():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if not session.get('es_admin'):
        flash("No tienes permisos para acceder a esta sección", "danger")
        return redirect(url_for('reportes'))
    
    usuarios = Usuario.query.order_by(Usuario.user).all()

    # Selección de usuario
    usuario_sel = None
    if request.method == 'GET':
        # Solo para GET, obtener usuario de la URL
        usuario_sel = request.args.get('usuario')
    elif request.method == 'POST':
        # Solo para POST, obtener usuario del formulario (campo oculto)
        usuario_sel = request.form.get('usuario')
    
    # Si no hay usuario seleccionado y hay usuarios disponibles, seleccionar el primero
    if not usuario_sel and usuarios:
        usuario_sel = usuarios[0].user
    
    # Obtener áreas y reportes
    areas = Area.query.order_by(Area.nombre).all()
    reportes_por_area = {
        area.nombre: Reporte.query.filter_by(area_id=area.id).order_by(Reporte.id).all()
        for area in areas
    }

    # Obtener usuario y sus accesos actuales
    usuario = Usuario.query.filter_by(user=usuario_sel).first() if usuario_sel else None
    accesos_usuario = [acceso.reporte_id for acceso in usuario.accesos] if usuario else []

    # Procesar guardado de accesos (solo para POST)
    if request.method == 'POST' and usuario:
        # Reportes seleccionados del formulario
        reportes_seleccionados = set(map(int, request.form.getlist('accesos')))

        # Accesos actuales desde la base de datos
        accesos_actuales = set(accesos_usuario)

        # Determinar accesos a agregar y eliminar
        agregar = reportes_seleccionados - accesos_actuales
        eliminar = accesos_actuales - reportes_seleccionados

        try:
            # Eliminar accesos desmarcados
            if eliminar:
                AccesoReporte.query.filter(
                    AccesoReporte.usuario_id == usuario.id,
                    AccesoReporte.reporte_id.in_(eliminar)
                ).delete(synchronize_session=False)

            # Agregar nuevos accesos
            for reporte_id in agregar:
                nuevo_acceso = AccesoReporte(usuario_id=usuario.id, reporte_id=reporte_id)
                db.session.add(nuevo_acceso)

            db.session.commit()
            flash(f"Accesos actualizados correctamente para {usuario.nombre} {usuario.apellido}", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar accesos: {str(e)}", "danger")

        # Redirigir para evitar reenvío del formulario
        return redirect(url_for('admin_accesos', usuario=usuario_sel))

    return render_template('admin_accesos.html',
                        nombre=session['user_name'],
                        user=session['user'],
                        usuarios=usuarios,
                        usuario_sel=usuario_sel,
                        reportes_por_area=reportes_por_area,
                        accesos_usuario=accesos_usuario,
                        es_admin=session.get('es_admin', False),
                        ver_metricas=session.get('ver_metricas', False),
                        ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False))


from flask import render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash
from models import db, Usuario  # Ajusta si usas otro archivo de modelos

@app.route('/admin_usuarios', methods=['GET', 'POST'])
def admin_usuarios():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("Acceso denegado.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        nombre = request.form.get('nombre')
        apellido = request.form.get('apellido')
        user = request.form.get('user')
        email = request.form.get('email')
        contrasena = request.form.get('contrasena')
        es_admin = bool(int(request.form.get('es_admin', 0)))
        ver_metricas = bool(int(request.form.get('ver_metricas', 0)))
        ver_solicitudes_reportes = bool(int(request.form.get('ver_solicitudes_reportes', 0)))


        if not nombre or not apellido or not user:
            flash("Nombre, apellido y usuario son obligatorios.", "warning")
            return redirect(url_for('admin_usuarios'))

        if contrasena:
            contrasena_hash = generate_password_hash(contrasena)
        else:
            contrasena_hash = None

        nuevo_usuario = Usuario(
            nombre=nombre,
            apellido=apellido,
            user=user,
            email=email if email else None,
            contrasena_hash=contrasena_hash,
            es_admin=es_admin,
            ver_metricas=ver_metricas,
            ver_solicitudes_reportes=ver_solicitudes_reportes
        )

        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash("Usuario creado exitosamente.", "success")
        except IntegrityError as e:
            db.session.rollback()
            # Detectar si es por clave duplicada
            if "Duplicate entry" in str(e.orig):
                flash("El nombre de usuario ya existe, por favor elige otro.", "danger")
            else:
                flash("Error al crear usuario: " + str(e), "danger")
        except Exception as e:
            db.session.rollback()
            flash("Error inesperado al crear usuario.", "danger")


        return redirect(url_for('admin_usuarios'))
    
    usuarios = Usuario.query.filter(Usuario.user != "admin").order_by(Usuario.id).all()
    return render_template('admin_usuarios.html', nombre=session['user_name'], user=session['user'], usuarios=usuarios, current_year=datetime.now().year,
                        es_admin=session.get('es_admin', False), ver_metricas=session.get('ver_metricas', False), ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False))


@app.route("/editar_usuario", methods=["POST"])
def editar_usuario():
    if not session.get("es_admin"): # Asegúrate que solo los admin puedan hacerlo
        flash("No tienes permisos para realizar esta acción", "danger")
        return redirect(url_for("admin_usuarios"))

    user_id = request.form.get("id")
    usuario = Usuario.query.get(user_id)
    if not usuario:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for("admin_usuarios"))
    
    # 🚫 Evitar modificar al súper admin
    if usuario.user == "admin":
        flash("No se puede modificar este usuario", "danger")
        return redirect(url_for("admin_usuarios"))

    # Obtener datos del formulario
    nuevo_nombre = request.form.get("nombre")
    nuevo_apellido = request.form.get("apellido")
    nuevo_user = request.form.get("user")
    nuevo_email = request.form.get("email") or None
    nueva_contrasena = request.form.get("contrasena")
    es_admin = True if request.form.get("es_admin") == "1" else False
    ver_metricas = True if request.form.get("ver_metricas") == "1" else False
    ver_solicitudes_reportes = True if request.form.get("ver_solicitudes_reportes") == "1" else False

    # Validar duplicados si cambian el usuario o email
    if usuario.user != nuevo_user:
        if Usuario.query.filter_by(user=nuevo_user).first():
            flash("Ya existe un usuario con ese nombre de usuario", "danger")
            return redirect(url_for("admin_usuarios"))

    if nuevo_email and usuario.email != nuevo_email:
        if Usuario.query.filter_by(email=nuevo_email).first():
            flash("Ya existe un usuario con ese correo", "danger")
            return redirect(url_for("admin_usuarios"))

    # Actualizar campos
    usuario.nombre = nuevo_nombre
    usuario.apellido = nuevo_apellido
    usuario.user = nuevo_user
    usuario.email = nuevo_email
    usuario.es_admin = es_admin
    usuario.ver_metricas = ver_metricas
    usuario.ver_solicitudes_reportes = ver_solicitudes_reportes

    if nueva_contrasena:
        usuario.contrasena_hash = generate_password_hash(nueva_contrasena)


    db.session.commit()
    flash("Usuario actualizado correctamente", "success")
    return redirect(url_for("admin_usuarios"))



@app.route('/admin_areas')
def admin_areas():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para acceder a esta sección", "danger")
        return redirect(url_for('reportes'))
    
    areas = Area.query.order_by(Area.id).all()
    return render_template('admin_areas.html', nombre=session['user_name'], user=session['user'], areas=areas, es_admin=session.get('es_admin', False), ver_metricas=session.get('ver_metricas', False), ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False))

@app.route('/admin_reportes/<int:area_id>')
def admin_reportes(area_id):
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para acceder a esta sección", "danger")
        return redirect(url_for('reportes'))
    
    area = Area.query.get_or_404(area_id)
    reportes = Reporte.query.filter_by(area_id=area_id).order_by(Reporte.id).all()
    return render_template('admin_reportes.html', nombre=session['user_name'], user=session['user'], area=area, reportes=reportes, es_admin=session.get('es_admin', False), ver_metricas=session.get('ver_metricas', False), ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False))

@app.route('/crear_area', methods=['POST'])
def crear_area():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para realizar esta acción", "danger")
        return redirect(url_for('reportes'))
    
    nombre = request.form.get('nombre')
    
    if not nombre:
        flash("El nombre del área es requerido", "danger")
        return redirect(url_for('admin_areas'))
    
    try:
        area = Area(nombre=nombre)
        db.session.add(area)
        db.session.commit()
        flash(f"Área '{nombre}' creada exitosamente", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al crear el área: {str(e)}", "danger")
    
    return redirect(url_for('admin_areas'))

@app.route('/editar_area', methods=['POST'])
def editar_area():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para realizar esta acción", "danger")
        return redirect(url_for('reportes'))
    
    area_id = request.form.get('id')
    nombre = request.form.get('nombre')
    
    if not area_id or not nombre:
        flash("Datos incompletos", "danger")
        return redirect(url_for('admin_areas'))
    
    try:
        area = Area.query.get(area_id)
        if not area:
            flash("Área no encontrada", "danger")
            return redirect(url_for('admin_areas'))
        
        area.nombre = nombre
        db.session.commit()
        flash(f"Área actualizada exitosamente", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al actualizar el área: {str(e)}", "danger")
    
    return redirect(url_for('admin_areas'))

@app.route('/eliminar_area', methods=['POST'])
def eliminar_area():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para realizar esta acción", "danger")
        return redirect(url_for('reportes'))
    
    area_id = request.form.get('id')
    
    if not area_id:
        flash("Área no especificada", "danger")
        return redirect(url_for('admin_areas'))
    
    try:
        area = Area.query.get(area_id)
        if not area:
            flash("Área no encontrada", "danger")
            return redirect(url_for('admin_areas'))
        
        db.session.delete(area)
        db.session.commit()
        flash(f"Área '{area.nombre}' eliminada exitosamente", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el área: {str(e)}", "danger")
    
    return redirect(url_for('admin_areas'))

@app.route('/crear_reporte/<int:area_id>', methods=['POST'])
def crear_reporte(area_id):
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para realizar esta acción", "danger")
        return redirect(url_for('reportes'))
    
    nombre = request.form.get('nombre')
    url = request.form.get('url')
    
    if not nombre or not url:
        flash("Nombre y URL son requeridos", "danger")
        return redirect(url_for('admin_reportes', area_id=area_id))
    
    try:
        reporte = Reporte(nombre=nombre, url=url, area_id=area_id)
        db.session.add(reporte)
        db.session.commit()
        flash(f"Reporte '{nombre}' creado exitosamente", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al crear el reporte: {str(e)}", "danger")
    
    return redirect(url_for('admin_reportes', area_id=area_id))

@app.route('/editar_reporte', methods=['POST'])
def editar_reporte():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para realizar esta acción", "danger")
        return redirect(url_for('reportes'))
    
    reporte_id = request.form.get('id')
    nombre = request.form.get('nombre')
    url = request.form.get('url')
    
    if not reporte_id or not nombre or not url:
        flash("Datos incompletos", "danger")
        return redirect(url_for('admin_areas'))
    
    try:
        reporte = Reporte.query.get(reporte_id)
        if not reporte:
            flash("Reporte no encontrado", "danger")
            return redirect(url_for('admin_areas'))
        
        reporte.nombre = nombre
        reporte.url = url
        db.session.commit()
        flash(f"Reporte actualizado exitosamente", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al actualizar el reporte: {str(e)}", "danger")
    
    return redirect(url_for('admin_reportes', area_id=reporte.area_id))

@app.route('/eliminar_reporte', methods=['POST'])
def eliminar_reporte():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para realizar esta acción", "danger")
        return redirect(url_for('reportes'))
    
    reporte_id = request.form.get('id')
    
    if not reporte_id:
        flash("Reporte no especificado", "danger")
        return redirect(url_for('admin_areas'))
    
    try:
        reporte = Reporte.query.get(reporte_id)
        if not reporte:
            flash("Reporte no encontrado", "danger")
            return redirect(url_for('admin_areas'))
        
        area_id = reporte.area_id
        db.session.delete(reporte)
        db.session.commit()
        flash(f"Reporte eliminado exitosamente", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el reporte: {str(e)}", "danger")
    
    return redirect(url_for('admin_reportes', area_id=area_id))




from models import BitacoraReporte  # <-- asegúrate de importar el correcto
from datetime import timedelta

@app.route("/metricas")
def metricas():
    
    if 'user_id' not in session:
        flash("Debes autenticarte para poder acceder a este módulo", "danger")
        return redirect(url_for('login'))
    elif not session.get('ver_metricas', False):
        flash("No tienes permisos para acceder a este módulo", "danger")
        return redirect(url_for('dashboard'))
    
    usuario_id_str = request.args.get("usuario_id")
    fecha_inicio_str = request.args.get("fecha_inicio")
    fecha_fin_str = request.args.get("fecha_fin")

    # Obtener ID del usuario con user='admin'
    admin = Usuario.query.filter_by(user='admin').first()
    admin_id = admin.id if admin else None

    # Validar usuario_id (evita aplicar el filtro si es el admin)
    usuario_id = None
    if usuario_id_str and usuario_id_str.isdigit():
        temp_id = int(usuario_id_str)
        if temp_id != admin_id:
            usuario_id = temp_id

    filtros = []

    if usuario_id:
        filtros.append(BitacoraReporte.usuario_id == usuario_id)

    if fecha_inicio_str:
        try:
            fecha_inicio = datetime.strptime(fecha_inicio_str, "%Y-%m-%d")
            filtros.append(BitacoraReporte.fecha_hora >= fecha_inicio)
        except ValueError:
            pass

    if fecha_fin_str:
        try:
            fecha_fin = datetime.strptime(fecha_fin_str, "%Y-%m-%d") + timedelta(days=1)
            filtros.append(BitacoraReporte.fecha_hora < fecha_fin)
        except ValueError:
            pass

    # Excluir registros del admin
    if admin_id:
        filtros.append(BitacoraReporte.usuario_id != admin_id)

    entradas = BitacoraReporte.query.filter(and_(*filtros)).order_by(BitacoraReporte.fecha_hora.desc()).all()

    resumen = (
        db.session.query(Reporte.nombre, db.func.count(BitacoraReporte.id))
        .join(BitacoraReporte.reporte)
        .filter(and_(*filtros))
        .group_by(Reporte.nombre)
        .all()
    )

    resumen_areas = (
        db.session.query(Area.nombre, db.func.count(BitacoraReporte.id))
        .join(Reporte, Reporte.area_id == Area.id)
        .join(BitacoraReporte, BitacoraReporte.reporte_id == Reporte.id)
        .filter(and_(*filtros))
        .group_by(Area.nombre)
        .order_by(Area.nombre)
        .all()
    )

    # Excluir al admin de la lista de usuarios para filtros
    if admin_id:
        usuarios = Usuario.query.filter(Usuario.id != admin_id).order_by(Usuario.nombre).all()
    else:
        usuarios = Usuario.query.order_by(Usuario.nombre).all()

    print("Usuario ID recibido (filtrado):", usuario_id)

    return render_template(
        "metricas.html",
        nombre=session['user_name'], 
        user=session['user'],
        resumen=resumen,
        resumen_areas=resumen_areas,
        entradas=entradas,
        usuarios=usuarios,
        es_admin=session.get('es_admin', False),
        ver_metricas=session.get('ver_metricas', False),
        ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False),
        usuario_filtro=usuario_id
    )



#################### Solicitud Reportes ############################

#Ingresar solicitud de reporte nuevo
@app.route('/solicitud_reporte/nueva', methods=['GET', 'POST'])
def nueva_solicitud_reporte():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para acceder a esta sección.", "danger")
        return redirect(url_for('reportes'))

    if request.method == 'POST':
        # Extraer campos
        reporte = request.form.get('reporte', '').strip()
        area = request.form.get('area', '').strip()
        fecha_solicitud = request.form.get('fecha_solicitud', '').strip()
        solicitado_por = request.form.get('solicitado_por', '').strip()
        prioridad = request.form.get('prioridad', '').strip()
        fecha_entregado = request.form.get('fecha_entregado', '').strip()
        encargado = request.form.get('encargado', '').strip()

        # Validar obligatorios
        errores = []
        if not reporte:
            errores.append("El campo 'Reporte' es obligatorio.")
        if not area:
            errores.append("El campo 'Área' es obligatorio.")
        if not fecha_solicitud:
            errores.append("La 'Fecha de Solicitud' es obligatoria.")
        if not solicitado_por:
            errores.append("El campo 'Solicitado por' es obligatorio.")
        if prioridad not in ['Alta', 'Media', 'Baja']:
            errores.append("La prioridad debe ser Alta, Media o Baja.")

        # Si hay errores, los mostramos
        if errores:
            for error in errores:
                flash(error, 'danger')
            return render_template('nueva_solicitud_reporte.html')

        try:
            nueva_solicitud = SolicitudReporte(
                reporte=reporte,
                area=area,
                fecha_solicitud=datetime.strptime(fecha_solicitud, '%Y-%m-%d'),
                solicitado_por=solicitado_por,
                prioridad=prioridad,
                fecha_entregado=datetime.strptime(fecha_entregado, '%Y-%m-%d') if fecha_entregado else None,
                encargado=encargado if encargado else None
            )
            db.session.add(nueva_solicitud)
            db.session.commit()
            flash('Solicitud registrada exitosamente.', 'success')
            return redirect(url_for('nueva_solicitud_reporte'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al guardar la solicitud: {e}', 'danger')

    return render_template('nueva_solicitud_reporte.html',
                            nombre=session['user_name'], 
                            user=session['user'],
                            es_admin=session.get('es_admin', False),
                            ver_metricas=session.get('ver_metricas', False))


@app.route('/admin_solicitudes_reportes')
def admin_solicitudes_reportes():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No tienes permisos para acceder a esta sección", "danger")
        return redirect(url_for('reportes'))

    solicitudes = SolicitudReporte.query.order_by(
        SolicitudReporte.fecha_entregado.isnot(None),  # False primero (pendientes)
        SolicitudReporte.fecha_solicitud.desc()
    ).all()
    
    return render_template('admin_solicitudes_reportes.html', 
                            solicitudes=solicitudes,
                            nombre=session['user_name'], 
                            user=session['user'],
                            es_admin=session.get('es_admin', False),
                            ver_metricas=session.get('ver_metricas', False),
                            ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False))


@app.route('/crear_solicitud_reporte', methods=['POST'])
def crear_solicitud_reporte():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No autorizado", "danger")
        return redirect(url_for('admin_solicitudes_reportes'))

    nueva = SolicitudReporte(
        reporte=request.form['reporte'],
        area=request.form['area'],
        fecha_solicitud=request.form['fecha_solicitud'],
        solicitado_por=request.form['solicitado_por'],
        prioridad=request.form['prioridad'],
        fecha_entregado=request.form['fecha_entregado'] or None,
        encargado=request.form['encargado'] or None,
        complejidad=request.form['complejidad'],
        progreso=int(request.form['progreso'] or 0),
        observaciones=request.form.get('observaciones') or None
    )
    db.session.add(nueva)
    db.session.commit()
    flash("Solicitud creada correctamente", "success")
    return redirect(url_for('admin_solicitudes_reportes'))



@app.route('/editar_solicitud_reporte', methods=['POST'])
def editar_solicitud_reporte():
    if not session.get('logged_in') or not session.get('es_admin'):
        flash("No autorizado", "danger")
        return redirect(url_for('admin_solicitudes_reportes'))

    solicitud = SolicitudReporte.query.get(request.form['id'])
    if not solicitud:
        flash("Solicitud no encontrada", "danger")
        return redirect(url_for('admin_solicitudes_reportes'))

    solicitud.reporte = request.form['reporte']
    solicitud.area = request.form['area']
    solicitud.fecha_solicitud = request.form['fecha_solicitud']
    solicitud.solicitado_por = request.form['solicitado_por']
    solicitud.prioridad = request.form['prioridad']
    solicitud.fecha_entregado = request.form['fecha_entregado'] or None
    solicitud.encargado = request.form['encargado'] or None
    solicitud.complejidad = request.form['complejidad']
    solicitud.progreso = int(request.form['progreso'] or 0)
    solicitud.observaciones = request.form.get('observaciones') or None

    db.session.commit()
    flash("Solicitud actualizada correctamente", "success")
    return redirect(url_for('admin_solicitudes_reportes'))


# Ver solicitudes de reportes
@app.route('/solicitudes_reportes')
def ver_solicitudes_reportes():
    if not session.get('logged_in'):
        flash("Debes autenticarte para poder acceder.", "danger")
        return redirect(url_for('login'))
    elif not session.get('ver_solicitudes_reportes'):
        flash("No tienes permisos para acceder a este módulo.", "danger")
        return redirect(url_for('dashboard'))

    solicitudes = SolicitudReporte.query.order_by(
        SolicitudReporte.fecha_entregado.isnot(None),  # False primero (pendientes)
        SolicitudReporte.fecha_solicitud.desc()
    ).all()

    return render_template('ver_solicitudes_reportes.html', 
                            solicitudes=solicitudes,
                            nombre=session['user_name'], 
                            user=session['user'],
                            es_admin=session.get('es_admin', False),
                            ver_metricas=session.get('ver_metricas', False),
                            ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False))


import re
from urllib.parse import quote, unquote

def generar_slug_desde_nombre(nombre, reporte_id):
    """Genera un slug a partir del nombre y ID del reporte"""
    # Limpiar el nombre: minúsculas, sin caracteres especiales
    slug_base = re.sub(r'[^\w\s-]', '', nombre.lower())
    slug_base = re.sub(r'[-\s]+', '-', slug_base).strip('-')
    
    # Truncar si es muy largo
    if len(slug_base) > 50:
        slug_base = slug_base[:50].rsplit('-', 1)[0]
    
    # Agregar ID al final como identificador único
    return f"{reporte_id}-{slug_base}"

def extraer_id_desde_slug(slug):
    """Extrae el ID del reporte desde el slug"""
    try:
        # El ID está al final después del último guion
        partes = slug.split('-', 1)
        if len(partes) == 2 and partes[0].isdigit():
            return int(partes[0])

    except:
        pass
    return None


@app.route('/reportes/<slug>')
def ver_reporte_por_slug(slug):
    """Vista para acceder a un reporte mediante URL amigable"""
    
    # Extraer el ID desde el slug
    reporte_id = extraer_id_desde_slug(slug)
    
    if not reporte_id:
        flash("URL de reporte inválida.", "danger")
        if session.get('logged_in'):
            return redirect(url_for('reportes'))
        else:
            return redirect(url_for('login'))
    
    # Buscar el reporte
    reporte = Reporte.query.get(reporte_id)
    if not reporte:
        flash("Reporte no encontrado.", "danger")
        if session.get('logged_in'):
            return redirect(url_for('reportes'))
        else:
            return redirect(url_for('login'))
    
    # Verificar login
    if not session.get('logged_in'):
        session['redirect_after_login'] = request.path
        flash("Debes iniciar sesión para acceder a este reporte.", "warning")
        return redirect(url_for('login'))
    
    # Verificar acceso
    acceso = db.session.query(AccesoReporte).filter(
        AccesoReporte.usuario_id == session['user_id'],
        AccesoReporte.reporte_id == reporte.id
    ).first()
    
    if not acceso:
        flash("No tienes permiso para acceder a este reporte.", "danger")
        return redirect(url_for('reportes'))
    
    # Registrar en bitácora
    zona = pytz.timezone("America/Guatemala")
    fecha_actual = datetime.now(zona).replace(tzinfo=None)
    
    nuevo_registro = BitacoraReporte(
        usuario_id=session['user_id'],
        reporte_id=reporte.id,
        fecha_hora=fecha_actual
    )
    db.session.add(nuevo_registro)
    db.session.commit()
    
    # Obtener área y reportes
    area = reporte.area
    areas_data = obtener_areas_usuario(session['user_id'])
    
    # Renderizar normalmente
    return render_template(
        'reportes.html',
        nombre=session['user_name'],
        user=session['user'],
        es_admin=session.get('es_admin', False),
        ver_metricas=session.get('ver_metricas', False),
        ver_solicitudes_reportes=session.get('ver_solicitudes_reportes', False),
        areas=areas_data,
        reporte_directo={
            'id': reporte.id,
            'nombre': reporte.nombre,
            'slug': slug,
            'url': url_for('go', token=serializer.dumps({'id': reporte.id}))
        },
        area_nombre=area.nombre
    )


def obtener_areas_usuario(usuario_id):
    """Helper para obtener la estructura de áreas y reportes del usuario"""
    usuario = db.session.get(Usuario, usuario_id)
    
    areas_con_acceso = db.session.query(Area).join(Reporte).join(AccesoReporte).filter(
        AccesoReporte.usuario_id == usuario.id
    ).distinct().all()
    
    areas_data = {}
    for area in areas_con_acceso:
        reportes_acceso = db.session.query(Reporte).join(AccesoReporte).filter(
            Reporte.area_id == area.id,
            AccesoReporte.usuario_id == usuario.id
        ).all()
        
        reportes_formato = [{
            'id': r.id,
            'nombre': r.nombre,
            'slug': generar_slug_desde_nombre(r.nombre, r.id),
            'url': url_for('go', token=serializer.dumps({'id': r.id}), _external=True)
        } for r in reportes_acceso]
        
        areas_data[area.nombre] = reportes_formato
    
    return areas_data

if __name__ == '__main__':
    inicializar_admin()
    # Registrar la función para que esté disponible en las plantillas Jinja
    app.jinja_env.globals.update(generar_slug_desde_nombre=generar_slug_desde_nombre)

    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 4000)))

