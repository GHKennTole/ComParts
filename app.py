from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
import os
import math
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse, urljoin
import pymysql
import pymysql.cursors

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'appsecretkey')
bcrypt = Bcrypt(app)

# Configuración de la base de datos MySQL (usar variables de entorno en producción)
def get_db_config():
    return {
        'host': os.environ.get('MYSQL_HOST', 'biqzxkkzarlrq5wq57be-mysql.services.clever-cloud.com'),
        'port': int(os.environ.get('MYSQL_PORT', 3306)),
        'user': os.environ.get('MYSQL_USER', 'u0xwmpkmnis9vgtp'),
        'password': os.environ.get('MYSQL_PASSWORD', 'DDlVD5KdCYcAbxUJPfKF'),
        'db': os.environ.get('MYSQL_DB', 'biqzxkkzarlrq5wq57be'),
        'cursorclass': pymysql.cursors.DictCursor,
        'autocommit': False
    }

class ConnectionProxy:
    """
    Proxy ligero para mantener compatibilidad con el uso actual:
    mysql.connection.cursor(), mysql.connection.commit(), mysql.connection.close()
    """
    def __init__(self, cfg):
        self.cfg = cfg
        self._conn = None

    def _ensure_conn(self):
        if self._conn is None:
            self._conn = pymysql.connect(**self.cfg)
        return self._conn

    def cursor(self):
        return self._ensure_conn().cursor()

    def commit(self):
        if self._conn:
            self._conn.commit()

    def close(self):
        if self._conn:
            try:
                self._conn.close()
            finally:
                self._conn = None

# Creamos objeto 'mysql' con interfaz compatible al código existente
mysql = type("M", (), {})()
mysql.connection = ConnectionProxy(get_db_config())

def is_safe_url(target):
    """Verifica que la URL objetivo pertenezca al mismo host (evita open redirects)."""
    if not target:
        return False
    host_url = request.host_url
    ref_url = urlparse(host_url)
    test_url = urlparse(urljoin(host_url, target))
    return (test_url.scheme in ('http', 'https')) and (ref_url.netloc == test_url.netloc)

# ------------------- RUTAS PRINCIPALES -------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/inicio')
def inicio():
    return render_template('index.html')

@app.route('/contacto')
def contacto():
    return render_template('contacto.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/registro')
def Registro():
    return render_template('registro.html')

@app.template_filter('cordoba')
def cordoba_filter(value, decimals=0, sep=' '):
    from decimal import Decimal, InvalidOperation
    try:
        n = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return f"C$ {value}"
    formatted = f"{n:,.{int(decimals)}f}".replace(',', sep)
    return f"C$ {formatted}"

# ------------------- REGISTRO DE USUARIO -------------------

@app.route('/crearusuario', methods=['GET', 'POST'])
def crearusuario():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM usuario WHERE email = %s", (email,))
        existe = cursor.fetchone()
        if existe:
            flash("El correo ya está registrado. Por favor usa otro.", "registro_warning")
            cursor.close()
            return redirect(url_for('Registro'))
        # hash antes de guardar
        hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute("INSERT INTO usuario (nombre, email, password, id_rol) VALUES (%s, %s, %s, '2')",
                       (nombre, email, hash_password))
        mysql.connection.commit()
        cursor.close()
        flash("¡Usuario registrado exitosamente!", "registro_success")
        return redirect(url_for('Registro'))
    return render_template('registro.html')


# ------------------- LOGIN -------------------

@app.route('/accesologin', methods=['GET', 'POST'])
def accesologin():
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM usuario WHERE email = %s", (email,))
        user = cursor.fetchone()

        def do_login(u):
            session['logueado'] = True
            session['id'] = u['id']
            session['id_rol'] = u['id_rol']
            session['nombre'] = u.get('nombre')
            cursor.execute("UPDATE usuario SET login_count = COALESCE(login_count,0)+1, last_login=NOW() WHERE id=%s", (u['id'],))
            mysql.connection.commit()

        if user and bcrypt.check_password_hash(user['password'], password):
            do_login(user)
            cursor.close()
            flash(f"Bienvenido, {session.get('nombre') or 'Usuario'}", "login_success")
            return redirect(url_for('admin' if user['id_rol'] == 1 else 'usuario'))

        if user and user['password'] == password:
            new_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute("UPDATE usuario SET password=%s WHERE id=%s", (new_hash, user['id']))
            mysql.connection.commit()
            do_login(user)
            cursor.close()
            flash(f"Bienvenido, {session.get('nombre') or 'Usuario'}", "login_success")
            return redirect(url_for('admin' if user['id_rol'] == 1 else 'usuario'))

        cursor.close()
        flash('Correo o contraseña incorrectos', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')


# ------------------- ADMIN -------------------

@app.route('/admin')
def admin():
    if session.get('id_rol') == 1:
        return render_template('admin.html')
    else:
        flash('Acceso restringido solo para administradores.', 'danger')
        return redirect(url_for('login'))

@app.route('/usuario')
def usuario():
    if session.get('id_rol') == 2:
        return render_template('usuario.html')
    else:
        flash('Acceso restringido al panel de usuarios.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    # usa categoría específica para que no aparezca tras el login
    flash('Sesión cerrada correctamente.', 'logout_success')
    return redirect(url_for('login'))

# ------------------- PRODUCTOS -------------------

@app.route('/listaproducto', methods=['GET', 'POST'])
def listaproducto():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM productos")
    productos = cursor.fetchall()
    cursor.close()
    return render_template('listaproducto.html', productos=productos)

@app.route('/agregar_producto', methods=['POST'])
def agregar_producto():
    if not session.get('id'):
        flash('Inicia sesión para agregar productos.', 'warning')
        return redirect(url_for('login'))

    nombre = request.form['nombre']
    precio = request.form['precio']
    descripcion = request.form['descripcion']
    fecha = request.form.get('fecha') or None
    usuario_id = session.get('id')

    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO productos (nombre, precio, descripcion, fecha, usuario_id) VALUES (%s, %s, %s, %s, %s)",
        (nombre, precio, descripcion, fecha, usuario_id)
    )
    mysql.connection.commit()
    cursor.close()
    flash('Producto agregado correctamente.', 'success')
    return redirect(url_for('listaproducto'))


@app.route('/eliminar_producto/<int:id>')
def eliminar_producto(id):
    # Eliminar del DB
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM productos WHERE id = %s", (id,))
    mysql.connection.commit()
    cursor.close()
    flash('Producto eliminado correctamente.', 'success')

    ref = request.referrer
    if ref and is_safe_url(ref):
        return redirect(ref)

    return redirect(url_for('editarproductos'))

@app.route('/editar_producto_modal/<int:id>', methods=['POST'])
def editar_producto_modal(id):
    nombre = request.form['nombre']
    precio = request.form['precio']
    descripcion = request.form['descripcion']
    # Si añades <input type="date" name="fecha"> en el modal, habilita esto:
    fecha = request.form.get('fecha')
    fecha = fecha or None

    cursor = mysql.connection.cursor()
    cursor.execute(
        "UPDATE productos SET nombre=%s, precio=%s, descripcion=%s, fecha=%s WHERE id=%s",
        (nombre, precio, descripcion, fecha, id)
    )
    mysql.connection.commit()
    cursor.close()
    flash('Producto editado correctamente.', 'success')

    ref = request.referrer
    if ref and is_safe_url(ref):
        return redirect(ref)
    return redirect(url_for('editarproductos'))

# ------------------- EDITARPRODUCTOS con filtros, orden, búsqueda y paginación -------------------

@app.route('/editarproductos', methods=['GET'])
def editarproductos():
    # Parámetros GET
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except (ValueError, TypeError):
        page = 1

    # opciones por página solicitadas: 10,15,20,25 (default 10)
    per_page_options = [10, 15, 20, 25]
    try:
        per_page = int(request.args.get('per_page', 10))
        if per_page not in per_page_options:
            per_page = 10
    except (ValueError, TypeError):
        per_page = 10

    sort = request.args.get('sort', 'id_asc')  # id_asc, precio_desc, precio_asc, nombre_asc, nombre_desc
    search = request.args.get('search', '').strip()

    # Construir WHERE y params
    where_clauses = []
    params = []

    if search:
        if search.isdigit():
            where_clauses.append("(id = %s OR nombre LIKE %s)")
            params.append(int(search))
            params.append(f"%{search}%")
        else:
            where_clauses.append("nombre LIKE %s")
            params.append(f"%{search}%")

    where_sql = ''
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    # ORDER BY map
    order_sql = "ORDER BY id ASC"
    if sort == 'precio_desc':
        order_sql = "ORDER BY precio DESC"
    elif sort == 'precio_asc':
        order_sql = "ORDER BY precio ASC"
    elif sort == 'nombre_asc':
        order_sql = "ORDER BY nombre ASC"
    elif sort == 'nombre_desc':
        order_sql = "ORDER BY nombre DESC"

    cursor = mysql.connection.cursor()

    # Conteo total
    count_query = f"SELECT COUNT(*) AS cnt FROM productos {where_sql}"
    cursor.execute(count_query, tuple(params))
    count_row = cursor.fetchone()
    total_count = count_row['cnt'] if count_row else 0

    total_pages = math.ceil(total_count / per_page) if per_page > 0 else 1
    if total_pages == 0:
        total_pages = 1
    if page > total_pages:
        page = total_pages

    offset = (page - 1) * per_page

    # Query principal con límite
    query = f"SELECT * FROM productos {where_sql} {order_sql} LIMIT %s OFFSET %s"
    final_params = params + [per_page, offset]
    cursor.execute(query, tuple(final_params))
    productos = cursor.fetchall()
    cursor.close()

    # Rango mostrado
    start_item = offset + 1 if total_count > 0 else 0
    end_item = min(offset + per_page, total_count)

    return render_template('editarproductos.html',
                           productos=productos,
                           page=page,
                           per_page=per_page,
                           per_page_options=per_page_options,
                           total_pages=total_pages,
                           total_count=total_count,
                           start_item=start_item,
                           end_item=end_item,
                           sort=sort,
                           search=search)

# ------------------- USUARIOS -------------------

@app.route('/listausuarios', methods=['GET', 'POST'])
def listausuarios():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM usuario")
    usuarios = cursor.fetchall()
    cursor.close()
    return render_template('listausuarios.html', usuarios=usuarios)

@app.route('/agregar_usuario', methods=['POST'])
def agregar_usuario():
    nombre = request.form['nombre']
    email = request.form['email']
    password = request.form['password']
    hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO usuario (nombre, email, password, id_rol) VALUES (%s, %s, %s, 2)",
                   (nombre, email, hash_password))
    mysql.connection.commit()
    cursor.close()
    flash('Usuario agregado correctamente.', 'success')
    return redirect(url_for('listausuarios'))


@app.route('/eliminar_usuario/<int:id>')
def eliminar_usuario(id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM usuario WHERE id = %s", (id,))
    mysql.connection.commit()
    cursor.close()
    flash('Usuario eliminado correctamente.', 'success')
    return redirect(url_for('listausuarios'))

@app.route('/editar_usuario_modal/<int:id>', methods=['POST'])
def editar_usuario_modal(id):
    nombre = request.form['nombre']
    email = request.form['email']
    password = request.form['password']
    # evita doble-hash si ya es un hash de bcrypt
    if password.startswith('$2a$') or password.startswith('$2b$') or password.startswith('$2y$'):
        hash_password = password
    else:
        hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE usuario SET nombre=%s, email=%s, password=%s WHERE id=%s",
                   (nombre, email, hash_password, id))
    mysql.connection.commit()
    cursor.close()
    flash('Usuario editado correctamente.', 'success')
    return redirect(url_for('listausuarios'))

@app.route('/editar_perfil', methods=['POST'])
def editar_perfil():
    if not session.get('id'):
        flash('Inicia sesión para editar tu perfil.', 'warning')
        return redirect(url_for('login'))

    nombre = request.form.get('nombre', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()

    cursor = mysql.connection.cursor()

    # valida email único
    cursor.execute("SELECT id FROM usuario WHERE email=%s AND id <> %s", (email, session['id']))
    existe = cursor.fetchone()
    if existe:
        cursor.close()
        flash('Ese correo ya está en uso.', 'warning')
        return redirect(url_for('perfil_admin'))

    campos = []
    params = []
    if nombre:
        campos.append("nombre=%s")
        params.append(nombre)
    if email:
        campos.append("email=%s")
        params.append(email)
    if password:
        hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
        campos.append("password=%s")
        params.append(hash_password)

    if campos:
        params.append(session['id'])
        cursor.execute(f"UPDATE usuario SET {', '.join(campos)} WHERE id=%s", tuple(params))
        mysql.connection.commit()
        # refresca nombre de sesión si cambió
        if nombre:
            session['nombre'] = nombre
        flash('Perfil actualizado correctamente.', 'success')
    else:
        flash('No se enviaron cambios.', 'info')

    cursor.close()
    return redirect(url_for('perfil_admin'))


# ------------------- OTROS -------------------

@app.route('/listar')
def listar():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM usuario')
    usuarios = cursor.fetchall()
    cursor.close()
    return render_template('listausuarios.html', usuarios=usuarios)

@app.route('/listar_productos_agregados')
def listar_productos():
    # redirige a la vista que implementa filtros/paginación
    return redirect(url_for('editarproductos'))

@app.route('/listar_productos')
def listar_productos_agregados():
    # redirige a la vista que implementa filtros/paginación
    return redirect(url_for('listaproducto'))

@app.route('/perfil_admin')
def perfil_admin():
    if 'id' in session and session.get('id_rol') == 1:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM usuario WHERE id = %s", (session['id'],))
        admin = cursor.fetchone()
        if not admin:
            cursor.close()
            flash('Usuario no encontrado.', 'warning')
            return redirect(url_for('admin'))

        cursor.execute("SELECT COUNT(*) AS cnt FROM productos WHERE usuario_id = %s", (session['id'],))
        product_count = (cursor.fetchone() or {}).get('cnt', 0)

        login_count = admin.get('login_count', 0)
        cursor.close()

        return render_template('perfiladmin.html', usuario=admin, product_count=product_count, login_count=login_count)
    else:
        flash('Acceso denegado. Solo administradores.', 'danger')
        return redirect(url_for('login'))
    
@app.route('/dashboard')
def dashboard():
    if session.get('id_rol') != 1:
        flash('Acceso restringido solo para administradores.', 'danger')
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT COUNT(*) AS c FROM usuario")
    total_usuarios = cursor.fetchone()['c']

    cursor.execute("SELECT COUNT(*) AS c FROM productos")
    total_productos = cursor.fetchone()['c']

    cursor.execute("SELECT COUNT(*) AS c FROM usuario WHERE DATE(created_at)=CURDATE()")
    usuarios_hoy = cursor.fetchone()['c']

    cursor.execute("SELECT COUNT(*) AS c FROM productos WHERE DATE(fecha)=CURDATE()")
    productos_hoy = cursor.fetchone()['c']

    cursor.execute("""
        SELECT nombre, email, last_login 
        FROM usuario 
        WHERE last_login IS NOT NULL 
        ORDER BY last_login DESC 
        LIMIT 6
    """)
    ultimos_logins = cursor.fetchall()

    # Distribución de productos por usuarios ADMIN (solo id_rol = 1)
    cursor.execute("""
        SELECT u.nombre, COUNT(p.id) AS cant
        FROM usuario u
        LEFT JOIN productos p ON p.usuario_id = u.id
        WHERE u.id_rol = 1
        GROUP BY u.id
        ORDER BY cant DESC
        LIMIT 5
    """)
    dist = cursor.fetchall()
    cursor.close()

    labels_dist = [d['nombre'] for d in dist] if dist else []
    data_dist = [d['cant'] for d in dist] if dist else []

    return render_template('dashboard.html',
                           total_usuarios=total_usuarios,
                           total_productos=total_productos,
                           usuarios_hoy=usuarios_hoy,
                           productos_hoy=productos_hoy,
                           ultimos_logins=ultimos_logins,
                           labels_dist=labels_dist,
                           data_dist=data_dist)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('FLASK_ENV', '').lower() == 'development'
    app.run(debug=debug, host='0.0.0.0', port=port)