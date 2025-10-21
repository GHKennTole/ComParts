from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import math
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.secret_key = 'appsecretkey'

# Configuración de la base de datos MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'ventas'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

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
            flash("El correo ya está registrado. Por favor usa otro.", "warning")
            cursor.close()
            return redirect(url_for('Registro'))
        cursor.execute("INSERT INTO usuario (nombre, email, password, id_rol) VALUES (%s, %s, %s, '2')", (nombre, email, password))
        mysql.connection.commit()
        cursor.close()
        flash("¡Usuario registrado exitosamente!", "success")
        return redirect(url_for('Registro'))
    return render_template('registro.html')

# ------------------- LOGIN -------------------

@app.route('/accesologin', methods=['GET', 'POST'])
def accesologin():
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM usuario WHERE email = %s AND password = %s", (email, password))
        user = cursor.fetchone()
        cursor.close()
        if user:
            session['logueado'] = True
            session['id'] = user['id']
            session['id_rol'] = user['id_rol']
            session['nombre'] = user.get('nombre')
            if user['id_rol'] == 1:
                return redirect(url_for('admin'))
            elif user['id_rol'] == 2:
                return redirect(url_for('usuario'))
        else:
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
    flash('Sesión cerrada correctamente.', 'success')
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
    nombre = request.form['nombre']
    precio = request.form['precio']
    descripcion = request.form['descripcion']
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO productos (nombre, precio, descripcion) VALUES (%s, %s, %s)", (nombre, precio, descripcion))
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

    # Intentar regresar a la página previa (referrer) si es segura
    ref = request.referrer
    if ref and is_safe_url(ref):
        return redirect(ref)

    # Si no hay referrer o no es seguro, redirigir a la lista de edición
    return redirect(url_for('editarproductos'))

@app.route('/editar_producto_modal/<int:id>', methods=['POST'])
def editar_producto_modal(id):
    nombre = request.form['nombre']
    precio = request.form['precio']
    descripcion = request.form['descripcion']
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE productos SET nombre=%s, precio=%s, descripcion=%s WHERE id=%s", (nombre, precio, descripcion, id))
    mysql.connection.commit()
    cursor.close()
    flash('Producto editado correctamente.', 'success')

    # Intentar regresar a la página previa (referrer) si es segura (evita llevar a "agregar")
    ref = request.referrer
    if ref and is_safe_url(ref):
        return redirect(ref)

    # fallback a la vista de edición
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
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO usuario (nombre, email, password, id_rol) VALUES (%s, %s, %s, 2)", (nombre, email, password))
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
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE usuario SET nombre=%s, email=%s, password=%s WHERE id=%s", (nombre, email, password, id))
    mysql.connection.commit()
    cursor.close()
    flash('Usuario editado correctamente.', 'success')
    return redirect(url_for('listausuarios'))

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
        cursor.close()
        if admin:
            return render_template('perfiladmin.html', usuario=admin)
        else:
            flash('Usuario no encontrado.', 'warning')
            return redirect(url_for('admin'))
    else:
        flash('Acceso denegado. Solo administradores.', 'danger')
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=8000)
