from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL

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
            if user['id_rol'] == 1:
                return redirect(url_for('admin'))
            elif user['id_rol'] == 2:
                return render_template('usuario.html')
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

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada correctamente.', 'success')
    return redirect(url_for('login'))

# ------------------- PRODUCTOS -------------------

@app.route('/listaproducto', methods=['GET', 'POST'])
def listaproducto():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM producto")
    productos = cursor.fetchall()
    cursor.close()
    return render_template('listaproducto.html', productos=productos)

@app.route('/agregar_producto', methods=['POST'])
def agregar_producto():
    nombre = request.form['nombre']
    precio = request.form['precio']
    descripcion = request.form['descripcion']
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO producto (nombre, precio, descripcion) VALUES (%s, %s, %s)", (nombre, precio, descripcion))
    mysql.connection.commit()
    cursor.close()
    flash('Producto agregado correctamente.', 'success')
    return redirect(url_for('listaproducto'))

@app.route('/eliminar_producto/<int:id>')
def eliminar_producto(id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM producto WHERE id = %s", (id,))
    mysql.connection.commit()
    cursor.close()
    flash('Producto eliminado correctamente.', 'success')
    return redirect(url_for('listaproducto'))

@app.route('/editar_producto_modal/<int:id>', methods=['POST'])
def editar_producto_modal(id):
    nombre = request.form['nombre']
    precio = request.form['precio']
    descripcion = request.form['descripcion']
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE producto SET nombre=%s, precio=%s, descripcion=%s WHERE id=%s", (nombre, precio, descripcion, id))
    mysql.connection.commit()
    cursor.close()
    flash('Producto editado correctamente.', 'success')
    return redirect(url_for('listaproducto'))

@app.route('/editarproductos')
def editarproductos():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM producto")
    productos = cursor.fetchall()
    cursor.close()
    return render_template('editarproductos.html', productos=productos)

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
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM productos')
    productos = cursor.fetchall()
    cursor.close()
    return render_template('editarproductos.html', productos=productos)


@app.route('/listar_productos')
def listar_productos_agregados():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM productos")
    productos = cursor.fetchall()
    cursor.close()
    return render_template("listaproducto.html", productos=productos)

if __name__ == '__main__':
    app.run(debug=True, port=8000)