from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
app=Flask(__name__)

app.secret_key = 'appsecretkey'  # Clave secreta para sesiones

# Configuración de la base de datos MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'ventas'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)  # Inicializa la extensión MySQL con la app


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

@app.route('/login') # 
def login():
    return render_template('login.html')

@app.route('/registro') # 
def Registro():
    return render_template('registro.html') 

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
    return render_template('Registro.html')


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
                return render_template('admin.html')
            elif user['id_rol'] == 2:
                return render_template('usuario.html')
        else:
            flash('Correo o contraseña incorrectos', 'danger')
            return redirect(url_for('login'))
    return render_template('Login.html')


@app.route('/listar')
def listar():
    return "Vista de perfil de usuario (pendiente)"

@app.route('/admin')
def admin():
    if session.get('rol') == 'admin':
        return render_template('admin.html')
    else:
        flash('Acceso restringido solo para administradores.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada correctamente.', 'success')
    return redirect(url_for('login'))


@app.route('/listar_productos_agregados')
def listar_productos_agregados():
    return "Vista para agregar productos (pendiente)"

@app.route('/listar_productos')
def listar_productos():
    return "Vista para listar productos (pendiente)"

if __name__ == '__main__':
    app.run(debug=True, port=8000)
