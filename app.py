import os, qrcode, random, string, sqlite3
from flask import Flask, redirect, url_for, render_template_string, render_template
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dev-secret-key"  

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

DB_PATH = "app.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            rowid INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS library (
            qr_text TEXT NOT NULL,
            qr_image_path TEXT UNIQUE NOT NULL,
            user_rowid INTEGER
        )
    """)
    conn.commit()
    conn.close()

class User(UserMixin):
    def __init__(self, rowid, username, password_hash):
        self.id = rowid
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    row = conn.execute(
        "SELECT rowid, username, password_hash FROM users WHERE rowid = ?",
        (user_id,)
    ).fetchone()
    conn.close()

    if row:
        return User(row["rowid"], row["username"], row["password_hash"])
    return None

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[
        InputRequired(message="Uživatelské jméno je povinné"),
        Length(min=3, max=20, message="Uživatelské jméno musí mít 3-20 znaků")
    ])
    password = PasswordField("Password", validators=[
        InputRequired(message="Heslo je povinné"),
        Length(min=6, message="Heslo musí mít minimálně 6 znaků")
    ])
    confirm = PasswordField("Potvrzení hesla", validators=[
        InputRequired(message="Potvrzení hesla je povinné"),
        EqualTo('password', message='Hesla se neshodují')
    ])
    submit = SubmitField("Zaregistrovat se")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(message="Uživatelské jméno je povinné")])
    password = PasswordField("Password", validators=[InputRequired(message="Heslo je povinné")])
    submit = SubmitField("Přihlásit se")

class QrNewForm(FlaskForm):
    qr_text = StringField(validators=[
        InputRequired(message="Text nebo URL je povinný"),
        Length(min=1, max=1000, message="Text nesmí být delší než 1000 znaků")
    ])
    submit = SubmitField("Vytvořit QR")

class DeleteAccountForm(FlaskForm):
    submit = SubmitField("Ano, smazat můj účet")

@app.route("/")
def index():
    if current_user.is_authenticated:
        con = sqlite3.connect("app.db")
        cur = con.cursor()
        res = cur.execute("SELECT qr_text, qr_image_path FROM library WHERE user_rowid = ?", (current_user.id,))
        user_library = res.fetchall()
        return render_template("index.html", user_library=user_library)
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        password_hash = generate_password_hash(form.password.data)

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (form.username.data, password_hash)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Uživatel už existuje"
            return render_template("error.html", error=error)

    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        conn = get_db()
        row = conn.execute(
            "SELECT rowid, username, password_hash FROM users WHERE username = ?",
            (form.username.data,)
        ).fetchone()
        conn.close()

        if row and check_password_hash(row["password_hash"], form.password.data):
            login_user(User(row["rowid"], row["username"], row["password_hash"]))
            return redirect(url_for("index"))
        
        error = "Špatné přihlašovací údaje"
        return render_template("error.html", error=error)

    return render_template("login.html", form=form)

@app.route("/protected")
@login_required
def protected():
    return render_template("protected.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/qr-new", methods = ['GET', 'POST'])
@login_required
def qr_new():
    form=QrNewForm()
    if form.validate_on_submit():
        qr_text = form.qr_text.data
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_text)
        qr.make(fit=True)

        def generate_safe_filename_string(length=50):
            allowed_chars = string.ascii_letters + string.digits + "_-"
            return ''.join(random.choice(allowed_chars) for _ in range(length))

        file_name = generate_safe_filename_string()

        file_name = file_name + ".png"
        QR_STORAGE = "./static/qr_images/"

        img = qr.make_image(fill_color="black", back_color="white")
        img.save(QR_STORAGE + file_name)


        con = sqlite3.connect("app.db")
        cur = con.cursor()
        qr_image_path = file_name
        cur.execute('INSERT INTO library(qr_text, qr_image_path, user_rowid) VALUES(?, ?, ?)',
                    (qr_text, qr_image_path, current_user.id))
        con.commit()
        con.close()
        return redirect(url_for("qr_display", filename=file_name))
    return render_template("qr_new.html", form=form)

@app.route("/qr-display/<filename>")
@login_required
def qr_display(filename):
    """
    ⚠️ AI PRÁCE: Ověření vlastnictví souboru
    - Kontrola, že soubor patří přihlášenému uživateli
    - Bezpečnostní kontrola
    """
    conn = get_db()
    qr_file = conn.execute(
        "SELECT qr_text, qr_image_path FROM library WHERE qr_image_path = ? AND user_rowid = ?",
        (filename, current_user.id)
    ).fetchone()
    conn.close()
    
    if not qr_file:
        error = "QR kód nebyl nalezen"
        return render_template("error.html", error=error)
    
    return render_template("qr_display.html", qr_text=qr_file[0], qr_image=qr_file[1])

@app.route("/delete-qr/<qr_file>", methods=["POST"])
@login_required
def delete_qr(qr_file):
    """
    ⚠️ AI PRÁCE: Kaskádové mazání QR kódu
    - Ověření vlastnictví
    - Smazání souboru
    - Smazání záznamu z DB
    """
    try:
        conn = get_db()
        
        # Ověření, že QR kód patří přihlášenému uživateli
        row = conn.execute(
            "SELECT qr_image_path FROM library WHERE qr_image_path = ? AND user_rowid = ?",
            (qr_file, current_user.id)
        ).fetchone()
        
        if not row:
            conn.close()
            return redirect(url_for("index"))
        
        # Smazání souboru
        try:
            os.remove(f"./static/qr_images/{qr_file}")
        except FileNotFoundError:
            pass  # Soubor už neexistuje, pokračujeme dál
        
        # Smazání ze DB
        conn.execute(
            "DELETE FROM library WHERE qr_image_path = ? AND user_rowid = ?",
            (qr_file, current_user.id)
        )
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Chyba při mazání QR kódu: {e}")
    
    return redirect(url_for("index"))

@app.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():
    """
    ⚠️ AI PRÁCE: Komplexní operace
    - Kaskádové mazání: účet + všechny QR kódy + soubory
    - Bezpečné transakce v DB
    - Cleanup souborů
    """
    form = DeleteAccountForm()
    
    if form.validate_on_submit():
        try:
            conn = get_db()
            user_id = current_user.id
            
            # Získání všech QR kódů uživatele pro smazání souborů
            qr_files = conn.execute(
                "SELECT qr_image_path FROM library WHERE user_rowid = ?",
                (user_id,)
            ).fetchall()
            
            # Smazání fyzických souborů
            for qr_file in qr_files:
                try:
                    os.remove(f"./static/qr_images/{qr_file[0]}")
                except FileNotFoundError:
                    pass
            
            # Smazání záznamů z DB (kaskádově)
            conn.execute("DELETE FROM library WHERE user_rowid = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE rowid = ?", (user_id,))
            conn.commit()
            conn.close()
            
            logout_user()
            return redirect(url_for("login"))
            
        except Exception as e:
            print(f"Chyba při mazání účtu: {e}")
            error = "Chyba při mazání účtu"
            return render_template("error.html", error=error)
    
    return render_template("delete_account.html", form=form)

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(debug=True)
