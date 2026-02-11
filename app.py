from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from flask_bcrypt import Bcrypt
from functools import wraps

app = Flask(__name__)
app.secret_key = "super_secure_hostel_key_123"
bcrypt = Bcrypt(app)

DATABASE = "database.db"

# ---------------- DATABASE -------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as con:
        cur = con.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'student'
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS rooms(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_no TEXT UNIQUE,
            beds INTEGER,
            available INTEGER
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS bookings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            room_no TEXT,
            status TEXT
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS complaints(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT,
            status TEXT
        )
        """)

init_db()

# ---------------- DECORATORS ----------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access required")
            return redirect("/dashboard")
        return f(*args, **kwargs)
    return wrapper

# ---------------- AUTH ----------------
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        con = get_db()
        user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if user and bcrypt.check_password_hash(user["password"], password):
            session["uid"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            return redirect("/dashboard")
        else:
            flash("Invalid email or password")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = bcrypt.generate_password_hash(
            request.form["password"]
        ).decode("utf-8")

        try:
            with get_db() as con:
                con.execute(
                    "INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                    (name, email, password, "student")
                )
            flash("Registration successful")
            return redirect("/login")
        except:
            flash("Email already exists")

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    con = get_db()

    if session["role"] == "admin":
        bookings = con.execute("SELECT * FROM bookings").fetchall()
        complaints = con.execute("SELECT * FROM complaints").fetchall()
        return render_template(
            "admin_dashboard.html",
            bookings=bookings,
            complaints=complaints
        )

    rooms = con.execute("SELECT * FROM rooms WHERE available > 0").fetchall()
    booking = con.execute(
        "SELECT * FROM bookings WHERE user_id=?",
        (session["uid"],)
    ).fetchone()

    return render_template(
        "student_dashboard.html",
        rooms=rooms,
        booking=booking
    )

# ---------------- ROOM BOOKING ----------------
@app.route("/book/<room_no>")
@login_required
def book(room_no):
    con = get_db()

    existing = con.execute(
        "SELECT * FROM bookings WHERE user_id=?",
        (session["uid"],)
    ).fetchone()

    if existing:
        flash("You already have a booking")
        return redirect("/dashboard")

    con.execute(
        "INSERT INTO bookings(user_id,room_no,status) VALUES(?,?,?)",
        (session["uid"], room_no, "Pending")
    )

    con.execute(
        "UPDATE rooms SET available = available - 1 WHERE room_no=?",
        (room_no,)
    )

    con.commit()
    flash("Room booking requested")
    return redirect("/dashboard")

# ---------------- COMPLAINT ----------------
@app.route("/complaint", methods=["POST"])
@login_required
def complaint():
    msg = request.form["message"]

    with get_db() as con:
        con.execute(
            "INSERT INTO complaints(user_id,message,status) VALUES(?,?,?)",
            (session["uid"], msg, "Pending")
        )

    flash("Complaint submitted")
    return redirect("/dashboard")

# ---------------- ADMIN ACTION ----------------
@app.route("/approve/<int:id>")
@login_required
@admin_required
def approve(id):
    with get_db() as con:
        con.execute(
            "UPDATE bookings SET status='Approved' WHERE id=?",
            (id,)
        )
    flash("Booking approved")
    return redirect("/dashboard")

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
