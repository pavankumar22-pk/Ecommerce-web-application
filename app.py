"""SmartCart Flask backend.

Keep this file beside config.py, smartcart.db, static/, templates/, and utils/.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import time
import uuid
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps
from pathlib import Path

import bcrypt
import razorpay
from flask import Flask, abort, flash, make_response, redirect, render_template, request, session, url_for
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

import config
from utils.pdf_generator import generate_pdf


BASE_DIR = Path(__file__).resolve().parent
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

app = Flask(__name__, static_folder=str(BASE_DIR / "static"), template_folder=str(BASE_DIR / "templates"))
app.config.update(
    SECRET_KEY=os.environ.get("SMARTCART_SECRET_KEY", config.SECRET_KEY),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    UPLOAD_FOLDER=str(BASE_DIR / "static" / "uploads" / "product_images"),
    ADMIN_UPLOAD_FOLDER=str(BASE_DIR / "static" / "uploads" / "admin_profiles"),
    MAIL_SERVER=config.MAIL_SERVER,
    MAIL_PORT=config.MAIL_PORT,
    MAIL_USE_TLS=config.MAIL_USE_TLS,
    MAIL_USERNAME=config.MAIL_USERNAME,
    MAIL_PASSWORD=config.MAIL_PASSWORD,
)
Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
Path(app.config["ADMIN_UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

mail = Mail(app)
razorpay_client = razorpay.Client(auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET))


def database_path() -> str:
    """Use a configured database only when it exists; otherwise use the project DB."""
    configured = Path(str(config.DB_NAME)).expanduser()
    return str(configured if configured.exists() else BASE_DIR / "smartcart.db")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(database_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "admin_id" not in session:
            flash("Please login first!", "danger")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


def user_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first!", "danger")
            return redirect(url_for("user_login"))
        return view(*args, **kwargs)
    return wrapped


def form_value(name: str) -> str:
    return request.form.get(name, "").strip()


def money(value) -> Decimal:
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError):
        raise ValueError("Enter a valid price.")
    if amount <= 0:
        raise ValueError("Price must be greater than zero.")
    return amount


def upload_image(file_storage, folder: str) -> str:
    original = secure_filename(file_storage.filename or "")
    if not original or "." not in original:
        raise ValueError("Please upload a valid image file.")
    extension = original.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("Image must be PNG, JPG, JPEG, GIF, or WEBP.")
    filename = f"{uuid.uuid4().hex}.{extension}"
    file_storage.save(str(Path(folder) / filename))
    return filename


def delete_image(folder: str, filename: str | None) -> None:
    if not filename:
        return
    path = Path(folder) / Path(filename).name
    if path.is_file():
        path.unlink()


def current_cart() -> dict:
    cart = session.get("cart", {})
    return cart if isinstance(cart, dict) else {}


def selected_cart_items():
    """Fetch current prices and names from the DB; never charge session values."""
    cart = current_cart()
    selected = session.get("selected_products") or list(cart)
    selected = [str(pid) for pid in selected if str(pid) in cart]
    if not selected:
        return [], Decimal("0.00")

    product_ids = [int(pid) for pid in selected if pid.isdigit()]
    if len(product_ids) != len(selected):
        return [], Decimal("0.00")
    placeholders = ",".join("?" for _ in product_ids)
    with get_db_connection() as conn:
        rows = conn.execute(f"SELECT product_id, name, price, image FROM products WHERE product_id IN ({placeholders})", product_ids).fetchall()
    products = {str(row["product_id"]): row for row in rows}
    items, total = [], Decimal("0.00")
    for pid in selected:
        product = products.get(pid)
        quantity = cart.get(pid, {}).get("quantity", 0)
        if product is None or not isinstance(quantity, int) or quantity < 1:
            continue
        price = money(product["price"])
        items.append({"product_id": int(pid), "name": product["name"], "price": price, "quantity": quantity})
        total += price * quantity
    return items, total


@app.route("/")
def home():
    return render_template("index1.html")


@app.route("/admin-signup", methods=["GET", "POST"])
def admin_signup():
    if request.method == "GET":
        return render_template("admin/admin_signup.html")
    name, email = form_value("name"), form_value("email").lower()
    if not name or not email:
        flash("Name and email are required.", "danger")
        return redirect(url_for("admin_signup"))
    with get_db_connection() as conn:
        exists = conn.execute("SELECT 1 FROM admin WHERE email=?", (email,)).fetchone()
    if exists:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect(url_for("admin_signup"))
    session["signup_name"], session["signup_email"] = name, email
    session["otp"] = str(secrets.randbelow(900000) + 100000)
    try:
        message = Message("SmartCart Admin OTP", sender=app.config["MAIL_USERNAME"], recipients=[email])
        message.body = f"Your OTP for SmartCart Admin Registration is: {session['otp']}"
        mail.send(message)
    except Exception:
        app.logger.exception("Could not send admin signup OTP")
        session.pop("otp", None)
        flash("Could not send the OTP. Check the mail configuration and try again.", "danger")
        return redirect(url_for("admin_signup"))
    flash("OTP sent to your email!", "success")
    return redirect(url_for("verify_otp_get"))


@app.route("/verify-otp", methods=["GET"])
def verify_otp_get():
    if not session.get("signup_email"):
        return redirect(url_for("admin_signup"))
    return render_template("admin/verify_otp.html")


@app.route("/verify-otp", methods=["POST"])
def verify_otp_post():
    password, submitted_otp = form_value("password"), form_value("otp")
    if not password or not secrets.compare_digest(session.get("otp", ""), submitted_otp):
        flash("Invalid OTP or password. Try again!", "danger")
        return redirect(url_for("verify_otp_get"))
    name, email = session.get("signup_name"), session.get("signup_email")
    if not name or not email:
        flash("Your signup session has expired. Please try again.", "danger")
        return redirect(url_for("admin_signup"))
    try:
        with get_db_connection() as conn:
            conn.execute("INSERT INTO admin (name, email, password) VALUES (?, ?, ?)", (name, email, bcrypt.hashpw(password.encode(), bcrypt.gensalt())))
    except sqlite3.IntegrityError:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect(url_for("admin_login"))
    for key in ("otp", "signup_name", "signup_email"):
        session.pop(key, None)
    flash("Admin registered successfully!", "success")
    return redirect(url_for("admin_login"))


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin/admin_login.html")
    email, password = form_value("email").lower(), form_value("password")
    with get_db_connection() as conn:
        admin = conn.execute("SELECT * FROM admin WHERE email=?", (email,)).fetchone()
    if not admin or not bcrypt.checkpw(password.encode(), admin["password"]):
        flash("Invalid email or password.", "danger")
        return redirect(url_for("admin_login"))
    session.clear()
    session.update(admin_id=admin["admin_id"], admin_name=admin["name"], admin_email=admin["email"])
    flash("Login successful!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin-dashboard")
@admin_required
def admin_dashboard():
    return render_template("admin/dashboard.html", admin_name=session.get("admin_name"))


@app.route("/admin-logout")
def admin_logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("admin_login"))


@app.route("/admin/add-item", methods=["GET", "POST"])
@admin_required
def add_item():
    if request.method == "GET":
        return render_template("admin/add_item.html")
    name, description, category = form_value("name"), form_value("description"), form_value("category")
    image = request.files.get("image")
    try:
        price = money(form_value("price"))
        if not name or image is None:
            raise ValueError("Name and product image are required.")
        filename = upload_image(image, app.config["UPLOAD_FOLDER"])
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("add_item"))
    try:
        with get_db_connection() as conn:
            conn.execute("INSERT INTO products (name, description, category, price, image) VALUES (?, ?, ?, ?, ?)", (name, description, category, float(price), filename))
    except Exception:
        delete_image(app.config["UPLOAD_FOLDER"], filename)
        raise
    flash("Product added successfully!", "success")
    return redirect(url_for("add_item"))


@app.route("/admin/item-list")
@admin_required
def admin_item_list():
    search, category = request.args.get("search", "").strip(), request.args.get("category", "").strip()
    query, params = "SELECT * FROM products WHERE 1=1", []
    if search:
        query += " AND name LIKE ?"; params.append(f"%{search}%")
    if category:
        query += " AND category = ?"; params.append(category)
    with get_db_connection() as conn:
        categories = conn.execute("SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != ''").fetchall()
        products = conn.execute(query, params).fetchall()
    return render_template("admin/item_list.html", products=products, categories=categories)


@app.route("/admin/view-item/<int:item_id>")
@admin_required
def view_item(item_id):
    with get_db_connection() as conn:
        product = conn.execute("SELECT * FROM products WHERE product_id=?", (item_id,)).fetchone()
    if not product:
        flash("Product not found!", "danger")
        return redirect(url_for("admin_item_list"))
    return render_template("admin/view_item.html", product=product)


@app.route("/admin/update-item/<int:item_id>", methods=["GET", "POST"])
@admin_required
def update_item(item_id):
    with get_db_connection() as conn:
        product = conn.execute("SELECT * FROM products WHERE product_id=?", (item_id,)).fetchone()
        if not product:
            flash("Product not found!", "danger")
            return redirect(url_for("admin_item_list"))
        if request.method == "GET":
            return render_template("admin/update_item.html", product=product)
        try:
            price = money(form_value("price"))
            if not form_value("name"):
                raise ValueError("Product name is required.")
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("update_item", item_id=item_id))
        image = request.files.get("image")
        filename = product["image"]
        if image and image.filename:
            try:
                filename = upload_image(image, app.config["UPLOAD_FOLDER"])
            except ValueError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("update_item", item_id=item_id))
        conn.execute("UPDATE products SET name=?, description=?, category=?, price=?, image=? WHERE product_id=?", (form_value("name"), form_value("description"), form_value("category"), float(price), filename, item_id))
    if filename != product["image"]:
        delete_image(app.config["UPLOAD_FOLDER"], product["image"])
    flash("Product updated successfully!", "success")
    return redirect(url_for("admin_item_list"))


@app.route("/admin/delete-item/<int:item_id>", methods=["GET", "POST"])
@admin_required
def delete_item(item_id):
    with get_db_connection() as conn:
        product = conn.execute("SELECT image FROM products WHERE product_id=?", (item_id,)).fetchone()
        if not product:
            flash("Product not found!", "danger")
            return redirect(url_for("admin_item_list"))
        # Keep historical order items so old orders and invoices remain valid.
        # The current schema has no foreign key from order_items to products.
        conn.execute("DELETE FROM products WHERE product_id=?", (item_id,))
    delete_image(app.config["UPLOAD_FOLDER"], product["image"])
    flash("Product deleted successfully!", "success")
    return redirect(url_for("admin_item_list"))


@app.route("/admin/profile", methods=["GET", "POST"])
@admin_required
def admin_profile():
    admin_id = session["admin_id"]
    with get_db_connection() as conn:
        admin = conn.execute("SELECT * FROM admin WHERE admin_id=?", (admin_id,)).fetchone()
        if not admin:
            session.clear(); return redirect(url_for("admin_login"))
        if request.method == "GET":
            return render_template("admin/admin_profile.html", admin=admin)
        name, email, password = form_value("name"), form_value("email").lower(), form_value("password")
        if not name or not email:
            flash("Name and email are required.", "danger"); return redirect(url_for("admin_profile"))
        image, filename = request.files.get("profile_image"), admin["profile_image"]
        if image and image.filename:
            try: filename = upload_image(image, app.config["ADMIN_UPLOAD_FOLDER"])
            except ValueError as exc:
                flash(str(exc), "danger"); return redirect(url_for("admin_profile"))
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()) if password else admin["password"]
        try:
            conn.execute("UPDATE admin SET name=?, email=?, password=?, profile_image=? WHERE admin_id=?", (name, email, hashed, filename, admin_id))
        except sqlite3.IntegrityError:
            if filename != admin["profile_image"]: delete_image(app.config["ADMIN_UPLOAD_FOLDER"], filename)
            flash("That email is already in use.", "danger"); return redirect(url_for("admin_profile"))
    if filename != admin["profile_image"]: delete_image(app.config["ADMIN_UPLOAD_FOLDER"], admin["profile_image"])
    session.update(admin_name=name, admin_email=email)
    flash("Profile updated successfully!", "success")
    return redirect(url_for("admin_profile"))


@app.route("/user-register", methods=["GET", "POST"])
def user_register():
    if request.method == "GET": return render_template("user/user_register.html")
    name, email, password = form_value("name"), form_value("email").lower(), form_value("password")
    if not name or not email or not password:
        flash("Name, email, and password are required.", "danger"); return redirect(url_for("user_register"))
    try:
        with get_db_connection() as conn:
            conn.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, bcrypt.hashpw(password.encode(), bcrypt.gensalt())))
    except sqlite3.IntegrityError:
        flash("Email already registered! Please login.", "danger"); return redirect(url_for("user_login"))
    flash("Registration successful! Please login.", "success")
    return redirect(url_for("user_login"))


@app.route("/user-login", methods=["GET", "POST"])
def user_login():
    if request.method == "GET": return render_template("user/user_login.html")
    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE email=?", (form_value("email").lower(),)).fetchone()
    if not user or not bcrypt.checkpw(form_value("password").encode(), user["password"]):
        flash("Invalid email or password.", "danger"); return redirect(url_for("user_login"))
    session.clear(); session.update(user_id=user["user_id"], user_name=user["name"], user_email=user["email"])
    flash("Login successful!", "success")
    return redirect(url_for("user_dashboard"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Email a short-lived OTP for a user password reset."""
    if request.method == "GET":
        return render_template("user/forgot_password.html")

    email = form_value("email").lower()
    if not email:
        flash("Please enter your email address.", "danger")
        return redirect(url_for("forgot_password"))

    with get_db_connection() as conn:
        user = conn.execute("SELECT user_id, email FROM users WHERE email=?", (email,)).fetchone()

    # Use one message for unknown addresses so this endpoint cannot be used to
    # discover which email addresses have accounts.
    if user:
        otp = str(secrets.randbelow(900000) + 100000)
        session["password_reset_email"] = user["email"]
        session["password_reset_otp"] = otp
        session["password_reset_expires"] = int(time.time()) + 600
        try:
            message = Message(
                "SmartCart password reset code",
                sender=app.config["MAIL_USERNAME"],
                recipients=[user["email"]],
            )
            message.body = f"Your SmartCart password-reset code is: {otp}. It expires in 10 minutes."
            mail.send(message)
        except Exception:
            app.logger.exception("Could not send password reset email")
            for key in ("password_reset_email", "password_reset_otp", "password_reset_expires"):
                session.pop(key, None)
            flash("Could not send the reset email. Please check the mail configuration and try again.", "danger")
            return redirect(url_for("forgot_password"))

    flash("If that email is registered, a password-reset code has been sent.", "success")
    return redirect(url_for("reset_password"))


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        return render_template("user/reset_password.html")

    otp = form_value("otp")
    password = form_value("password")
    confirm_password = form_value("confirm_password")
    email = session.get("password_reset_email")
    expected_otp = session.get("password_reset_otp")
    expires_at = session.get("password_reset_expires", 0)

    if not email or not expected_otp or time.time() > expires_at:
        for key in ("password_reset_email", "password_reset_otp", "password_reset_expires"):
            session.pop(key, None)
        flash("Your reset code has expired. Please request a new one.", "danger")
        return redirect(url_for("forgot_password"))
    if not password or password != confirm_password:
        flash("Passwords must match.", "danger")
        return redirect(url_for("reset_password"))
    if not secrets.compare_digest(expected_otp, otp):
        flash("Invalid reset code.", "danger")
        return redirect(url_for("reset_password"))

    with get_db_connection() as conn:
        result = conn.execute(
            "UPDATE users SET password=? WHERE email=?",
            (bcrypt.hashpw(password.encode(), bcrypt.gensalt()), email),
        )
    for key in ("password_reset_email", "password_reset_otp", "password_reset_expires"):
        session.pop(key, None)
    if result.rowcount != 1:
        flash("Unable to reset the password. Please try again.", "danger")
        return redirect(url_for("forgot_password"))
    flash("Password reset successfully. Please log in.", "success")
    return redirect(url_for("user_login"))


@app.route("/user-dashboard")
@user_required
def user_dashboard(): return render_template("user/user_home.html", user_name=session.get("user_name"))


@app.route("/user-logout")
def user_logout():
    session.clear(); flash("Logged out successfully!", "success")
    return redirect(url_for("user_login"))


@app.route("/user/products")
@user_required
def user_products():
    search, category = request.args.get("search", "").strip(), request.args.get("category", "").strip()
    query, params = "SELECT * FROM products WHERE 1=1", []
    if search: query += " AND name LIKE ?"; params.append(f"%{search}%")
    if category: query += " AND category=?"; params.append(category)
    with get_db_connection() as conn:
        categories = conn.execute("SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != ''").fetchall()
        products = conn.execute(query, params).fetchall()
    return render_template("user/user_products.html", products=products, categories=categories)


@app.route("/user/product/<int:product_id>")
@user_required
def user_product_details(product_id):
    with get_db_connection() as conn: product = conn.execute("SELECT * FROM products WHERE product_id=?", (product_id,)).fetchone()
    if not product:
        flash("Product not found!", "danger"); return redirect(url_for("user_products"))
    return render_template("user/product_details.html", product=product)


@app.route("/user/add-to-cart/<int:product_id>", methods=["GET", "POST"])
@user_required
def add_to_cart(product_id):
    with get_db_connection() as conn: product = conn.execute("SELECT * FROM products WHERE product_id=?", (product_id,)).fetchone()
    if not product:
        flash("Product not found.", "danger"); return redirect(url_for("user_products"))
    cart, pid = current_cart(), str(product_id)
    cart[pid] = {"name": product["name"], "price": float(product["price"]), "image": product["image"], "quantity": int(cart.get(pid, {}).get("quantity", 0)) + 1}
    session["cart"] = cart
    flash("Item added to cart!", "success")
    return redirect(request.referrer or url_for("user_products"))


@app.route("/user/cart")
@user_required
def view_cart():
    cart = current_cart()
    return render_template("user/cart.html", cart=cart, grand_total=sum(Decimal(str(i.get("price", 0))) * i.get("quantity", 0) for i in cart.values()))


def change_cart(pid, action):
    cart = current_cart()
    if pid in cart:
        cart[pid]["quantity"] = int(cart[pid].get("quantity", 1)) + action
        if cart[pid]["quantity"] <= 0: cart.pop(pid)
    session["cart"] = cart
    session.pop("selected_products", None)
    return redirect(url_for("view_cart"))


@app.route("/user/cart/increase/<pid>", methods=["GET", "POST"])
@user_required
def increase_quantity(pid): return change_cart(pid, 1)


@app.route("/user/cart/decrease/<pid>", methods=["GET", "POST"])
@user_required
def decrease_quantity(pid): return change_cart(pid, -1)


@app.route("/user/cart/remove/<pid>", methods=["GET", "POST"])
@user_required
def remove_from_cart(pid):
    cart = current_cart(); cart.pop(pid, None); session["cart"] = cart; session.pop("selected_products", None)
    flash("Item removed!", "success"); return redirect(url_for("view_cart"))


@app.route("/user/checkout", methods=["POST"])
@user_required
def user_checkout():
    cart = current_cart()
    valid = [str(pid) for pid in request.form.getlist("selected_product") if str(pid) in cart]
    if not valid:
        flash("Please select at least one product!", "danger"); return redirect(url_for("view_cart"))
    session["selected_products"] = valid
    return redirect(url_for("user_address"))


@app.route("/user/address")
@user_required
def user_address(): return render_template("user/address.html")


@app.route("/user/save-address", methods=["POST"])
@user_required
def save_address():
    fields = {key: form_value(key) for key in ("name", "phone", "address", "city", "pincode")}
    if not all(fields.values()):
        flash("Please complete every delivery-address field.", "danger"); return redirect(url_for("user_address"))
    session["delivery_address"] = fields
    return redirect(url_for("user_pay"))


@app.route("/user/pay")
@user_required
def user_pay():
    if not session.get("delivery_address"):
        flash("Please provide a delivery address first.", "danger"); return redirect(url_for("user_address"))
    items, total = selected_cart_items()
    if not items or total <= 0:
        flash("Your selected cart items are no longer available.", "danger"); return redirect(url_for("view_cart"))
    if total > Decimal("500000"):
        flash("Payment amount cannot exceed ₹5,00,000.", "danger"); return redirect(url_for("view_cart"))
    try:
        order = razorpay_client.order.create({"amount": int(total * 100), "currency": "INR", "payment_capture": 1})
    except Exception:
        app.logger.exception("Razorpay order creation failed")
        flash("Unable to start payment. Please try again.", "danger"); return redirect(url_for("view_cart"))
    session["pending_payment"] = {"order_id": order["id"], "amount_paise": int(total * 100), "items": [{**i, "price": str(i["price"])} for i in items]}
    return render_template("user/payment.html", amount=float(total), key_id=config.RAZORPAY_KEY_ID, order_id=order["id"])


@app.route("/verify-payment", methods=["POST"])
@user_required
def verify_payment():
    payment_id, order_id, signature = (request.form.get("razorpay_payment_id"), request.form.get("razorpay_order_id"), request.form.get("razorpay_signature"))
    pending = session.get("pending_payment", {})
    if not payment_id or not order_id or not signature or order_id != pending.get("order_id"):
        flash("Payment verification failed.", "danger"); return redirect(url_for("view_cart"))
    try:
        razorpay_client.utility.verify_payment_signature({"razorpay_order_id": order_id, "razorpay_payment_id": payment_id, "razorpay_signature": signature})
        payment = razorpay_client.payment.fetch(payment_id)
        if payment.get("status") not in {"captured", "authorized"} or payment.get("order_id") != order_id or int(payment.get("amount", -1)) != pending.get("amount_paise"):
            raise ValueError("Payment details did not match the order.")
    except Exception:
        app.logger.exception("Razorpay payment verification failed")
        flash("Payment verification failed. Please contact support.", "danger"); return redirect(url_for("view_cart"))
    try:
        with get_db_connection() as conn:
            existing = conn.execute("SELECT order_id FROM orders WHERE razorpay_payment_id=?", (payment_id,)).fetchone()
            if existing: return redirect(url_for("order_success", order_db_id=existing["order_id"]))
            amount = Decimal(pending["amount_paise"]) / 100
            cur = conn.execute("INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status) VALUES (?, ?, ?, ?, 'paid')", (session["user_id"], order_id, payment_id, float(amount)))
            db_order_id = cur.lastrowid
            for item in pending["items"]:
                conn.execute("INSERT INTO order_items (order_id, product_id, product_name, quantity, price) VALUES (?, ?, ?, ?, ?)", (db_order_id, item["product_id"], item["name"], item["quantity"], float(item["price"])))
    except sqlite3.Error:
        app.logger.exception("Order storage failed")
        flash("There was an error saving your order. Contact support.", "danger"); return redirect(url_for("view_cart"))
    cart = current_cart()
    for item in pending["items"]: cart.pop(str(item["product_id"]), None)
    session["cart"] = cart
    session.pop("selected_products", None); session.pop("pending_payment", None)
    flash("Payment successful and order placed!", "success")
    return redirect(url_for("order_success", order_db_id=db_order_id))


@app.route("/payment-success")
def payment_success():
    flash("Payments must be verified before an order is confirmed.", "warning")
    return redirect(url_for("view_cart"))


@app.route("/user/order-success/<int:order_db_id>")
@user_required
def order_success(order_db_id):
    with get_db_connection() as conn:
        order = conn.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?", (order_db_id, session["user_id"])).fetchone()
        items = conn.execute("SELECT * FROM order_items WHERE order_id=?", (order_db_id,)).fetchall()
    if not order:
        flash("Order not found.", "danger"); return redirect(url_for("user_products"))
    return render_template("user/order_success.html", order=order, items=items)


@app.route("/user/my-orders")
@user_required
def my_orders():
    with get_db_connection() as conn: orders = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC", (session["user_id"],)).fetchall()
    return render_template("user/my_orders.html", orders=orders)


@app.route("/user/download-invoice/<int:order_id>")
@user_required
def download_invoice(order_id):
    with get_db_connection() as conn:
        user = conn.execute("SELECT user_id, name, email FROM users WHERE user_id=?", (session["user_id"],)).fetchone()
        order = conn.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?", (order_id, session["user_id"])).fetchone()
        items = conn.execute("SELECT * FROM order_items WHERE order_id=?", (order_id,)).fetchall()
    if not order:
        flash("Order not found.", "danger"); return redirect(url_for("my_orders"))
    pdf = generate_pdf(render_template("user/invoice.html", order=order, items=items, user=user, delivery_address=session.get("delivery_address", {})))
    if not pdf:
        flash("Error generating PDF.", "danger"); return redirect(url_for("my_orders"))
    response = make_response(pdf.getvalue())
    response.headers.update({"Content-Type": "application/pdf", "Content-Disposition": f"attachment; filename=invoice_{order_id}.pdf"})
    return response


@app.errorhandler(413)
def file_too_large(_error):
    flash("Image is too large. Maximum size is 5 MB.", "danger")
    return redirect(request.referrer or url_for("home"))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
