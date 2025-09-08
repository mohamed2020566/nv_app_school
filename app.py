# -*- coding: utf-8 -*-
import os
from datetime import datetime, timedelta, date
from functools import wraps
import requests, hashlib, hmac, json

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Mail, Message

# ---------------- Configuration ----------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-prod")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///teacher_portal.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
TRIAL_DAYS = int(os.environ.get("TRIAL_DAYS", "30"))
MONTHLY_PRICE_DZD = int(os.environ.get("MONTHLY_PRICE_DZD", "250"))

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# --- Chargily Pay ---
CHARGILY_SECRET_KEY = os.environ.get("CHARGILY_SECRET_KEY")  # test/live secret key
CHARGILY_MODE = os.environ.get("CHARGILY_MODE", "test").lower()
CHARGILY_API_BASE = (
    "https://pay.chargily.net/api/v2" if CHARGILY_MODE == "live"
    else "https://pay.chargily.net/test/api/v2"
)

# --- Mail (SMTP) ---
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")  # بريد المُرسل
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")  # App Password أو كلمة مرور SMTP
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER", app.config["MAIL_USERNAME"])
mail = Mail(app)

# ---------------- Models ----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(120), default="أستاذ(ة)")
    institution = db.Column(db.String(200))
    subject = db.Column(db.String(120))
    school_year = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    trial_end = db.Column(db.Date, nullable=False, default=lambda: (date.today() + timedelta(days=TRIAL_DAYS)))

    classes = db.relationship("Classroom", backref="user", lazy=True)
    payments = db.relationship("Payment", backref="user", lazy=True)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    @property
    def active_until(self):
        active_date = self.trial_end or date.today()
        if self.payments:
            last = max([p.period_end for p in self.payments if p.period_end], default=None)
            if last and last > active_date:
                active_date = last
        return active_date

    @property
    def is_subscription_active(self):
        return date.today() <= (self.active_until or date.today())

    @property
    def days_left(self):
        days = (self.active_until - date.today()).days
        return max(0, days)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount_dzd = db.Column(db.Integer, default=MONTHLY_PRICE_DZD)
    period_start = db.Column(db.Date, nullable=False)
    period_end = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    method = db.Column(db.String(50), default="يدوي")

class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    students = db.relationship("Student", backref="classroom", cascade="all, delete", lazy=True)
    lesson_plans = db.relationship("LessonPlan", backref="classroom", cascade="all, delete", lazy=True)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    classroom_id = db.Column(db.Integer, db.ForeignKey("classroom.id"), nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    notes = db.relationship("Note", backref="student", cascade="all, delete", lazy=True)
    grades = db.relationship("Grade", backref="student", cascade="all, delete", lazy=True)
    followups = db.relationship("FollowUp", backref="student", cascade="all, delete", lazy=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("student.id"), nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    absence = db.Column(db.Boolean, default=False)
    tardy = db.Column(db.Boolean, default=False)
    behavior = db.Column(db.Text)
    participation = db.Column(db.Integer)
    suggestions = db.Column(db.Text)

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("student.id"), nullable=False)
    term = db.Column(db.Integer, nullable=False)  # 1، 2، 3
    # حقول مرنة + توافق مع القوالب الحالية
    title = db.Column(db.String(200), nullable=False, default="فرض/اختبار")
    exam1 = db.Column(db.Float, nullable=True)
    exam2 = db.Column(db.Float, nullable=True)
    final_exam = db.Column(db.Float, nullable=True)
    score = db.Column(db.Float, nullable=False)
    out_of = db.Column(db.Float, default=20.0)
    weight = db.Column(db.Float, default=1.0)
    date = db.Column(db.Date, default=date.today)

class LessonPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    classroom_id = db.Column(db.Integer, db.ForeignKey("classroom.id"), nullable=False)
    date = db.Column(db.Date, default=date.today)
    title = db.Column(db.String(200), nullable=False)
    objectives = db.Column(db.Text)
    pedagogy = db.Column(db.Text)
    session_plan = db.Column(db.Text)

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    date = db.Column(db.Date, default=date.today)
    title = db.Column(db.String(200), nullable=False)
    notes = db.Column(db.Text)

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    date = db.Column(db.Date, default=date.today)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)

class FollowUp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("student.id"), nullable=False)
    date = db.Column(db.Date, default=date.today)
    plan = db.Column(db.Text)
    notes = db.Column(db.Text)

# ---------------- Helpers ----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="reset-password")

def subscription_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        allowed_paths = {"subscribe", "profile", "logout", "reset_password", "forgot_password"}
        if current_user.is_subscription_active:
            return view_func(*args, **kwargs)
        endpoint = request.endpoint or ""
        if endpoint in allowed_paths:
            return view_func(*args, **kwargs)
        flash("انتهت الفترة التجريبية. الرجاء تجديد الاشتراك للاستمرار.", "warning")
        return redirect(url_for("subscribe"))
    return wrapper

def term_label(term: int) -> str:
    return {1: "الثلاثي الأول", 2: "الثاني", 3: "الثالث"}.get(term, f"فصل {term}")

# ---------------- Auth Routes ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        name = request.form.get("name","أستاذ(ة)")
        if not email or not password:
            flash("يرجى إدخال البريد وكلمة المرور.", "danger")
            return render_template("auth/register.html")
        if User.query.filter_by(email=email).first():
            flash("هذا البريد مسجل مسبقًا.", "warning")
            return render_template("auth/register.html")
        user = User(email=email, name=name)
        user.set_password(password)
        user.trial_end = date.today() + timedelta(days=TRIAL_DAYS)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("مرحبًا! تم إنشاء الحساب. لديك فترة تجريبية لمدة شهر.", "success")
        return redirect(url_for("dashboard"))
    return render_template("auth/register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("تم تسجيل الدخول بنجاح.", "success")
            return redirect(url_for("dashboard"))
        flash("بيانات الدخول غير صحيحة.", "danger")
    return render_template("auth/login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("تم تسجيل الخروج.", "info")
    return redirect(url_for("login"))

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("إن وُجد حساب مطابق سيتم إرسال رابط إعادة التعيين.", "info")
            return render_template("auth/forgot_password.html")
        token = serializer().dumps({"uid": user.id, "email": user.email})
        reset_url = url_for("reset_password", token=token, _external=True)

        try:
            if app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD"):
                msg = Message(subject="إعادة تعيين كلمة المرور - منصة الأساتذة",
                              recipients=[user.email])
                msg.body = (
                    f"مرحبًا {user.name},\n\n"
                    f"لاستعادة كلمة المرور اضغط الرابط التالي:\n{reset_url}\n\n"
                    f"الرابط صالح لمدة 24 ساعة."
                )
                mail.send(msg)
                flash("تم إرسال رابط إعادة التعيين إلى بريدك.", "success")
                return render_template("auth/forgot_password.html")
            else:
                flash("تفعيل البريد غير مُعد. نعرض الرابط هنا لأغراض التجربة:", "warning")
                flash(reset_url, "info")
                return render_template("auth/forgot_password.html", reset_url=reset_url)
        except Exception as e:
            print("MAIL ERROR:", e)
            flash("تعذّر إرسال البريد، نعرض الرابط لأغراض التجربة:", "warning")
            flash(reset_url, "info")
            return render_template("auth/forgot_password.html", reset_url=reset_url)
    return render_template("auth/forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET","POST"])
def reset_password(token):
    try:
        data = serializer().loads(token, max_age=3600*24)  # صالح ليوم
    except SignatureExpired:
        flash("انتهت صلاحية الرابط. أعد المحاولة.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("رابط غير صالح.", "danger")
        return redirect(url_for("forgot_password"))
    user = User.query.get_or_404(data.get("uid"))
    if request.method == "POST":
        pw1 = request.form.get("password","")
        pw2 = request.form.get("password2","")
        if not pw1 or pw1 != pw2:
            flash("الرجاء التأكد من كلمات المرور.", "danger")
            return render_template("auth/reset_password.html")
        user.set_password(pw1)
        db.session.commit()
        flash("تم تحديث كلمة المرور. يمكنك تسجيل الدخول.", "success")
        return redirect(url_for("login"))
    return render_template("auth/reset_password.html")

# ---------------- Profile & Subscription ----------------
@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    if request.method == "POST":
        current_user.name = request.form.get("name") or current_user.name
        current_user.institution = request.form.get("institution")
        current_user.subject = request.form.get("subject")
        current_user.school_year = request.form.get("school_year")
        db.session.commit()
        flash("تم حفظ المعلومات.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", price=MONTHLY_PRICE_DZD)

@app.route("/subscribe", methods=["GET","POST"])
@login_required
def subscribe():
    if request.method == "POST":
        months = int(request.form.get("months","1") or "1")
        start = date.today()
        active_until = current_user.active_until or date.today()
        if active_until >= date.today():
            start = active_until + timedelta(days=1)
        period_end = start + timedelta(days=30*months - 1)
        pay = Payment(user_id=current_user.id, amount_dzd=MONTHLY_PRICE_DZD*months,
                      period_start=start, period_end=period_end, method="يدوي/نموذج")
        db.session.add(pay)
        db.session.commit()
        flash(f"تم تمديد الاشتراك حتى {period_end.strftime('%Y-%m-%d')}.", "success")
        return redirect(url_for("dashboard"))
    payments = Payment.query.filter_by(user_id=current_user.id).order_by(Payment.created_at.desc()).all()
    return render_template("subscribe.html", payments=payments, price=MONTHLY_PRICE_DZD)

def create_chargily_checkout(months: int = 1):
    amount = MONTHLY_PRICE_DZD * months  # DZD
    payload = {
        "amount": amount,
        "currency": "dzd",
        "success_url": url_for("subscribe", _external=True) + "?success=1",
        "failure_url": url_for("subscribe", _external=True) + "?canceled=1",
        "webhook_endpoint": url_for("chargily_webhook", _external=True),
        "locale": "ar",
        "metadata": {"user_id": str(current_user.id), "months": str(months)},
        # "payment_method": "edahabia",  # اختياري
    }
    headers = {"Authorization": f"Bearer {CHARGILY_SECRET_KEY}", "Content-Type": "application/json"}
    r = requests.post(f"{CHARGILY_API_BASE}/checkouts", json=payload, headers=headers, timeout=20)
    r.raise_for_status()
    data = r.json()
    return data["checkout_url"]

@app.route("/subscribe/chargily", methods=["POST"])
@login_required
def subscribe_chargily():
    try:
        months = int(request.form.get("months", "1") or "1")
        checkout_url = create_chargily_checkout(months)
        return redirect(checkout_url, code=303)
    except Exception as e:
        print("CHARGILY CHECKOUT ERROR:", e)
        flash("تعذّر بدء عملية الدفع عبر Chargily Pay.", "danger")
        return redirect(url_for("subscribe"))

@app.route("/webhooks/chargily", methods=["POST"])
def chargily_webhook():
    # 1) التحقق من التوقيع
    signature = request.headers.get("signature") or request.headers.get("Signature")
    payload = request.get_data(as_text=True)
    if not signature or not CHARGILY_SECRET_KEY:
        return ("", 400)
    computed = hmac.new(CHARGILY_SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, computed):
        return ("", 403)

    # 2) معالجة الحدث
    event = json.loads(payload or "{}")
    if event.get("type") == "checkout.paid":
        data = event.get("data", {}) or {}
        meta = data.get("metadata") or {}
        user_id = int(meta.get("user_id", "0") or 0)
        months = int(meta.get("months", "1") or 1)

        user = User.query.get(user_id)
        if user:
            start = date.today()
            if (user.active_until or date.today()) >= date.today():
                start = user.active_until + timedelta(days=1)
            period_end = start + timedelta(days=30*months - 1)
            amount = int(data.get("amount") or MONTHLY_PRICE_DZD*months)
            p = Payment(user_id=user.id, amount_dzd=amount,
                        period_start=start, period_end=period_end,
                        method="Chargily Pay")
            db.session.add(p)
            db.session.commit()
            print(f"[Chargily] Extended user {user.id} to {period_end}")
    return jsonify(success=True), 200

# ---------------- Dashboard ----------------
@app.route("/")
@login_required
@subscription_required
def dashboard():
    classes = Classroom.query.filter_by(user_id=current_user.id).all()
    students_count = Student.query.filter_by(user_id=current_user.id).count()
    return render_template("dashboard.html", classes=classes, students_count=students_count)

# ---------------- Classrooms ----------------
@app.route("/classes", methods=["GET","POST"])
@login_required
@subscription_required
def classes():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        if not name:
            flash("يرجى إدخال اسم القسم.", "danger")
        else:
            c = Classroom(user_id=current_user.id, name=name)
            db.session.add(c)
            db.session.commit()
            flash("تم إضافة القسم.", "success")
        return redirect(url_for("classes"))
    q = request.args.get("q","").strip()
    query = Classroom.query.filter_by(user_id=current_user.id)
    if q:
        query = query.filter(Classroom.name.ilike(f"%{q}%"))
    items = query.order_by(Classroom.created_at.desc()).all()
    return render_template("classes.html", items=items)

@app.route("/classes/<int:class_id>/delete", methods=["POST"])
@login_required
@subscription_required
def delete_class(class_id):
    c = Classroom.query.filter_by(id=class_id, user_id=current_user.id).first_or_404()
    db.session.delete(c)
    db.session.commit()
    flash("تم حذف القسم.", "info")
    return redirect(url_for("classes"))

# ---------------- Students ----------------
@app.route("/students", methods=["GET","POST"])
@login_required
@subscription_required
def students():
    if request.method == "POST":
        first_name = request.form.get("first_name","").strip()
        last_name = request.form.get("last_name","").strip()
        classroom_id = int(request.form.get("classroom_id","0"))
        if not first_name or not last_name or not classroom_id:
            flash("الرجاء تعبئة كل الحقول.", "danger")
        else:
            classroom = Classroom.query.filter_by(id=classroom_id, user_id=current_user.id).first()
            if not classroom:
                flash("قسم غير موجود.", "danger")
            else:
                st = Student(user_id=current_user.id, classroom_id=classroom_id,
                             first_name=first_name, last_name=last_name)
                db.session.add(st)
                db.session.commit()
                flash("تم إضافة التلميذ.", "success")
        return redirect(url_for("students"))

    q = request.args.get("q","").strip()
    class_filter = request.args.get("class_id")
    query = Student.query.filter_by(user_id=current_user.id)
    if q:
        query = query.filter(
            db.or_(Student.first_name.ilike(f"%{q}%"), Student.last_name.ilike(f"%{q}%"))
        )
    if class_filter:
        query = query.filter(Student.classroom_id == int(class_filter))
    items = query.order_by(Student.created_at.desc()).all()
    classes = Classroom.query.filter_by(user_id=current_user.id).all()
    return render_template("students.html", items=items, classes=classes)

@app.route("/classes/<int:class_id>/students")
@login_required
@subscription_required
def students_by_class(class_id):
    classroom = Classroom.query.filter_by(id=class_id, user_id=current_user.id).first_or_404()
    q = request.args.get("q","").strip()
    query = Student.query.filter_by(user_id=current_user.id, classroom_id=class_id)
    if q:
        query = query.filter(
            db.or_(Student.first_name.ilike(f"%{q}%"), Student.last_name.ilike(f"%{q}%"))
        )
    students_list = query.order_by(Student.last_name.asc()).all()
    return render_template("students_by_class.html", classroom=classroom, items=students_list)

@app.route("/students/<int:student_id>/delete", methods=["POST"])
@login_required
@subscription_required
def delete_student(student_id):
    st = Student.query.filter_by(id=student_id, user_id=current_user.id).first_or_404()
    db.session.delete(st)
    db.session.commit()
    flash("تم حذف التلميذ.", "info")
    return redirect(request.referrer or url_for("students"))

# ---------------- Notes ----------------
@app.route("/notes", methods=["GET"])
@login_required
@subscription_required
def notes_home():
    classes = Classroom.query.filter_by(user_id=current_user.id).all()
    selected_class_id = request.args.get("class_id", type=int)
    students_list = []
    if selected_class_id:
        students_list = Student.query.filter_by(user_id=current_user.id, classroom_id=selected_class_id)\
                                     .order_by(Student.last_name.asc()).all()
    return render_template("notes.html", classes=classes, students=students_list, selected_class_id=selected_class_id)

@app.route("/notes/add", methods=["POST"])
@login_required
@subscription_required
def add_note():
    student_id = request.form.get("student_id", type=int)
    st = Student.query.filter_by(id=student_id, user_id=current_user.id).first_or_404()
    note = Note(
        user_id=current_user.id,
        student_id=st.id,
        date=request.form.get("date", type=lambda v: datetime.strptime(v, "%Y-%m-%d").date()) if request.form.get("date") else date.today(),
        absence=bool(request.form.get("absence")),
        tardy=bool(request.form.get("tardy")),
        behavior=request.form.get("behavior"),
        participation=request.form.get("participation", type=int),
        suggestions=request.form.get("suggestions")
    )
    db.session.add(note)
    db.session.commit()
    flash("تم حفظ الملاحظة.", "success")
    return redirect(url_for("notes_home", class_id=st.classroom_id))

@app.route("/notes/list")
@login_required
@subscription_required
def list_notes():
    q = request.args.get("q","").strip()
    class_id = request.args.get("class_id", type=int)
    query = Note.query.join(Student).filter(Note.user_id == current_user.id)
    if class_id:
        query = query.filter(Student.classroom_id == class_id)
    if q:
        query = query.filter(
            db.or_(Student.first_name.ilike(f"%{q}%"), Student.last_name.ilike(f"%{q}%"))
        )
    items = query.order_by(Note.date.desc()).limit(500).all()
    classes = Classroom.query.filter_by(user_id=current_user.id).all()
    return render_template("notes_list.html", items=items, classes=classes, class_id=class_id, q=q)

# ---------------- Grades ----------------
@app.route("/grades", methods=["GET"])
@login_required
@subscription_required
def grades_home():
    classes = Classroom.query.filter_by(user_id=current_user.id).all()
    class_id = request.args.get("class_id", type=int)
    term = request.args.get("term", type=int)
    items, students_list = [], []
    if class_id:
        students_list = Student.query.filter_by(user_id=current_user.id, classroom_id=class_id)\
                                     .order_by(Student.last_name.asc()).all()
        base = Grade.query.join(Student).filter(Grade.user_id==current_user.id, Student.classroom_id==class_id)
        if term:
            base = base.filter(Grade.term==term)
        items = base.order_by(Grade.date.desc()).all()
    return render_template("grades.html", classes=classes, class_id=class_id, term=term,
                           items=items, students=students_list, term_label=term_label)

@app.route("/grades/add", methods=["POST"])
@login_required
@subscription_required
def add_grade():
    student_id = request.form.get("student_id", type=int)
    st = Student.query.filter_by(id=student_id, user_id=current_user.id).first_or_404()
    grade = Grade(
        user_id=current_user.id,
        student_id=st.id,
        term=request.form.get("term", type=int),
        title=request.form.get("title","فرض/اختبار"),
        score=request.form.get("score", type=float),
        out_of=request.form.get("out_of", type=float) or 20.0,
        weight=request.form.get("weight", type=float) or 1.0,
        date=request.form.get("date", type=lambda v: datetime.strptime(v, "%Y-%m-%d").date()) if request.form.get("date") else date.today(),
    )
    db.session.add(grade)
    db.session.commit()
    flash("تم تسجيل النقطة.", "success")
    return redirect(url_for("grades_home", class_id=st.classroom_id, term=grade.term))

def compute_student_average(student_id, term=None):
    q = Grade.query.filter_by(user_id=current_user.id, student_id=student_id)
    if term:
        q = q.filter(Grade.term==term)
    gs = q.all()
    if not gs:
        return None
    total_weight = sum(g.weight for g in gs if g.out_of and g.weight)
    if total_weight == 0:
        return None
    acc = sum((g.score / (g.out_of or 20.0)) * 20.0 * (g.weight or 1.0) for g in gs)
    return round(acc / total_weight, 2)

# ---------------- Lesson Planning ----------------
@app.route("/planning", methods=["GET","POST"])
@login_required
@subscription_required
def planning():
    classes = Classroom.query.filter_by(user_id=current_user.id).all()
    if request.method == "POST":
        classroom_id = request.form.get("classroom_id", type=int)
        cls = Classroom.query.filter_by(user_id=current_user.id, id=classroom_id).first_or_404()
        plan = LessonPlan(
            user_id=current_user.id,
            classroom_id=cls.id,
            date=request.form.get("date", type=lambda v: datetime.strptime(v, "%Y-%m-%d").date()) if request.form.get("date") else date.today(),
            title=request.form.get("title","درس"),
            objectives=request.form.get("objectives"),
            pedagogy=request.form.get("pedagogy"),
            session_plan=request.form.get("session_plan"),
        )
        db.session.add(plan)
        db.session.commit()
        flash("تم حفظ تحضير الدرس.", "success")
        return redirect(url_for("planning"))
    class_id = request.args.get("class_id", type=int)
    items = LessonPlan.query.filter_by(user_id=current_user.id)
    if class_id:
        items = items.filter(LessonPlan.classroom_id==class_id)
    items = items.order_by(LessonPlan.date.desc()).all()
    return render_template("planning.html", classes=classes, items=items, class_id=class_id)

# ---------------- Extra Notebooks ----------------
@app.route("/meetings", methods=["GET","POST"])
@login_required
@subscription_required
def meetings():
    if request.method == "POST":
        mt = Meeting(
            user_id=current_user.id,
            date=request.form.get("date", type=lambda v: datetime.strptime(v, "%Y-%m-%d").date()) if request.form.get("date") else date.today(),
            title=request.form.get("title","اجتماع"),
            notes=request.form.get("notes")
        )
        db.session.add(mt)
        db.session.commit()
        flash("تم حفظ الاجتماع.", "success")
        return redirect(url_for("meetings"))
    q = request.args.get("q","").strip()
    items = Meeting.query.filter_by(user_id=current_user.id)
    if q:
        items = items.filter(Meeting.title.ilike(f"%{q}%"))
    items = items.order_by(Meeting.date.desc()).all()
    return render_template("notebooks/meetings.html", items=items)

@app.route("/activities", methods=["GET","POST"])
@login_required
@subscription_required
def activities():
    if request.method == "POST":
        act = Activity(
            user_id=current_user.id,
            date=request.form.get("date", type=lambda v: datetime.strptime(v, "%Y-%m-%d").date()) if request.form.get("date") else date.today(),
            title=request.form.get("title","نشاط"),
            description=request.form.get("description")
        )
        db.session.add(act)
        db.session.commit()
        flash("تم حفظ النشاط.", "success")
        return redirect(url_for("activities"))
    q = request.args.get("q","").strip()
    items = Activity.query.filter_by(user_id=current_user.id)
    if q:
        items = items.filter(Activity.title.ilike(f"%{q}%"))
    items = items.order_by(Activity.date.desc()).all()
    return render_template("notebooks/activities.html", items=items)

@app.route("/followups", methods=["GET","POST"])
@login_required
@subscription_required
def followups():
    classes = Classroom.query.filter_by(user_id=current_user.id).all()
    students = []
    if request.method == "POST":
        student_id = request.form.get("student_id", type=int)
        st = Student.query.filter_by(id=student_id, user_id=current_user.id).first_or_404()
        fu = FollowUp(
            user_id=current_user.id,
            student_id=st.id,
            date=request.form.get("date", type=lambda v: datetime.strptime(v, "%Y-%m-%d").date()) if request.form.get("date") else date.today(),
            plan=request.form.get("plan"),
            notes=request.form.get("notes")
        )
        db.session.add(fu)
        db.session.commit()
        flash("تم حفظ المتابعة الفردية.", "success")
        return redirect(url_for("followups", class_id=st.classroom_id))
    class_id = request.args.get("class_id", type=int)
    if class_id:
        students = Student.query.filter_by(user_id=current_user.id, classroom_id=class_id).order_by(Student.last_name.asc()).all()
    q = request.args.get("q","").strip()
    items = FollowUp.query.join(Student).filter(FollowUp.user_id==current_user.id)
    if class_id:
        items = items.filter(Student.classroom_id == class_id)
    if q:
        items = items.filter(db.or_(Student.first_name.ilike(f"%{q}%"), Student.last_name.ilike(f"%{q}%")))
    items = items.order_by(FollowUp.date.desc()).all()
    return render_template("notebooks/followups.html", items=items, classes=classes, students=students, class_id=class_id)

# ---------------- Printing Routes ----------------
@app.route("/print/students")
@login_required
@subscription_required
def print_students():
    class_id = request.args.get("class_id", type=int)
    term = request.args.get("term", type=int)
    classroom = Classroom.query.filter_by(id=class_id, user_id=current_user.id).first_or_404()
    students = Student.query.filter_by(user_id=current_user.id, classroom_id=class_id).order_by(Student.last_name.asc()).all()
    return render_template("print/students.html", classroom=classroom, students=students, term=term, term_label=term_label)

@app.route("/print/notes")
@login_required
@subscription_required
def print_notes():
    class_id = request.args.get("class_id", type=int)
    classroom = Classroom.query.filter_by(id=class_id, user_id=current_user.id).first_or_404()
    items = Note.query.join(Student).filter(Note.user_id==current_user.id, Student.classroom_id==class_id)\
                      .order_by(Note.date.desc()).all()
    return render_template("print/notes.html", classroom=classroom, items=items)

@app.route("/print/grades")
@login_required
@subscription_required
def print_grades():
    class_id = request.args.get("class_id", type=int)
    term = request.args.get("term", type=int)
    classroom = Classroom.query.filter_by(id=class_id, user_id=current_user.id).first_or_404()
    students = Student.query.filter_by(user_id=current_user.id, classroom_id=class_id).order_by(Student.last_name.asc()).all()
    averages = []
    for st in students:
        avg = compute_student_average(st.id, term=term)
        averages.append((st, avg))
    return render_template("print/grades.html", classroom=classroom, term=term, averages=averages, term_label=term_label)

@app.route("/print/lesson_plan/<int:plan_id>")
@login_required
@subscription_required
def print_lesson_plan(plan_id):
    plan = LessonPlan.query.filter_by(id=plan_id, user_id=current_user.id).first_or_404()
    return render_template("print/lesson_plan.html", plan=plan)

# ---------------- Utilities ----------------
@app.context_processor
def inject_globals():
    return {
        "MONTHLY_PRICE_DZD": MONTHLY_PRICE_DZD,
        "today": date.today(),
    }

@app.template_filter("full_name")
def full_name(st: Student):
    return f"{st.first_name} {st.last_name}"

@app.template_filter("fmt_date")
def fmt_date(d: date):
    try:
        return d.strftime("%Y-%m-%d")
    except Exception:
        return ""

# ---------------- Initialize DB ----------------
with app.app_context():
    db.create_all()

# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
