import streamlit as st
import sqlite3, hashlib, secrets, io, threading, time, os
from datetime import date, datetime, timedelta
import pandas as pd

DB_FILE = os.getenv("DB_FILE", "student_management.db")
MAX_SCHOOLS = None  # None = no application-level school limit. Set an integer only if you intentionally want a cap.

st.set_page_config(page_title="Educational Institution Management System", page_icon="🎓", layout="wide")


# ---------------- DATABASE ----------------

# Per-thread SQLite connections avoid reconnecting for every SELECT/UPDATE.
# WAL lets readers continue while another connection is writing.
_DB_LOCAL = threading.local()

def db():
    conn = getattr(_DB_LOCAL, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA cache_size = -32000")
        _DB_LOCAL.conn = conn
    return conn

def execute(q, p=(), fetch=False, many=False):
    conn = db()
    cur = conn.cursor()
    for attempt in range(4):
        try:
            if many:
                cur.executemany(q, p)
            else:
                cur.execute(q, p)
            result = cur.fetchall() if fetch else None
            if not fetch:
                conn.commit()
            return result
        except sqlite3.OperationalError as e:
            conn.rollback()
            if "locked" not in str(e).lower() or attempt == 3:
                st.error(f"Database error: {e}")
                return None
            time.sleep(0.08 * (attempt + 1))
        except sqlite3.Error as e:
            conn.rollback()
            st.error(f"Database error: {e}")
            return None
        finally:
            cur.close()
    return None

def one(q, p=()):
    r = execute(q, p, True)
    return r[0] if r else None

def now():
    return datetime.now().isoformat(timespec="seconds")

# ---------------- SECURITY ----------------
def hash_password(password):
    salt = secrets.token_hex(16)
    iterations = 310000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations).hex()
    return f"pbkdf2${iterations}${salt}${digest}"


def verify_password(password, stored):
    if not stored: return False
    if stored.startswith("pbkdf2$"):
        try:
            _, it, salt, digest = stored.split("$", 3)
            check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(it)).hex()
            return secrets.compare_digest(check, digest)
        except Exception:
            return False
    # Legacy SHA-256 compatibility.
    return secrets.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)


def make_username(base):
    base = "".join(x for x in base.lower() if x.isalnum()) or "user"
    u = base;
    n = 1
    while one("SELECT id FROM users WHERE username=?", (u,)): n += 1; u = f"{base}{n}"
    return u


def log(uid, action, details=""):
    execute("INSERT INTO audit_logs(user_id,action,details,created_at) VALUES(?,?,?,?)", (uid, action, details, now()))


# ---------------- INITIALIZATION / MIGRATION ----------------
def initialize():
    c = db();
    x = c.cursor()
    x.execute("""CREATE TABLE IF NOT EXISTS schools(
        id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,code TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',subscription_start TEXT,subscription_expiry TEXT,created_at TEXT NOT NULL)""")
    x.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,
        name TEXT NOT NULL,role TEXT NOT NULL,school_id INTEGER,student_id INTEGER,active INTEGER DEFAULT 1,
        can_view_fees INTEGER DEFAULT 0,created_at TEXT NOT NULL,
        FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE,
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE)""")
    # students table must exist before users FK is enforced on insert; SQLite permits creation order.
    x.execute("""CREATE TABLE IF NOT EXISTS students(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,class_id INTEGER NOT NULL,
        name TEXT NOT NULL,roll_number TEXT NOT NULL,phone TEXT,email TEXT,active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE,
        FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS classes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,class_name TEXT NOT NULL,section TEXT,
        created_at TEXT NOT NULL,FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE)""")
    # Recreate users FK issue harmlessly for new DB; SQLite CREATE with missing table is accepted.
    x.execute("""CREATE TABLE IF NOT EXISTS subjects(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,subject_name TEXT NOT NULL,
        max_marks REAL NOT NULL,passing_marks REAL,created_at TEXT NOT NULL,
        FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS marks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL,subject_id INTEGER NOT NULL,marks REAL NOT NULL,
        updated_at TEXT NOT NULL,UNIQUE(student_id,subject_id),FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
        FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS attendance(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,student_id INTEGER NOT NULL,
        attendance_date TEXT NOT NULL,status TEXT NOT NULL,remarks TEXT,recorded_by INTEGER,created_at TEXT NOT NULL,
        UNIQUE(student_id,attendance_date),FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS fee_records(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,student_id INTEGER NOT NULL,fee_month TEXT NOT NULL,
        due_date TEXT,amount_due REAL NOT NULL,notes TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
        UNIQUE(student_id,fee_month),FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS fee_payments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,fee_id INTEGER NOT NULL,amount REAL NOT NULL,payment_date TEXT NOT NULL,
        receipt_no TEXT,notes TEXT,recorded_by INTEGER,created_at TEXT NOT NULL,
        FOREIGN KEY(fee_id) REFERENCES fee_records(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS fee_plans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,student_id INTEGER NOT NULL,
        fee_type TEXT NOT NULL DEFAULT 'Monthly',plan_name TEXT,contract_total REAL DEFAULT 0,
        installment_amount REAL DEFAULT 0,installments INTEGER DEFAULT 0,start_date TEXT,end_date TEXT,
        active INTEGER DEFAULT 1,notes TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
        FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE,
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS timetable(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,class_id INTEGER NOT NULL,day_of_week TEXT NOT NULL,
        period_name TEXT NOT NULL,subject_id INTEGER,teacher_id INTEGER,start_time TEXT,end_time TEXT,room TEXT,
        FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS parent_student(
        id INTEGER PRIMARY KEY AUTOINCREMENT,parent_user_id INTEGER NOT NULL,student_id INTEGER NOT NULL,
        UNIQUE(parent_user_id,student_id),FOREIGN KEY(parent_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS audit_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT NOT NULL,details TEXT,created_at TEXT NOT NULL)""")
    x.execute("""CREATE TABLE IF NOT EXISTS subject_attendance(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,student_id INTEGER NOT NULL,
        subject_id INTEGER NOT NULL,attendance_date TEXT NOT NULL,status TEXT NOT NULL,remarks TEXT,
        recorded_by INTEGER,created_at TEXT NOT NULL,UNIQUE(student_id,subject_id,attendance_date),
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
        FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS teacher_attendance(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,teacher_id INTEGER NOT NULL,
        attendance_date TEXT NOT NULL,status TEXT NOT NULL,remarks TEXT,recorded_by INTEGER,
        created_at TEXT NOT NULL,UNIQUE(teacher_id,attendance_date),
        FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS student_feedback(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,student_id INTEGER NOT NULL,
        teacher_id INTEGER NOT NULL,feedback TEXT NOT NULL,performance_level TEXT,
        created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
        FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE)""")
    x.execute("CREATE TABLE IF NOT EXISTS platform_settings(key TEXT PRIMARY KEY,value TEXT)")
    x.execute("""CREATE TABLE IF NOT EXISTS notifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,school_id INTEGER NOT NULL,student_id INTEGER,
        recipient_type TEXT NOT NULL,channel TEXT NOT NULL,message TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Prepared',
        created_by INTEGER,created_at TEXT NOT NULL,FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE SET NULL)""")
    # Migrate old DB columns.
    cols = [r[1] for r in x.execute("PRAGMA table_info(users)").fetchall()]
    if "student_id" not in cols: x.execute("ALTER TABLE users ADD COLUMN student_id INTEGER")
    if "can_view_fees" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_view_fees INTEGER DEFAULT 0")
    if "can_change_username" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_change_username INTEGER DEFAULT 0")
    if "can_change_password" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_change_password INTEGER DEFAULT 0")
    if "can_manage_fees" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_manage_fees INTEGER DEFAULT 0")
    if "can_manage_attendance" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_manage_attendance INTEGER DEFAULT 0")
    if "can_manage_results" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_manage_results INTEGER DEFAULT 0")
    if "can_manage_students" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_manage_students INTEGER DEFAULT 0")
    if "can_manage_classes" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_manage_classes INTEGER DEFAULT 0")
    if "can_manage_accounts" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_manage_accounts INTEGER DEFAULT 0")
    if "can_view_dashboard" not in cols: x.execute("ALTER TABLE users ADD COLUMN can_view_dashboard INTEGER DEFAULT 1")
    if "school_forced_suspended" not in cols:
        x.execute("ALTER TABLE users ADD COLUMN school_forced_suspended INTEGER DEFAULT 0")
    # Academic result history: each academic year/class is stored separately.
    x.execute("""CREATE TABLE IF NOT EXISTS result_marks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        subject_id INTEGER NOT NULL,
        class_id INTEGER NOT NULL,
        academic_year TEXT NOT NULL,
        marks REAL NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(student_id,subject_id,academic_year),
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
        FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
        FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE CASCADE)""")
    x.execute("""CREATE TABLE IF NOT EXISTS student_promotions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        school_id INTEGER NOT NULL,
        from_class_id INTEGER NOT NULL,
        to_class_id INTEGER NOT NULL,
        academic_year TEXT NOT NULL,
        promoted_at TEXT NOT NULL,
        promoted_by INTEGER,
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE)""")

    # Professional fee-management migrations; existing fee records/payments remain intact.
    fee_cols = [r[1] for r in x.execute("PRAGMA table_info(fee_records)").fetchall()]
    for col, definition in [
        ("fee_type", "TEXT DEFAULT 'Monthly'"),
        ("period_label", "TEXT"),
        ("period_start", "TEXT"),
        ("period_end", "TEXT"),
        ("discount", "REAL DEFAULT 0"),
        ("late_fee", "REAL DEFAULT 0"),
        # Fee history fields keep each month/semester/year as an independent cycle.
        ("academic_year", "TEXT"),
        ("cycle_number", "INTEGER DEFAULT 1")
    ]:
        if col not in fee_cols:
            x.execute(f"ALTER TABLE fee_records ADD COLUMN {col} {definition}")
    school_cols = [r[1] for r in x.execute("PRAGMA table_info(schools)").fetchall()]
    if "institution_type" not in school_cols: x.execute("ALTER TABLE schools ADD COLUMN institution_type TEXT DEFAULT 'School'")
    class_cols = [r[1] for r in x.execute("PRAGMA table_info(classes)").fetchall()]
    if "incharge_teacher_id" not in class_cols: x.execute("ALTER TABLE classes ADD COLUMN incharge_teacher_id INTEGER")
    scols = [r[1] for r in x.execute("PRAGMA table_info(subjects)").fetchall()]
    if "passing_marks" not in scols: x.execute("ALTER TABLE subjects ADD COLUMN passing_marks REAL")
    # Old app had student credentials inside students. Keep them if present, but accounts now live in users.
    stcols = [r[1] for r in x.execute("PRAGMA table_info(students)").fetchall()]
    if "student_username" in stcols and "student_password" in stcols:
        rows = x.execute(
            "SELECT id,school_id,name,student_username,student_password FROM students WHERE student_username IS NOT NULL").fetchall()
        for sid, sch, name, u, pw in rows:
            if not x.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone():
                x.execute(
                    "INSERT INTO users(username,password,name,role,school_id,student_id,active,created_at) VALUES(?,?,?,?,?,?,1,?)",
                    (u, pw, name, "student", sch, sid, now()))
    if not x.execute("SELECT id FROM users WHERE username='admin'").fetchone():
        x.execute("""INSERT INTO users(username,password,name,role,school_id,active,
                    can_change_username,can_change_password,created_at)
                    VALUES(?,?,?,?,NULL,1,1,1,?)""",
                  ("admin", hash_password("Admin@123"), "System Administrator", "admin", now()))
    # Preserve legacy marks by copying them into the current academic-year history table.
    current_year = str(date.today().year)
    legacy_marks = x.execute("""SELECT m.student_id,m.subject_id,s.class_id,m.marks,m.updated_at
                                FROM marks m JOIN students s ON s.id=m.student_id""").fetchall()
    for stid,subid,cid,mk,updated in legacy_marks:
        x.execute("""INSERT OR IGNORE INTO result_marks
                    (student_id,subject_id,class_id,academic_year,marks,updated_at)
                    VALUES(?,?,?,?,?,?)""",
                  (stid,subid,cid,current_year,float(mk),updated or now()))
    # Performance indexes. They are created once and make the most-used
    # school/class/student/fee queries index-backed instead of full-table scans.
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_users_school_role_active ON users(school_id,role,active)",
        "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
        "CREATE INDEX IF NOT EXISTS idx_students_school_class_active ON students(school_id,class_id,active)",
        "CREATE INDEX IF NOT EXISTS idx_students_school_roll ON students(school_id,roll_number)",
        "CREATE INDEX IF NOT EXISTS idx_classes_school_name_section ON classes(school_id,class_name,section)",
        "CREATE INDEX IF NOT EXISTS idx_subjects_school_name ON subjects(school_id,subject_name)",
        "CREATE INDEX IF NOT EXISTS idx_marks_student_subject ON marks(student_id,subject_id)",
        "CREATE INDEX IF NOT EXISTS idx_result_marks_student_year ON result_marks(student_id,academic_year)",
        "CREATE INDEX IF NOT EXISTS idx_result_marks_class_year ON result_marks(class_id,academic_year,student_id)",
        "CREATE INDEX IF NOT EXISTS idx_attendance_student_date ON attendance(student_id,attendance_date)",
        "CREATE INDEX IF NOT EXISTS idx_attendance_school_date ON attendance(school_id,attendance_date)",
        "CREATE INDEX IF NOT EXISTS idx_subject_att_student_date ON subject_attendance(student_id,attendance_date)",
        "CREATE INDEX IF NOT EXISTS idx_teacher_att_school_date ON teacher_attendance(school_id,attendance_date)",
        "CREATE INDEX IF NOT EXISTS idx_feedback_student ON student_feedback(student_id)",
        "CREATE INDEX IF NOT EXISTS idx_fee_records_school_student ON fee_records(school_id,student_id)",
        "CREATE INDEX IF NOT EXISTS idx_fee_records_student_period ON fee_records(student_id,fee_month)",
        "CREATE INDEX IF NOT EXISTS idx_fee_records_school_year_class ON fee_records(school_id,academic_year,student_id)",
        "CREATE INDEX IF NOT EXISTS idx_fee_records_school_type_year ON fee_records(school_id,fee_type,academic_year)",
        "CREATE INDEX IF NOT EXISTS idx_fee_records_school_due ON fee_records(school_id,due_date)",
        "CREATE INDEX IF NOT EXISTS idx_fee_payments_fee ON fee_payments(fee_id)",
        "CREATE INDEX IF NOT EXISTS idx_fee_records_school_class_type_key ON fee_records(school_id,student_id,fee_type,fee_month)",
        "CREATE INDEX IF NOT EXISTS idx_timetable_school_class_day ON timetable(school_id,class_id,day_of_week)",
        "CREATE INDEX IF NOT EXISTS idx_parent_student_parent ON parent_student(parent_user_id,student_id)",
        "CREATE INDEX IF NOT EXISTS idx_parent_student_student ON parent_student(student_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_notifications_school_created ON notifications(school_id,created_at)",
    ]
    for index_sql in indexes:
        x.execute(index_sql)
    c.commit()
    # Keep the initialized thread-local connection alive for the app session.


initialize()


# ---------------- SCHOOL / RESULT HELPERS ----------------
# The application-level school cap is disabled by default; production scale is
# determined by the database/server resources rather than a hard-coded 10-school limit.
def school_active(sid):
    s = one("SELECT status,subscription_expiry FROM schools WHERE id=?", (sid,))
    if not s or s[0] != "ACTIVE": return False
    if s[1]:
        try:
            if date.today() > datetime.strptime(s[1], "%Y-%m-%d").date():
                execute("UPDATE schools SET status='SUSPENDED' WHERE id=?", (sid,))
                return False
        except ValueError:
            return False
    return True


def academic_year_options():
    y = date.today().year
    return [str(y-1), str(y), str(y+1)]


def current_academic_year():
    return str(date.today().year)


def suspend_school(school_id, actor_id):
    execute("UPDATE schools SET status='SUSPENDED' WHERE id=?", (school_id,))
    execute("""UPDATE users SET active=0,school_forced_suspended=1
               WHERE school_id=? AND role!='admin'""", (school_id,))
    log(actor_id, "SUSPEND_INSTITUTION", f"school={school_id}; all school accounts suspended")


def activate_school(school_id, actor_id):
    execute("UPDATE schools SET status='ACTIVE' WHERE id=?", (school_id,))
    # Reactivate only accounts that were suspended because of the school.
    # Individually suspended accounts remain suspended.
    execute("""UPDATE users SET active=1,school_forced_suspended=0
               WHERE school_id=? AND school_forced_suspended=1""", (school_id,))
    log(actor_id, "ACTIVATE_INSTITUTION", f"school={school_id}; school-forced accounts reactivated")


def suspend_account(account_id, actor_id, reason="INDIVIDUAL"):
    execute("UPDATE users SET active=0,school_forced_suspended=0 WHERE id=? AND role!='admin'", (account_id,))
    log(actor_id, "SUSPEND_ACCOUNT", f"{account_id};reason={reason}")


def activate_account(account_id, actor_id):
    execute("UPDATE users SET active=1,school_forced_suspended=0 WHERE id=? AND role!='admin'", (account_id,))
    log(actor_id, "ACTIVATE_ACCOUNT", str(account_id))


def school_code():
    while True:
        code = secrets.token_hex(3).upper()
        if not one("SELECT id FROM schools WHERE code=?", (code,)): return code


def grade(p):
    if p >= 90: return "A+"
    if p >= 80: return "A"
    if p >= 70: return "B"
    if p >= 60: return "C"
    if p >= 50: return "D"
    return "F"


def result_calc(marks, maxs, passes):
    if not maxs: return 0, 0, "F", "PENDING"
    total = sum(float(x) for x in marks);
    possible = sum(float(x) for x in maxs)
    pct = (total / possible * 100) if possible else 0
    g = grade(pct)
    if any(p is None for p in passes): return total, pct, g, "PENDING"
    return total, pct, g, "PASS" if all(float(m) >= float(p) for m, p in zip(marks, passes)) else "FAIL"



def student_result(sid, academic_year=None, class_id=None):
    """Build one result with one SQL query instead of one query per subject."""
    academic_year = academic_year or current_academic_year()
    current = current_academic_year()
    stu = one(
        """SELECT s.id,s.name,s.roll_number,c.class_name,c.section,s.class_id,s.school_id
           FROM students s JOIN classes c ON s.class_id=c.id WHERE s.id=?""", (sid,))
    if not stu:
        return None

    display_class_id = class_id or stu[5]
    class_row = one("SELECT class_name,section FROM classes WHERE id=?", (display_class_id,))
    class_name = class_row[0] if class_row else stu[3]
    section = class_row[1] if class_row else stu[4]

    rows_sql = """
        SELECT sub.id,sub.subject_name,sub.max_marks,sub.passing_marks,
               CASE
                 WHEN ? = ? THEN COALESCE(rm.marks, m.marks, 0)
                 ELSE COALESCE(rm.marks, 0)
               END AS obtained
        FROM subjects sub
        LEFT JOIN result_marks rm
          ON rm.subject_id=sub.id AND rm.student_id=? AND rm.academic_year=?
        LEFT JOIN marks m
          ON m.subject_id=sub.id AND m.student_id=?
        WHERE sub.school_id=?
        ORDER BY sub.subject_name
    """
    subs = execute(rows_sql, (academic_year,current,sid,academic_year,sid,stu[6]), fetch=True) or []
    rows=[]; ms=[]; mx=[]; ps=[]
    for sub in subs:
        m=float(sub[4] or 0)
        rows.append({
            "Subject":sub[1],"Marks":m,"Maximum Marks":sub[2],
            "Passing Marks":sub[3],
            "Status":"PENDING" if sub[3] is None else ("PASS" if m >= float(sub[3]) else "FAIL")
        })
        ms.append(m); mx.append(float(sub[2] or 0)); ps.append(sub[3])

    total,pct,g,res=result_calc(ms,mx,ps)
    return (stu[0],stu[1],stu[2],class_name,section,display_class_id,academic_year), pd.DataFrame(rows), total,pct,g,res


def class_positions(sid, cid, academic_year):
    """Calculate an entire class in one aggregate query (no N+1 student queries)."""
    current = current_academic_year()
    if academic_year == current:
        student_rows = execute(
            """SELECT id,name,roll_number FROM students
               WHERE school_id=? AND class_id=? AND active=1 ORDER BY roll_number""",
            (sid,cid), fetch=True) or []
    else:
        student_rows = execute(
            """SELECT DISTINCT s.id,s.name,s.roll_number
               FROM result_marks rm JOIN students s ON s.id=rm.student_id
               WHERE s.school_id=? AND rm.class_id=? AND rm.academic_year=?
               ORDER BY s.roll_number""",
            (sid,cid,academic_year), fetch=True) or []

    if not student_rows:
        return pd.DataFrame()

    # Subjects are shared by the institution. The CROSS JOIN creates one small
    # row per student/subject and the aggregation returns one row per student.
    data = execute(
        """SELECT s.id,s.name,s.roll_number,
                  COALESCE(SUM(
                    CASE WHEN ?=? THEN COALESCE(rm.marks,m.marks,0)
                         ELSE COALESCE(rm.marks,0) END),0) AS total,
                  COALESCE(SUM(sub.max_marks),0) AS possible,
                  SUM(CASE WHEN sub.passing_marks IS NULL THEN 1 ELSE 0 END) AS pending_count,
                  SUM(CASE
                        WHEN sub.passing_marks IS NOT NULL
                         AND (CASE WHEN ?=? THEN COALESCE(rm.marks,m.marks,0)
                                   ELSE COALESCE(rm.marks,0) END) < sub.passing_marks
                        THEN 1 ELSE 0 END) AS fail_count
           FROM students s
           JOIN subjects sub ON sub.school_id=s.school_id
           LEFT JOIN result_marks rm
             ON rm.student_id=s.id AND rm.subject_id=sub.id AND rm.academic_year=?
           LEFT JOIN marks m
             ON m.student_id=s.id AND m.subject_id=sub.id
           WHERE s.school_id=? AND s.class_id=? AND s.active=1
           GROUP BY s.id,s.name,s.roll_number
           ORDER BY s.roll_number""",
        (academic_year,current,academic_year,current,academic_year,sid,cid), fetch=True) or []

    scored=[]
    for r in data:
        total=float(r[3] or 0)
        possible=float(r[4] or 0)
        pct=(total/possible*100) if possible else 0
        pending=int(r[5] or 0)>0
        failed=int(r[6] or 0)>0
        scored.append({
            "Student ID":r[0],"Student":r[1],"Roll No":r[2],
            "Total":round(total,2),"Percentage":round(pct,2),
            "Grade":grade(pct),"Result":"PENDING" if pending else ("PASS" if not failed else "FAIL")
        })

    if not scored:
        return pd.DataFrame()
    df=pd.DataFrame(scored)
    df["Position"]=df["Percentage"].rank(method="min",ascending=False).astype(int)
    return df.sort_values(["Position","Percentage","Roll No"],
                          ascending=[True,False,True]).reset_index(drop=True)

def top_three_positions_text(sid,cid,academic_year):
    df=class_positions(sid,cid,academic_year)
    if df.empty: return []
    out=[]
    for pos in sorted([int(x) for x in df["Position"].unique() if int(x)<=3]):
        names=df.loc[df["Position"]==pos,"Student"].tolist()
        out.append((pos,names))
    return out


def excel_bytes(df):
    out = io.BytesIO()
    try:
        with pd.ExcelWriter(out, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Report")
        return out.getvalue()
    except Exception:
        return None


def pdf_bytes(sid):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    r = student_result(sid)
    if not r: return None
    stu, df, total, pct, g, res = r
    school = one("SELECT name,code FROM schools WHERE id=(SELECT school_id FROM students WHERE id=?)", (sid,))
    out = io.BytesIO();
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=35, leftMargin=35, topMargin=35, bottomMargin=35)
    styles = getSampleStyleSheet();
    story = [Paragraph(school[0], styles["Title"]), Paragraph("Student Result Card", styles["Heading2"]), Spacer(1, 10)]
    story.append(Paragraph(f"Student: {stu[1]} | Roll No: {stu[2]} | Class: {stu[3]} Section {stu[4] or ''}",
                           styles["BodyText"]));
    story.append(Spacer(1, 10))
    data = [["Subject", "Marks", "Maximum", "Passing", "Status"]] + df[
        ["Subject", "Marks", "Maximum Marks", "Passing Marks", "Status"]].fillna("Not set").values.tolist()
    t = Table(data, repeatRows=1);
    t.setStyle(TableStyle(
        [("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey), ("GRID", (0, 0), (-1, -1), .5, colors.grey),
         ("ALIGN", (1, 1), (-1, -1), "CENTER")]))
    story += [t, Spacer(1, 12),
              Paragraph(f"Total: {total:g} | Percentage: {pct:.2f}% | Grade: {g} | Result: {res}", styles["Heading3"])]
    doc.build(story);
    return out.getvalue()



# ---------------- NEW FEATURE HELPERS ----------------
def account_permission(user_id, column):
    row = one(f"SELECT {column} FROM users WHERE id=?", (user_id,))
    return bool(row and row[0])

def attendance_summary(student_id):
    rows = execute("SELECT status,COUNT(*) FROM attendance WHERE student_id=? GROUP BY status",
                   (student_id,), fetch=True) or []
    total = sum(r[1] for r in rows)
    present = sum(r[1] for r in rows if r[0] == "Present")
    return total, present, (present / total * 100 if total else None)

def attendance_display(student_id):
    total, present, pct = attendance_summary(student_id)
    return "Attendance Not Added" if total == 0 else f"{pct:.2f}% ({present}/{total})"


def detailed_results_csv(sid, cid, academic_year=None):
    """Create a class report with batched SQL instead of one query per student/subject."""
    academic_year = academic_year or current_academic_year()
    current = current_academic_year()
    school = one("SELECT name,institution_type FROM schools WHERE id=?", (sid,))
    subjects = execute(
        "SELECT id,subject_name,max_marks,passing_marks FROM subjects WHERE school_id=? ORDER BY subject_name",
        (sid,), fetch=True) or []

    if academic_year == current:
        students = execute(
            """SELECT s.id,s.name,s.roll_number,c.class_name,c.section
               FROM students s JOIN classes c ON c.id=s.class_id
               WHERE s.school_id=? AND s.class_id=? AND s.active=1
               ORDER BY s.roll_number""", (sid,cid), fetch=True) or []
    else:
        students = execute(
            """SELECT DISTINCT s.id,s.name,s.roll_number,c.class_name,c.section
               FROM result_marks rm JOIN students s ON s.id=rm.student_id
               JOIN classes c ON c.id=rm.class_id
               WHERE s.school_id=? AND rm.class_id=? AND rm.academic_year=?
               ORDER BY s.roll_number""", (sid,cid,academic_year), fetch=True) or []

    if not students:
        return pd.DataFrame()

    # One batched query for every student/subject mark.
    mark_rows = execute(
        """SELECT s.id AS student_id,sub.id AS subject_id,
                  CASE WHEN ?=? THEN COALESCE(rm.marks,m.marks,0)
                       ELSE COALESCE(rm.marks,0) END AS marks
           FROM students s
           JOIN subjects sub ON sub.school_id=s.school_id
           LEFT JOIN result_marks rm
             ON rm.student_id=s.id AND rm.subject_id=sub.id AND rm.academic_year=?
           LEFT JOIN marks m
             ON m.student_id=s.id AND m.subject_id=sub.id
           WHERE s.school_id=? AND s.class_id=? AND s.active=1""",
        (academic_year,current,academic_year,sid,cid), fetch=True) or []
    mark_map={(int(r[0]),int(r[1])):float(r[2] or 0) for r in mark_rows}

    posdf=class_positions(sid,cid,academic_year)
    posmap={int(r["Student ID"]):int(r["Position"])
            for _,r in posdf.iterrows()} if not posdf.empty else {}

    data=[]
    for s in students:
        row={"Institution":school[0],"Institution Type":school[1],
             "Academic Year":academic_year,"Class":s[3],"Section":s[4] or "",
             "Student Name":s[1],"Roll No":s[2]}
        total=possible=0.0; pending=False; passed=True
        for sub in subjects:
            m=mark_map.get((int(s[0]),int(sub[0])),0.0)
            row[f"{sub[1]} Marks"]=m
            total += m
            possible += float(sub[2] or 0)
            if sub[3] is None:
                pending=True
            elif m < float(sub[3]):
                passed=False

        pct=total/possible*100 if possible else 0
        row["Total Obtained"]=round(total,2)
        row["Total Marks"]=round(possible,2)
        row["Percentage"]=round(pct,2)
        row["Grade"]=grade(pct)
        row["Result"]="PENDING" if pending else ("PASS" if passed else "FAIL")
        row["Position"]=posmap.get(int(s[0]),"")
        row["Attendance"]=attendance_display(s[0])
        data.append(row)

    df=pd.DataFrame(data)
    if df.empty:
        return df

    summary_rows=[{col:"" for col in df.columns} for _ in range(2)]
    summary_rows[0]["Student Name"]="Subject Total Marks"
    summary_rows[1]["Student Name"]="Subject Passing Marks"
    for sub in subjects:
        summary_rows[0][f"{sub[1]} Marks"]=float(sub[2] or 0)
        summary_rows[1][f"{sub[1]} Marks"]="" if sub[3] is None else float(sub[3])
    return pd.concat([df,pd.DataFrame(summary_rows)],ignore_index=True)

def attendance_csv_df(sid, cid=None):
    sql="""SELECT s.name,s.roll_number,c.class_name,COALESCE(c.section,''),a.attendance_date,a.status,COALESCE(a.remarks,'')
           FROM attendance a JOIN students s ON s.id=a.student_id
           JOIN classes c ON c.id=s.class_id WHERE a.school_id=?"""
    p=[sid]
    if cid is not None:
        sql+=" AND s.class_id=?"; p.append(cid)
    sql+=" ORDER BY c.class_name,c.section,a.attendance_date DESC,s.roll_number"
    rows=execute(sql,tuple(p),fetch=True) or []
    return pd.DataFrame(rows,columns=["Student","Roll No","Class","Section","Date","Status","Remarks"])


def teacher_attendance_df(sid):
    rows=execute("""SELECT u.name,u.username,ta.attendance_date,ta.status,COALESCE(ta.remarks,'')
                    FROM teacher_attendance ta JOIN users u ON u.id=ta.teacher_id
                    WHERE ta.school_id=? ORDER BY ta.attendance_date DESC,u.name""",(sid,),fetch=True) or []
    return pd.DataFrame(rows,columns=["Teacher","Username","Date","Status","Remarks"])

def subject_attendance_df(sid,cid,subject_id):
    rows=execute("""SELECT s.name,s.roll_number,c.class_name,c.section,sub.subject_name,
                           sa.attendance_date,sa.status,COALESCE(sa.remarks,'')
                    FROM subject_attendance sa JOIN students s ON s.id=sa.student_id
                    JOIN classes c ON c.id=s.class_id JOIN subjects sub ON sub.id=sa.subject_id
                    WHERE sa.school_id=? AND s.class_id=? AND sa.subject_id=?
                    ORDER BY sa.attendance_date DESC,s.roll_number""",
                 (sid,cid,subject_id),fetch=True) or []
    return pd.DataFrame(rows,columns=["Student","Roll No","Class","Section","Subject","Date","Status","Remarks"])


def institution_statistics(sid):
    """Return all institution dashboard counts with one grouped query."""
    rows = execute(
        """SELECT role,COUNT(*) FROM users
           WHERE school_id=? GROUP BY role""", (sid,), fetch=True) or []
    counts={r[0]:int(r[1]) for r in rows}
    students=one("SELECT COUNT(*) FROM students WHERE school_id=?",(sid,))
    classes=one("SELECT COUNT(*) FROM classes WHERE school_id=?",(sid,))
    return (
        counts.get("teacher",0), counts.get("principal",0),
        counts.get("management",0), counts.get("parent",0),
        int(students[0] if students else 0), int(classes[0] if classes else 0)
    )

def create_user(username, password, name, role, school_id=None, student_id=None, permissions=None):
    permissions = permissions or {}
    username = username.strip()
    if one("SELECT id FROM users WHERE username=?", (username,)):
        return False, "Username already exists."
    execute("""INSERT INTO users(
        username,password,name,role,school_id,student_id,active,can_view_fees,
        can_change_username,can_change_password,can_manage_fees,can_manage_attendance,
        can_manage_results,can_manage_students,can_manage_classes,can_manage_accounts,
        can_view_dashboard,created_at)
        VALUES(?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?)""",
        (username,hash_password(password),name.strip(),role,school_id,student_id,
         int(bool(permissions.get("can_view_fees",0))),
         int(bool(permissions.get("can_change_username",0))),
         int(bool(permissions.get("can_change_password",0))),
         int(bool(permissions.get("can_manage_fees",0))),
         int(bool(permissions.get("can_manage_attendance",0))),
         int(bool(permissions.get("can_manage_results",0))),
         int(bool(permissions.get("can_manage_students",0))),
         int(bool(permissions.get("can_manage_classes",0))),
         int(bool(permissions.get("can_manage_accounts",0))),
         int(bool(permissions.get("can_view_dashboard",1))),
         now()))
    return True, "Account created."

# ---------------- PROFESSIONAL FEE HELPERS ----------------
# Fee Management is deliberately cycle-based:
# Monthly  -> one independent record per month (YYYY-MM)
# Semester -> one independent record per semester (YYYY-S1 / YYYY-S2)
# Yearly   -> one independent record per year (YYYY)
#
# A previous cycle is NEVER merged into the next cycle. Payments stay attached
# to their own fee record, so old balances/history remain visible separately.

def _money(value):
    """Safely convert old/new fee values to a number without crashing on legacy text."""
    if value is None or value == "":
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def fee_effective_due(row):
    amount = _money(row.get("Amount Due", 0))
    discount = _money(row.get("Discount", 0))
    late_fee = _money(row.get("Late Fee", 0))
    return max(0.0, amount - discount + late_fee)


def fee_status(due, paid, due_date=None):
    due = _money(due)
    paid = _money(paid)
    balance = max(0.0, due - paid)
    if balance <= 0.005:
        return "Paid"
    if paid > 0:
        if due_date and str(due_date) < str(date.today()):
            return "Partially Paid / Overdue"
        return "Partially Paid"
    if due_date and str(due_date) < str(date.today()):
        return "Overdue"
    return "Unpaid"


def fee_cycle_info(fee_type, fee_key, period_label=None, due_date=None):
    """Return stable academic-year/cycle information for one fee record."""
    fee_type = fee_type or "Monthly"
    key = str(fee_key or "")
    label = period_label or key

    try:
        if fee_type == "Monthly":
            d = datetime.strptime(key[:7], "%Y-%m").date()
            return str(d.year), d.month, d.strftime("%B %Y")

        if fee_type == "Semester":
            if "-S" in key:
                year_text, sem_text = key.split("-S", 1)
                year, sem = int(year_text), int(sem_text)
            else:
                d = datetime.strptime(str(due_date), "%Y-%m-%d").date()
                year, sem = d.year, (1 if d.month <= 6 else 2)
            return str(year), sem, f"Semester {'Spring' if sem == 1 else 'Fall'} {year}"

        if fee_type == "Yearly":
            year = int(key[:4])
            return str(year), 1, f"Academic Year {year}"

    except (TypeError, ValueError):
        pass

    # Legacy/custom fallback.
    try:
        d = datetime.strptime(str(due_date), "%Y-%m-%d").date()
        return str(d.year), 1, label
    except (TypeError, ValueError):
        return str(date.today().year), 1, label


def fee_key_from_parts(fee_type, year, cycle):
    if fee_type == "Monthly":
        return f"{int(year):04d}-{int(cycle):02d}"
    if fee_type == "Semester":
        return f"{int(year)}-S{int(cycle)}"
    if fee_type == "Yearly":
        return f"{int(year)}"
    return f"CUSTOM-{int(year)}-{int(cycle)}"


def fee_label_from_parts(fee_type, year, cycle):
    year = int(year)
    cycle = int(cycle)
    if fee_type == "Monthly":
        return date(year, cycle, 1).strftime("%B %Y")
    if fee_type == "Semester":
        return f"Semester {'Spring' if cycle == 1 else 'Fall'} {year}"
    if fee_type == "Yearly":
        return f"Academic Year {year}"
    return f"Custom Period {cycle} {year}"


def fee_due_date(fee_type, year, cycle):
    year = int(year)
    cycle = int(cycle)
    if fee_type == "Monthly":
        return date(year, cycle, 10)
    if fee_type == "Semester":
        return date(year, 1 if cycle == 1 else 7, 10)
    if fee_type == "Yearly":
        return date(year, 1, 10)
    return date(year, 1, 10)


def fee_period_sort_key(fee_type, fee_key):
    try:
        if fee_type == "Monthly":
            d = datetime.strptime(str(fee_key)[:7], "%Y-%m").date()
            return d.year * 100 + d.month
        if fee_type == "Semester":
            y, s = str(fee_key).split("-S", 1)
            return int(y) * 10 + int(s)
        if fee_type == "Yearly":
            return int(str(fee_key)[:4]) * 10
    except (TypeError, ValueError):
        pass
    return 0


def fee_records_df(
    sid,
    class_id=None,
    student_id=None,
    fee_type=None,
    academic_year=None,
    fee_key=None,
    only_outstanding=False,
):
    """Fetch fee records in one SQL query and keep each billing cycle separate."""
    sql = """SELECT f.id,s.id,s.name,s.roll_number,c.class_name,COALESCE(c.section,''),
                    COALESCE(f.fee_type,'Monthly'),
                    COALESCE(f.period_label,f.fee_month),
                    f.fee_month,f.academic_year,COALESCE(f.cycle_number,1),f.due_date,
                    f.amount_due,COALESCE(f.discount,0),COALESCE(f.late_fee,0),
                    COALESCE(pay.total_paid,0),
                    COALESCE(f.notes,'')
             FROM fee_records f
             JOIN students s ON s.id=f.student_id
             JOIN classes c ON c.id=s.class_id
             LEFT JOIN (
                 SELECT fee_id,SUM(amount) AS total_paid
                 FROM fee_payments
                 GROUP BY fee_id
             ) pay ON pay.fee_id=f.id
             WHERE f.school_id=?"""
    params = [sid]

    if class_id is not None:
        sql += " AND s.class_id=?"
        params.append(class_id)
    if student_id is not None:
        sql += " AND s.id=?"
        params.append(student_id)
    if fee_type and fee_type != "All":
        sql += " AND COALESCE(f.fee_type,'Monthly')=?"
        params.append(fee_type)
    if academic_year and academic_year != "All":
        sql += " AND COALESCE(f.academic_year,substr(f.fee_month,1,4))=?"
        params.append(str(academic_year))
    if fee_key:
        sql += " AND f.fee_month=?"
        params.append(str(fee_key))

    sql += """ ORDER BY c.class_name,COALESCE(c.section,''),s.roll_number,
                      COALESCE(f.academic_year,substr(f.fee_month,1,4)),f.due_date,f.id"""

    rows = execute(sql, tuple(params), fetch=True) or []
    data = []

    for r in rows:
        # 17 fields:
        # 0 fee id, 1 student id, 2 name, 3 roll, 4 class, 5 section,
        # 6 type, 7 period, 8 key, 9 academic year, 10 cycle,
        # 11 due, 12 base, 13 discount, 14 late, 15 paid, 16 notes.
        base = _money(r[12])
        discount = _money(r[13])
        late = _money(r[14])
        paid = _money(r[15])
        net = max(0.0, base - discount + late)
        remaining = max(0.0, net - paid)
        status = fee_status(net, paid, r[11])

        if only_outstanding and remaining <= 0.005:
            continue

        fee_type_value = r[6] or "Monthly"
        academic = str(r[9] or "")
        if not academic:
            academic = fee_cycle_info(fee_type_value, r[8], r[7], r[11])[0]

        data.append({
            "Fee ID": r[0],
            "Student ID": r[1],
            "Student": r[2],
            "Roll No": r[3],
            "Class": r[4],
            "Section": r[5],
            "Fee Type": fee_type_value,
            "Period": r[7],
            "Fee Key": r[8],
            "Academic Year": academic,
            "Cycle": int(r[10] or 1),
            "Due Date": r[11],
            "Base Fee": round(base, 2),
            "Discount": round(discount, 2),
            "Late Fee": round(late, 2),
            "Net Payable": round(net, 2),
            "Paid": round(paid, 2),
            "Remaining": round(remaining, 2),
            "Status": status,
            "Notes": r[16],
        })

    df = pd.DataFrame(data)
    if not df.empty:
        df["_sort"] = [
            fee_period_sort_key(str(t), k)
            for t, k in zip(df["Fee Type"], df["Fee Key"])
        ]
        df = df.sort_values(
            ["Class", "Section", "Roll No", "Fee Type", "_sort", "Fee ID"]
        ).drop(columns=["_sort"]).reset_index(drop=True)
    return df


def fee_summary_for_student(student_id):
    school_row = one("SELECT school_id FROM students WHERE id=?", (student_id,))
    if not school_row:
        return {
            "total": 0.0, "paid": 0.0, "remaining": 0.0,
            "cycles": 0, "outstanding_cycles": 0, "overdue_cycles": 0
        }

    df = fee_records_df(school_row[0], student_id=student_id)
    if df.empty:
        return {
            "total": 0.0, "paid": 0.0, "remaining": 0.0,
            "cycles": 0, "outstanding_cycles": 0, "overdue_cycles": 0
        }

    return {
        "total": float(df["Net Payable"].sum()),
        "paid": float(df["Paid"].sum()),
        "remaining": float(df["Remaining"].sum()),
        "cycles": len(df),
        "outstanding_cycles": int((df["Remaining"] > 0.005).sum()),
        "overdue_cycles": int(df["Status"].astype(str).str.contains("Overdue").sum()),
    }


def fee_year_options(sid, fee_type=None, class_id=None):
    """Only show years actually used by fee records, plus current/next year."""
    sql = """SELECT DISTINCT COALESCE(f.academic_year,substr(f.fee_month,1,4))
             FROM fee_records f
             JOIN students s ON s.id=f.student_id
             WHERE f.school_id=?"""
    params = [sid]
    if fee_type and fee_type != "All":
        sql += " AND COALESCE(f.fee_type,'Monthly')=?"
        params.append(fee_type)
    if class_id is not None:
        sql += " AND s.class_id=?"
        params.append(class_id)

    rows = execute(sql, tuple(params), fetch=True) or []
    years = {str(r[0]) for r in rows if r[0]}
    years.update({str(date.today().year), str(date.today().year + 1)})
    return sorted(years, reverse=True)


def save_fee_record(
    sid, student_id, fee_type, period_label, fee_key,
    due_date, amount, discount, late_fee, notes, actor_id,
    cycle_number=None
):
    """Create/update exactly one independent billing cycle."""
    fee_type = fee_type or "Monthly"
    academic_year, inferred_cycle, clean_label = fee_cycle_info(
        fee_type, fee_key, period_label, due_date
    )
    cycle_number = int(cycle_number or inferred_cycle)
    period_label = (period_label or clean_label).strip()

    existing = one(
        "SELECT id FROM fee_records WHERE student_id=? AND fee_month=?",
        (student_id, fee_key)
    )

    if existing:
        execute(
            """UPDATE fee_records SET fee_type=?,period_label=?,academic_year=?,
                       cycle_number=?,due_date=?,amount_due=?,discount=?,late_fee=?,
                       notes=?,updated_at=?
               WHERE id=? AND school_id=?""",
            (
                fee_type, period_label, academic_year, cycle_number, str(due_date),
                float(amount), float(discount), float(late_fee), notes, now(),
                existing[0], sid
            )
        )
        fid = existing[0]
        action = "UPDATE_FEE_RECORD"
    else:
        execute(
            """INSERT INTO fee_records
               (school_id,student_id,fee_month,fee_type,period_label,period_start,
                period_end,academic_year,cycle_number,due_date,amount_due,discount,
                late_fee,notes,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sid, student_id, fee_key, fee_type, period_label, None, None,
                academic_year, cycle_number, str(due_date), float(amount),
                float(discount), float(late_fee), notes, now(), now()
            )
        )
        fid = one(
            "SELECT id FROM fee_records WHERE student_id=? AND fee_month=?",
            (student_id, fee_key)
        )[0]
        action = "CREATE_FEE_RECORD"

    log(
        actor_id, action,
        f"student={student_id},fee={fee_key},type={fee_type},"
        f"year={academic_year},cycle={cycle_number},amount={amount}"
    )
    return fid


def fee_cycle_sequence(fee_type, start_date, count):
    """Generate only the three supported billing cycles."""
    out = []
    if fee_type == "Monthly":
        for i in range(int(count)):
            total_month = start_date.year * 12 + (start_date.month - 1) + i
            year = total_month // 12
            month = total_month % 12 + 1
            key = fee_key_from_parts("Monthly", year, month)
            out.append(
                (key, fee_label_from_parts("Monthly", year, month),
                 fee_due_date("Monthly", year, month), year, month)
            )

    elif fee_type == "Semester":
        first_sem = 1 if start_date.month <= 6 else 2
        for i in range(int(count)):
            absolute = (start_date.year * 2) + (first_sem - 1) + i
            year = absolute // 2
            sem = absolute % 2 + 1
            key = fee_key_from_parts("Semester", year, sem)
            out.append(
                (key, fee_label_from_parts("Semester", year, sem),
                 fee_due_date("Semester", year, sem), year, sem)
            )

    elif fee_type == "Yearly":
        for i in range(int(count)):
            year = start_date.year + i
            key = fee_key_from_parts("Yearly", year, 1)
            out.append(
                (key, fee_label_from_parts("Yearly", year, 1),
                 fee_due_date("Yearly", year, 1), year, 1)
            )

    return out


def generate_class_fee_schedule(
    sid, class_id, fee_type, amount, discount, late_fee,
    start_date, count, actor_id, notes=""
):
    """Create missing fee cycles for every active student in one class.

    Existing cycles are left untouched, including paid/partially-paid history.
    This is what prevents one year/semester/month from being mixed with another.
    """
    students = execute(
        """SELECT id FROM students
           WHERE school_id=? AND class_id=? AND active=1
           ORDER BY roll_number""",
        (sid, class_id), fetch=True
    ) or []

    cycles = fee_cycle_sequence(fee_type, start_date, count)
    if not students or not cycles:
        return 0, 0, len(students), len(cycles)

    created = 0
    existing = 0

    # Keep each student's history separate. INSERT only missing cycles.
    for student_row in students:
        student_id = int(student_row[0])
        for key, label, due, year, cycle in cycles:
            found = one(
                "SELECT id FROM fee_records WHERE student_id=? AND fee_month=?",
                (student_id, key)
            )
            if found:
                existing += 1
                continue
            save_fee_record(
                sid, student_id, fee_type, label, key, due,
                amount, discount, late_fee, notes, actor_id, cycle
            )
            created += 1

    return created, existing, len(students), len(cycles)


def ensure_next_fee_cycle(student_id):
    """Create the next cycle after the newest cycle when it does not exist.

    This does NOT require old cycles to be fully paid. Therefore a previous
    outstanding balance can remain visible while the next month/semester/year
    is also shown as its own independent fee record.
    """
    latest = one(
        """SELECT id,school_id,fee_type,period_label,fee_month,due_date,
                  amount_due,COALESCE(discount,0),COALESCE(late_fee,0),
                  COALESCE(notes,'')
           FROM fee_records
           WHERE student_id=? AND COALESCE(fee_type,'Monthly') IN ('Monthly','Semester','Yearly')
           ORDER BY id DESC LIMIT 1""",
        (int(student_id),)
    )
    if not latest:
        return False

    _, sid, fee_type, period_label, fee_key, due_date, amount, discount, late_fee, notes = latest
    fee_type = fee_type or "Monthly"

    try:
        if fee_type == "Monthly":
            base = datetime.strptime(str(fee_key)[:7], "%Y-%m").date()
            total_month = base.year * 12 + base.month
            next_year = total_month // 12
            next_month = total_month % 12 + 1
            next_key = fee_key_from_parts("Monthly", next_year, next_month)
            next_label = fee_label_from_parts("Monthly", next_year, next_month)
            next_due = fee_due_date("Monthly", next_year, next_month)
            cycle = next_month

        elif fee_type == "Semester":
            y, s = str(fee_key).split("-S", 1)
            year, sem = int(y), int(s)
            absolute = year * 2 + sem
            next_year = absolute // 2
            next_sem = absolute % 2 + 1
            next_key = fee_key_from_parts("Semester", next_year, next_sem)
            next_label = fee_label_from_parts("Semester", next_year, next_sem)
            next_due = fee_due_date("Semester", next_year, next_sem)
            cycle = next_sem
            next_year = next_year

        elif fee_type == "Yearly":
            year = int(str(fee_key)[:4])
            next_year = year + 1
            next_key = fee_key_from_parts("Yearly", next_year, 1)
            next_label = fee_label_from_parts("Yearly", next_year, 1)
            next_due = fee_due_date("Yearly", next_year, 1)
            cycle = 1

        else:
            return False

    except (TypeError, ValueError):
        return False

    if one(
        "SELECT id FROM fee_records WHERE student_id=? AND fee_month=?",
        (int(student_id), next_key)
    ):
        return False

    save_fee_record(
        int(sid), int(student_id), fee_type, next_label, next_key, next_due,
        _money(amount), _money(discount), _money(late_fee), notes, 0, cycle
    )
    return True


def detailed_fee_class_df(sid, class_id, fee_type, academic_year=None, fee_key=None):
    """Compact class report used by the Fee Management page."""
    return fee_records_df(
        sid, class_id=class_id, fee_type=fee_type,
        academic_year=academic_year, fee_key=fee_key
    )



def next_fee_cycle_parts(fee_type, year, cycle):
    """Return the next independent billing cycle without changing the current one."""
    year = int(year)
    cycle = int(cycle)
    if fee_type == "Monthly":
        absolute = year * 12 + cycle
        next_year = absolute // 12
        next_month = absolute % 12 + 1
        return next_year, next_month
    if fee_type == "Semester":
        absolute = year * 2 + cycle
        next_year = absolute // 2
        next_semester = absolute % 2 + 1
        return next_year, next_semester
    if fee_type == "Yearly":
        return year + 1, 1
    return None, None


def fee_payment_total(fee_id):
    row = one(
        "SELECT COALESCE(SUM(amount),0) FROM fee_payments WHERE fee_id=?",
        (int(fee_id),)
    )
    return _money(row[0] if row else 0)



# ---------------- AUTH ----------------
def authenticate(u, p):
    x = one(
        """SELECT id,username,password,name,role,school_id,student_id,active,can_view_fees,
                  can_change_username,can_change_password,can_manage_fees,can_manage_attendance,
                  can_manage_results,can_manage_students,can_manage_classes,can_manage_accounts,
                  can_view_dashboard
           FROM users WHERE username=?""",
        (u.strip(),))
    if not x or x[7] != 1 or not verify_password(p, x[2]): return None
    if x[4] != "admin" and not school_active(x[5]): return "SUSPENDED"
    return {"id": x[0], "username": x[1], "name": x[3], "role": x[4], "school_id": x[5], "student_id": x[6],
            "can_view_fees": x[8], "can_change_username": x[9], "can_change_password": x[10],
            "can_manage_fees": x[11], "can_manage_attendance": x[12], "can_manage_results": x[13],
            "can_manage_students": x[14], "can_manage_classes": x[15], "can_manage_accounts": x[16],
            "can_view_dashboard": x[17]}


if "logged_in" not in st.session_state: st.session_state.logged_in = False
if "user" not in st.session_state: st.session_state.user = None

# ---------------- LOGIN + PUBLIC PORTAL ----------------
if not st.session_state.logged_in:
    st.title("🎓 Educational Institution Management System")
    st.caption("Multi-institution academic, attendance and fee management • Optimized for concurrent use")
    a, b, c = st.columns([1, 2, 1])
    with b:
        u = st.text_input("Username");
        p = st.text_input("Password", type="password")
        if st.button("Login", type="primary", use_container_width=True):
            a1 = authenticate(u, p)
            if a1 is None:
                st.error("Invalid username or password.")
            elif a1 == "SUSPENDED":
                st.error("School is suspended or subscription has expired.")
            else:
                st.session_state.logged_in = True; st.session_state.user = a1; st.rerun()
        st.info("First login: admin / Admin@123 — change it from Admin Security.")
    st.divider();
    st.header("🎓 Public Result Portal")
    st.caption("School Code + Class + Section + Roll Number are required, so identical roll numbers cannot mismatch.")
    c1, c2, c3, c4 = st.columns(4)
    pc = c1.text_input("School Code");
    pcl = c2.text_input("Class Name");
    ps = c3.text_input("Section");
    pr = c4.text_input("Roll Number")
    if st.button("🔍 View Result", key="public_result"):
        sch = one("SELECT id,name FROM schools WHERE code=?", (pc.strip().upper(),))
        if not sch or not school_active(sch[0]):
            st.error("School not found or unavailable.")
        else:
            stu = one(
                """SELECT s.id FROM students s JOIN classes c ON s.class_id=c.id WHERE s.school_id=? AND s.roll_number=? AND c.class_name=? AND COALESCE(c.section,'')=? AND s.active=1""",
                (sch[0], pr.strip(), pcl.strip(), ps.strip()))
            if not stu:
                st.error("Student not found. Check School Code, Class, Section and Roll Number.")
            else:
                r = student_result(stu[0]);
                st.success(f"Result found for {r[0][1]}");
                st.dataframe(r[1], use_container_width=True, hide_index=True)
                x1, x2, x3, x4 = st.columns(4);
                x1.metric("Total", f"{r[2]:g}");
                x2.metric("Percentage", f"{r[3]:.2f}%");
                x3.metric("Grade", r[4]);
                x4.metric("Result", r[5])
                pb = pdf_bytes(stu[0]);
                if pb: st.download_button("📄 Download Result Card PDF", pb, "result_card.pdf", "application/pdf")
    st.stop()

user = st.session_state.user
st.sidebar.title("🎓 Educational Institution");
st.sidebar.write(f"**{user['name']}**");
st.sidebar.caption(user['role'].upper())
if user["role"] != "admin":
    sch = one("SELECT name,code,subscription_expiry FROM schools WHERE id=?", (user["school_id"],))
    if sch: st.sidebar.info(f"🏫 {sch[0]}\n\nCode: {sch[1]}\n\nExpiry: {sch[2]}")
if st.sidebar.button("🚪 Logout",
                     use_container_width=True): st.session_state.logged_in = False;st.session_state.user = None;st.rerun()

# ---------------- ADMIN ----------------
if user["role"] == "admin":
    st.title("👑 Super Admin Control Panel")
    schools = execute("SELECT id,name,code,status,subscription_start,subscription_expiry FROM schools ORDER BY id DESC",
                      fetch=True) or []
    m1, m2, m3, m4, m5 = st.columns(5);
    m1.metric("Schools", len(schools));
    m2.metric("Active", sum(s[3] == "ACTIVE" for s in schools));
    m3.metric("Teachers", one("SELECT COUNT(*) FROM users WHERE role='teacher'")[0]);
    m4.metric("Principals", one("SELECT COUNT(*) FROM users WHERE role='principal'")[0]);
    m5.metric("Students", one("SELECT COUNT(*) FROM students")[0])
    opt = st.sidebar.radio("Admin Menu", ["Dashboard", "Add Institution", "Manage Institutions", "Manage Accounts",
                                          "Account Permissions", "Security & Account Control", "Audit Logs", "Admin Security"])
    if opt == "Dashboard":
        st.header("📊 Platform Overview")
        if schools:
            overview = []
            for s in schools:
                stats = institution_statistics(s[0])
                overview.append({
                    "Institution": s[1], "Code": s[2], "Status": s[3],
                    "Teachers": stats[0], "Principals": stats[1], "Management": stats[2],
                    "Parents": stats[3], "Students": stats[4], "Classes": stats[5],
                    "Subscription Start": s[4], "Subscription Expiry": s[5]
                })
            odf = pd.DataFrame(overview)
            st.dataframe(odf, width='stretch', hide_index=True)

            labels={f"{s[1]} | {s[3]} | {s[2]}":s for s in schools}
            chosen=labels[st.selectbox("View separate institution details",list(labels))]
            sid2=chosen[0]
            a,b,c,d,e,f=st.columns(6)
            vals=institution_statistics(sid2)
            a.metric("Teachers",vals[0]); b.metric("Principals",vals[1]); c.metric("Management",vals[2])
            d.metric("Parents",vals[3]); e.metric("Students",vals[4]); f.metric("Classes",vals[5])

            classes2=execute("""SELECT c.class_name,COALESCE(c.section,''),
                                      COALESCE(u.name,'Not assigned'),
                                      (SELECT COUNT(*) FROM students s WHERE s.class_id=c.id)
                               FROM classes c LEFT JOIN users u ON u.id=c.incharge_teacher_id
                               WHERE c.school_id=? ORDER BY c.class_name,c.section""",
                             (sid2,),fetch=True) or []
            st.subheader("Class Details")
            st.dataframe(pd.DataFrame(classes2,columns=["Class","Section","In-Charge Teacher","Students"]),
                         use_container_width=True,hide_index=True)

            perf=[]
            for cl in execute("SELECT id,class_name,section FROM classes WHERE school_id=?",(sid2,),fetch=True) or []:
                dr=detailed_results_csv(sid2,cl[0])
                if not dr.empty:
                    perf.append({"Class":cl[1],"Section":cl[2],"Average %":round(float(pd.to_numeric(dr["Percentage"], errors="coerce").mean()),2),
                                  "Students":len(dr)})
            if perf:
                pdf=pd.DataFrame(perf).sort_values("Average %",ascending=False)
                st.subheader("Class Performance")
                st.dataframe(pdf,use_container_width=True,hide_index=True)
                st.success(f"Best-performing class: {pdf.iloc[0]['Class']} - {pdf.iloc[0]['Section']} ({pdf.iloc[0]['Average %']}%)")
        else:
            st.info("No institutions have been created yet.")

    elif opt == "Add Institution":
        st.header("🏫 Add Educational Institution")
        name = st.text_input("Institution Name");
        institution_type = st.selectbox("Institution Type", ["School", "College", "University"])
        days = st.number_input("Subscription Days", min_value=1, value=30)
        if st.button("Create School", type="primary"):
            if MAX_SCHOOLS is not None and len(schools) >= MAX_SCHOOLS:
                st.error(f"Platform school limit reached ({MAX_SCHOOLS}).")
            elif not name.strip():
                st.error("Enter school name.")
            else:
                code = school_code();
                start = date.today();
                exp = start + timedelta(days=int(days));
                execute(
                    "INSERT INTO schools(name,code,institution_type,status,subscription_start,subscription_expiry,created_at) VALUES(?,?,?,?,?,?,?)",
                    (name.strip(), code, institution_type, "ACTIVE", str(start), str(exp), now()));
                log(user["id"], "CREATE_INSTITUTION", f"{institution_type}:{name} {code}");
                st.success(f"Created. School Code: {code} | Expiry: {exp}")
    elif opt == "Manage Institutions":
        st.header("⚙️ Manage Educational Institutions")
        if not schools:
            st.info("No schools.")
        else:
            labels = {f"{s[1]} ({s[3]}) [{s[2]}]": s for s in schools};
            sel = st.selectbox("School", list(labels));
            s = labels[sel]
            a, b = st.columns(2)
            with a:
                if s[3] == "ACTIVE":
                    if st.button("🔴 Suspend School"):
                        suspend_school(s[0],user["id"]); st.rerun()
                else:
                    if st.button("🟢 Activate School"):
                        activate_school(s[0],user["id"]); st.rerun()
            with b:
                d = st.number_input("Extension Days", min_value=1, value=30, key="ext")
                if st.button("📅 Extend Subscription"):
                    # Get expiry date safely
                    expiry_str = s[6] if len(s) > 6 else None
                    if expiry_str:
                        try:
                            expiry_date = datetime.strptime(expiry_str, '%Y-%m-%d').date()
                            base = max(date.today(), expiry_date)
                        except ValueError:
                            base = date.today()
                    else:
                        base = date.today()
                    ne = base + timedelta(days=int(d));
                    execute("UPDATE schools SET subscription_expiry=?,status='ACTIVE' WHERE id=?", (str(ne), s[0]));
                    log(user["id"], "EXTEND_SUBSCRIPTION", str(ne));
                    st.rerun()
    elif opt == "Manage Accounts":
        st.header("👥 Admin Account Management")
        st.info("Super Admin creates teacher, principal and management accounts. Parent accounts may also be created by authorized school staff from their Parent Accounts area.")
        if not schools:
            st.info("Create an institution first.")
        else:
            labels={f"{s[1]} ({s[3]}) [{s[2]}]":s[0] for s in schools}
            sid=labels[st.selectbox("Institution",list(labels))]
            role=st.selectbox("Account Type",["principal","teacher","management","parent"])
            name=st.text_input("Name")
            un=st.text_input("Username")
            pw=st.text_input("Password",type="password")
            p_student=None
            if role=="parent":
                sts=execute("SELECT id,name,roll_number FROM students WHERE school_id=? AND active=1 ORDER BY name",(sid,),fetch=True) or []
                if sts:
                    pmap={f"{x[1]} (Roll {x[2]})":x[0] for x in sts}
                    p_student=pmap[st.selectbox("Link Parent To Student",list(pmap))]
                else:
                    st.warning("Add a student before creating a parent account.")
            if st.button("Create Account",type="primary"):
                if not name.strip() or not un.strip() or len(pw)<6:
                    st.error("Enter name, username and password (6+ characters).")
                elif role=="parent" and p_student is None:
                    st.error("Select a student for the parent account.")
                else:
                    ok,msg=create_user(un,pw,name,role,school_id=sid,student_id=p_student,
                                       permissions={"can_view_fees":role=="principal"})
                    if ok:
                        if role=="parent" and p_student:
                            pu=one("SELECT id FROM users WHERE username=?",(un.strip(),))[0]
                            execute("INSERT OR IGNORE INTO parent_student(parent_user_id,student_id) VALUES(?,?)",(pu,p_student))
                        log(user["id"],"CREATE_ACCOUNT",f"{role}:{un.strip()}")
                        st.success(msg); st.rerun()
                    else: st.error(msg)

            st.subheader("Existing Accounts")
            acc=execute("""SELECT id,name,username,role,active,can_view_fees,
                                  can_change_username,can_change_password
                           FROM users WHERE school_id=? ORDER BY role,name""",(sid,),fetch=True) or []
            st.dataframe(pd.DataFrame(acc,columns=["ID","Name","Username","Role","Active","Fee Access","Username Change","Password Change"]),
                         use_container_width=True,hide_index=True)
            if acc:
                amap={f"{x[0]} - {x[1]} ({x[3]})":x for x in acc}
                chosen=amap[st.selectbox("Select account",list(amap))]
                if chosen[4]==1:
                    if st.button("🔴 Suspend Account"):
                        suspend_account(chosen[0],user["id"])
                        log(user["id"],"ADMIN_ACCOUNT_SUSPEND_FROM_MANAGE",f"{chosen[0]}:{chosen[2]}")
                        st.rerun()
                else:
                    if st.button("🟢 Activate Account"):
                        activate_account(chosen[0],user["id"])
                        log(user["id"],"ADMIN_ACCOUNT_ACTIVATE_FROM_MANAGE",f"{chosen[0]}:{chosen[2]}")
                        st.rerun()
                if st.button("🔑 Reset Password"):
                    temp=secrets.token_urlsafe(8)
                    execute("UPDATE users SET password=? WHERE id=?",(hash_password(temp),chosen[0]))
                    log(user["id"],"RESET_PASSWORD",str(chosen[0]))
                    st.success(f"Temporary password: {temp}")

    elif opt == "Account Permissions":
        st.header("🔐 Admin-Controlled Account Permissions")
        st.caption("Only the Super Admin can grant or revoke each account's permission to change its own username and/or password. Every teacher, principal and management account is controlled separately.")
        st.info("Disabling an account prevents login. Credential-change permissions affect only the selected account.")
        acc=execute("""SELECT id,name,username,role,active,can_change_username,can_change_password,
                              can_view_fees,can_manage_fees,can_manage_attendance,can_manage_results,
                              can_manage_students,can_manage_classes,can_manage_accounts,can_view_dashboard
                       FROM users
                       WHERE role IN ('principal','teacher','management','parent','student')
                       ORDER BY CASE role
                           WHEN 'principal' THEN 1
                           WHEN 'teacher' THEN 2
                           WHEN 'management' THEN 3
                           WHEN 'parent' THEN 4
                           WHEN 'student' THEN 5
                           ELSE 6 END, name""",fetch=True) or []
        if not acc:
            st.info("No non-admin accounts.")
        else:
            amap={f"{x[3].title()} | {x[1]} | {x[2]}":x for x in acc}
            chosen=amap[st.selectbox("Account",list(amap))]
            st.write(f"Selected: **{chosen[1]}** — {chosen[3]} — `{chosen[2]}`")
            st.subheader("🔑 Login Credential Privacy")
            st.caption("Turn these on only when this specific account should be allowed to change its own login credentials.")
            c1,c2=st.columns(2)
            with c1:
                cu=st.checkbox("Allow username change",value=bool(chosen[5]))
                cp=st.checkbox("Allow password change",value=bool(chosen[6]))
                vd=st.checkbox("Allow dashboard",value=bool(chosen[14]))
                vf=st.checkbox("View fees",value=bool(chosen[7]))
                mf=st.checkbox("Manage fees",value=bool(chosen[8]))
            with c2:
                ma=st.checkbox("Manage attendance",value=bool(chosen[9]))
                mr=st.checkbox("Manage results",value=bool(chosen[10]))
                ms=st.checkbox("Manage students",value=bool(chosen[11]))
                mc=st.checkbox("Manage classes",value=bool(chosen[12]))
                mac=st.checkbox("Manage accounts",value=bool(chosen[13]))
            if st.button("Save Permissions",type="primary"):
                execute("""UPDATE users SET can_change_username=?,can_change_password=?,can_view_dashboard=?,
                           can_view_fees=?,can_manage_fees=?,can_manage_attendance=?,can_manage_results=?,
                           can_manage_students=?,can_manage_classes=?,can_manage_accounts=? WHERE id=?""",
                        (int(cu),int(cp),int(vd),int(vf),int(mf),int(ma),int(mr),int(ms),int(mc),int(mac),chosen[0]))
                log(user["id"],"UPDATE_ACCOUNT_PERMISSIONS",str(chosen[0]))
                st.success("Permissions updated."); st.rerun()

    elif opt == "Security & Account Control":
        st.header("🛡️ Security & Account Control")
        st.caption("Super Admin can suspend an entire institution or any individual principal, teacher, management, parent or student account. Suspension never deletes academic or financial data.")
        st.subheader("🏫 Institution-wide Control")
        sec_schools=execute("SELECT id,name,code,status,institution_type FROM schools ORDER BY name",fetch=True) or []
        if sec_schools:
            smap={f"{x[1]} — {x[4]} — {x[3]} — {x[2]}":x for x in sec_schools}
            ss=smap[st.selectbox("Institution",list(smap),key="security_school")]
            a,b=st.columns(2)
            with a:
                if ss[3]=="ACTIVE":
                    if st.button("🔴 Suspend Entire Institution",type="primary"):
                        suspend_school(ss[0],user["id"]); st.success("Institution and all its user accounts have been suspended."); st.rerun()
                else:
                    if st.button("🟢 Reactivate Institution",type="primary"):
                        activate_school(ss[0],user["id"]); st.success("Institution reactivated. Accounts individually suspended before the institution suspension remain suspended."); st.rerun()
            with b:
                counts=execute("""SELECT role,COUNT(*) FROM users WHERE school_id=? GROUP BY role ORDER BY role""",(ss[0],),fetch=True) or []
                st.dataframe(pd.DataFrame(counts,columns=["Role","Accounts"]),use_container_width=True,hide_index=True)
        st.divider()
        st.subheader("👤 Individual Account Control")
        accounts=execute("""SELECT u.id,u.name,u.username,u.role,u.active,u.school_forced_suspended,
                                   s.name,s.code,s.status
                            FROM users u LEFT JOIN schools s ON s.id=u.school_id
                            WHERE u.role IN ('principal','teacher','management','parent','student')
                            ORDER BY s.name,u.role,u.name""",fetch=True) or []
        if accounts:
            amap={f"{x[6] or 'No Institution'} | {x[3].title()} | {x[1]} | {x[2]}":x for x in accounts}
            ac=amap[st.selectbox("Account",list(amap),key="security_account")]
            st.write(f"**{ac[1]}** — {ac[3].title()} — Institution: **{ac[6] or 'N/A'}** — Status: **{'Active' if ac[4] else 'Suspended'}**")
            if ac[4]:
                if st.button("🔴 Suspend This Account"):
                    suspend_account(ac[0],user["id"]); st.success("Account suspended."); st.rerun()
            else:
                if ac[5]:
                    st.info("This account is suspended because its institution is suspended. Reactivate the institution to restore it.")
                elif st.button("🟢 Reactivate This Account"):
                    activate_account(ac[0],user["id"]); st.success("Account reactivated."); st.rerun()
        else:
            st.info("No school/institution accounts exist yet.")

    elif opt == "Audit Logs":
        rows = execute(
            "SELECT id,COALESCE((SELECT username FROM users WHERE users.id=audit_logs.user_id),'System'),action,details,created_at FROM audit_logs ORDER BY id DESC LIMIT 1000",
            fetch=True) or []
        st.header("📜 Audit Logs");
        st.dataframe(pd.DataFrame(rows, columns=["ID", "User", "Action", "Details", "Date/Time"]),
                     use_container_width=True, hide_index=True)
    elif opt == "Admin Security":
        st.header("🔐 Admin Security");
        old = st.text_input("Current Password", type="password");
        new = st.text_input("New Password", type="password");
        con = st.text_input("Confirm New Password", type="password")
        if st.button("Change Password"):
            stored = one("SELECT password FROM users WHERE id=?", (user["id"],))[0]
            if not verify_password(old, stored):
                st.error("Current password is incorrect.")
            elif len(new) < 6 or new != con:
                st.error("Password must match and contain 6+ characters.")
            else:
                execute("UPDATE users SET password=? WHERE id=?", (hash_password(new), user["id"]));st.success(
                    "Password changed.")

# ---------------- SCHOOL ROLES ----------------
elif user["role"] in ("principal", "teacher", "management"):
    sid = user["school_id"];
    school = one("SELECT name,code,subscription_expiry FROM schools WHERE id=?", (sid,))
    if not school_active(sid): st.error("School suspended/expired."); st.stop()
    st.title(f"🏫 {school[0]}");
    st.caption(f"School Code: {school[1]}")
    can_fees = user["role"] == "principal" or bool(user.get("can_view_fees")) or bool(user.get("can_manage_fees"))
    if user["role"] == "principal":
        menu = ["Dashboard", "Classes", "Subjects", "Students", "Marks & Results",
                "Attendance", "Subject Attendance", "Teacher Attendance", "Timetable",
                "Search Student", "Fee Management", "Student Feedback",
                "Accounts & Permissions", "Notifications", "Institution Report", "My Account"]
    elif user["role"] == "management":
        menu = ["Dashboard"]
        if user.get("can_manage_classes"): menu += ["Classes"]
        if user.get("can_manage_results"): menu += ["Subjects", "Marks & Results"]
        if user.get("can_manage_students"): menu += ["Students"]
        if user.get("can_manage_attendance"): menu += ["Attendance", "Subject Attendance", "Teacher Attendance"]
        menu += ["Search Student"]
        if user.get("can_view_fees") or user.get("can_manage_fees"): menu += ["Fee Management"]
        menu += ["Student Feedback", "My Account"]
    else:
        menu = ["Dashboard", "Classes", "Subjects", "Students", "Marks & Results",
                "Attendance", "Subject Attendance", "Teacher Attendance", "Timetable",
                "Search Student", "Student Feedback", "My Account"]
        if can_fees: menu += ["Fee Management"]
        menu += ["Parent Accounts"]
    choice = st.sidebar.radio("School Menu", menu)
    if choice == "Dashboard":
        st.header("📊 School Dashboard")
        vals = [one("SELECT COUNT(*) FROM classes WHERE school_id=?", (sid,))[0],
                one("SELECT COUNT(*) FROM subjects WHERE school_id=?", (sid,))[0],
                one("SELECT COUNT(*) FROM students WHERE school_id=?", (sid,))[0],
                one("SELECT COUNT(*) FROM users WHERE school_id=? AND role='teacher'", (sid,))[0]]
        a, b, c, d = st.columns(4);
        a.metric("Classes", vals[0]);
        b.metric("Subjects", vals[1]);
        c.metric("Students", vals[2]);
        d.metric("Teachers", vals[3])
        st.info("Use the menu to manage academic records, attendance, timetable and fees.")
    elif choice == "Classes":
        st.header("📚 Classes & Sections");
        cn = st.text_input("Class Name");
        sec = st.text_input("Section")
        if st.button("Add Class"):
            if cn.strip() and not one(
                "SELECT id FROM classes WHERE school_id=? AND class_name=? AND COALESCE(section,'')=?",
                (sid, cn.strip(), sec.strip())):
                execute("INSERT INTO classes(school_id,class_name,section,created_at) VALUES(?,?,?,?)",
                        (sid, cn.strip(), sec.strip(), now()));st.success("Class added.");st.rerun()
            else:
                st.error("Class already exists or name is empty.")
        rows = execute(
            "SELECT id,class_name,section,created_at FROM classes WHERE school_id=? ORDER BY class_name,section",
            (sid,), True) or [];
        st.dataframe(pd.DataFrame(rows, columns=["ID", "Class", "Section", "Created"]), use_container_width=True,
                     hide_index=True)
    elif choice == "Subjects":
        st.header("📖 Subjects")
        st.info(
            "There is NO fixed passing mark. Teacher enters Maximum Marks and Passing Marks separately for every subject.")
        sn = st.text_input("Subject Name");
        maxs = st.text_input("Maximum / Total Marks", placeholder="Example: 100");
        passs = st.text_input("Passing Marks", placeholder="Example: 40")
        if st.button("Add Subject", type="primary"):
            try:
                mx = float(maxs);pm = float(passs)
            except:
                mx = pm = -1
            if not sn.strip() or mx <= 0 or pm < 0 or pm > mx:
                st.error(
                    "Enter valid subject name, total marks and passing marks. Passing marks cannot exceed total marks.")
            elif one("SELECT id FROM subjects WHERE school_id=? AND LOWER(subject_name)=LOWER(?)", (sid, sn.strip())):
                st.error("Subject already exists.")
            else:
                execute(
                    "INSERT INTO subjects(school_id,subject_name,max_marks,passing_marks,created_at) VALUES(?,?,?,?,?)",
                    (sid, sn.strip(), mx, pm, now()));st.success("Subject added with its own marks rule.");st.rerun()
        rows = execute(
            "SELECT id,subject_name,max_marks,passing_marks,created_at FROM subjects WHERE school_id=? ORDER BY subject_name",
            (sid,), True) or []
        st.dataframe(pd.DataFrame(rows, columns=["ID", "Subject", "Maximum Marks", "Passing Marks", "Created"]),
                     use_container_width=True, hide_index=True)
        if rows:
            st.subheader("Edit subject marks rules");
            mp = {f"{r[0]} - {r[1]}": r for r in rows};
            r = mp[st.selectbox("Subject", list(mp))];
            emx = st.text_input("New Maximum Marks", value=str(r[2]));
            epm = st.text_input("New Passing Marks", value="" if r[3] is None else str(r[3]))
            if st.button("Update Subject"):
                try:
                    mx = float(emx);pm = float(epm)
                except:
                    mx = pm = -1
                if mx <= 0 or pm < 0 or pm > mx:
                    st.error("Invalid marks.")
                else:
                    execute("UPDATE subjects SET max_marks=?,passing_marks=? WHERE id=? AND school_id=?",
                            (mx, pm, r[0], sid));st.success("Updated.");st.rerun()
    elif choice == "Students":
        st.header("👨‍🎓 Students");
        classes = execute("SELECT id,class_name,section FROM classes WHERE school_id=? ORDER BY class_name,section",
                          (sid,), True) or []
        if not classes:
            st.warning("Create a class first.")
        else:
            co = {f"{x[1]} - Section {x[2] or ''}": x[0] for x in classes};
            cid = co[st.selectbox("Class", list(co))];
            name = st.text_input("Student Name");
            roll = st.text_input("Roll Number");
            phone = st.text_input("Phone");
            email = st.text_input("Email")
            su = st.text_input("Student Username (optional)");
            sp = st.text_input("Student Password (optional)", type="password")
            if st.button("Add Student", type="primary"):
                if not name.strip() or not roll.strip():
                    st.error("Name and roll number required.")
                elif one("SELECT id FROM students WHERE school_id=? AND class_id=? AND roll_number=?",
                         (sid, cid, roll.strip())):
                    st.error("That roll number already exists in this class/section.")
                elif su.strip() and (len(sp) < 6 or one("SELECT id FROM users WHERE username=?", (su.strip(),))):
                    st.error("Student username must be unique and password must be 6+ characters.")
                else:
                    execute(
                        "INSERT INTO students(school_id,class_id,name,roll_number,phone,email,active,created_at) VALUES(?,?,?,?,?,?,1,?)",
                        (sid, cid, name.strip(), roll.strip(), phone.strip(), email.strip(), now()));
                    st.success("Student added.");
                    stu = one("SELECT id FROM students WHERE school_id=? AND class_id=? AND roll_number=?",
                              (sid, cid, roll.strip()))
                    if su.strip(): execute(
                        "INSERT INTO users(username,password,name,role,school_id,student_id,active,created_at) VALUES(?,?,?,?,?,?,1,?)",
                        (su.strip(), hash_password(sp), name.strip(), "student", sid, stu[0], now()))
                    st.rerun()
            rows = execute(
                "SELECT id,name,roll_number,phone,email,active FROM students WHERE school_id=? AND class_id=? ORDER BY roll_number",
                (sid, cid), True) or [];
            st.dataframe(pd.DataFrame(rows, columns=["ID", "Name", "Roll", "Phone", "Email", "Active"]),
                         use_container_width=True, hide_index=True)
            if rows and user["role"] in ("principal","teacher"):
                st.subheader("🗑️ Remove Student Who Has Left")
                delmap={f"{r[1]} | Roll {r[2]}":r for r in rows}
                ds=delmap[st.selectbox("Student to delete",list(delmap),key="delete_student")]
                confirm=st.checkbox("I confirm this student has left the institution and should be permanently deleted.",key="confirm_delete_student")
                if confirm and st.button("🗑️ Permanently Delete Student",key="delete_student_btn"):
                    execute("DELETE FROM students WHERE id=? AND school_id=?",(ds[0],sid))
                    log(user["id"],"DELETE_STUDENT",f"student={ds[0]};name={ds[1]}")
                    st.success("Student and linked account/records were deleted.")
                    st.rerun()
    elif choice == "Marks & Results":
        st.header("📝 Marks & Results")
        st.caption("Results are stored separately by academic year and class. Previous-year results remain available as history and do not mix with the student's new class.")
        classes=execute("SELECT id,class_name,section FROM classes WHERE school_id=? ORDER BY class_name,section",(sid,),True) or []
        subs=execute("SELECT id,subject_name,max_marks,passing_marks FROM subjects WHERE school_id=? ORDER BY subject_name",(sid,),True) or []
        if not classes or not subs:
            st.warning("Create classes and subjects first.")
        else:
            years=academic_year_options()
            academic_year=st.selectbox("Academic Year",years,index=years.index(current_academic_year()) if current_academic_year() in years else 1,key="result_year")
            co={f"{x[1]} - {x[2] or ''}":x for x in classes}
            selected_class=st.selectbox("Class / Section",list(co),key="result_class")
            cid=co[selected_class][0]
            so={f"{x[1]} (Max {x[2]}, Pass {x[3] if x[3] is not None else 'NOT SET'})":x for x in subs}
            sub=so[st.selectbox("Subject",list(so),key="result_subject")]
            if sub[3] is None: st.error("Set this subject's passing marks before entering final results.")
            sts=execute("SELECT id,name,roll_number FROM students WHERE school_id=? AND class_id=? AND active=1 ORDER BY roll_number",(sid,cid),True) or []
            for s in sts:
                old=one("SELECT marks FROM result_marks WHERE student_id=? AND subject_id=? AND academic_year=?",(s[0],sub[0],academic_year))
                val=st.number_input(f"{s[1]} (Roll {s[2]})",0.0,float(sub[2]),float(old[0]) if old else 0.0,key=f"mk{s[0]}_{sub[0]}_{academic_year}")
                if st.button(f"Save {s[1]}",key=f"save{s[0]}_{sub[0]}_{academic_year}"):
                    if old:
                        execute("UPDATE result_marks SET marks=?,updated_at=?,class_id=? WHERE id=?",(val,now(),cid,old[0]))
                    else:
                        execute("""INSERT INTO result_marks(student_id,subject_id,class_id,academic_year,marks,updated_at)
                                   VALUES(?,?,?,?,?,?)""",(s[0],sub[0],cid,academic_year,val,now()))
                    # Keep legacy marks current for compatibility with old reports.
                    if academic_year==current_academic_year():
                        legacy=one("SELECT id FROM marks WHERE student_id=? AND subject_id=?",(s[0],sub[0]))
                        if legacy: execute("UPDATE marks SET marks=?,updated_at=? WHERE id=?",(val,now(),legacy[0]))
                        else: execute("INSERT OR IGNORE INTO marks(student_id,subject_id,marks,updated_at) VALUES(?,?,?,?)",(s[0],sub[0],val,now()))
                    log(user["id"],"SAVE_RESULT",f"student={s[0]},subject={sub[0]},year={academic_year}")
                    st.success("Saved.")
            st.divider()
            st.subheader("Class Results")
            result=[]
            posdf=class_positions(sid,cid,academic_year)
            posmap={int(r["Student ID"]):int(r["Position"]) for _,r in posdf.iterrows()} if not posdf.empty else {}
            for s in sts:
                r=student_result(s[0],academic_year,cid)
                result.append({"Roll":s[2],"Student":s[1],"Total":round(r[2],2),"Percentage":round(r[3],2),
                                "Grade":r[4],"Result":r[5],"Position":posmap.get(s[0],"")})
            rdf=pd.DataFrame(result)
            st.dataframe(rdf,use_container_width=True,hide_index=True)
            st.subheader("🏆 Top 3 Positions — This Class / Section")
            top=top_three_positions_text(sid,cid,academic_year)
            if top:
                for pos,names in top:
                    st.success(f"{pos}{'st' if pos==1 else 'nd' if pos==2 else 'rd'} Position: {', '.join(names)}")
            else: st.info("No results available for positions yet.")
            st.subheader("🏆 Positions For All Classes — Separately")
            any_positions=False
            for acl in classes:
                ap=top_three_positions_text(sid,acl[0],academic_year)
                if ap:
                    any_positions=True
                    st.markdown(f"**{acl[1]} — Section {acl[2] or ''}**")
                    for pos,names in ap:
                        suffix="st" if pos==1 else "nd" if pos==2 else "rd"
                        st.write(f"{pos}{suffix} Position: {', '.join(names)}")
            if not any_positions:
                st.info("No class positions are available for this academic year yet.")
            xb=excel_bytes(rdf)
            if xb: st.download_button("⬇️ Download Results Excel",xb,"class_results.xlsx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            detailed_df=detailed_results_csv(sid,cid,academic_year)
            st.download_button("⬇️ Download Detailed Results CSV",detailed_df.to_csv(index=False).encode(),"class_results_detailed.csv","text/csv")
            if sts:
                chosen=st.selectbox("Result card student",[f"{s[2]} - {s[1]}" for s in sts],key="result_card_student")
                cs=sts[[f"{s[2]} - {s[1]}" for s in sts].index(chosen)]
                pb=pdf_bytes(cs[0])
                if pb: st.download_button("📄 Download PDF Result Card",pb,"result_card.pdf","application/pdf")
            st.divider()
            st.subheader("🎓 Promote Students To Next Class")
            st.caption("Promotion changes the student's current class only. Previous-year results remain stored under the previous academic year/class.")
            target_map={f"{x[1]} - {x[2] or ''}":x[0] for x in classes if x[0]!=cid}
            if target_map and sts:
                target=target_map[st.selectbox("Next Class / Section",list(target_map),key="promotion_target")]
                next_year=str(int(academic_year)+1) if academic_year.isdigit() else academic_year
                selected_students=st.multiselect("Students to promote", [f"{s[0]} | {s[1]} | Roll {s[2]}" for s in sts],default=[f"{s[0]} | {s[1]} | Roll {s[2]}" for s in sts],key="promote_students")
                confirm=st.checkbox("I confirm the selected students have completed this academic year.",key="confirm_promotion")
                if confirm and st.button("🎓 Promote Selected Students",type="primary",key="promote_btn"):
                    for label in selected_students:
                        stid=int(label.split(" | ",1)[0])
                        execute("""INSERT INTO student_promotions(student_id,school_id,from_class_id,to_class_id,academic_year,promoted_at,promoted_by)
                                   VALUES(?,?,?,?,?,?,?)""",(stid,sid,cid,target,academic_year,now(),user["id"]))
                        execute("UPDATE students SET class_id=? WHERE id=? AND school_id=?",(target,stid,sid))
                    log(user["id"],"PROMOTE_STUDENTS",f"from={cid};to={target};year={academic_year};count={len(selected_students)}")
                    st.success(f"{len(selected_students)} student(s) promoted to {next_year} / next class.")
                    st.rerun()
            else:
                st.info("Create another class/section before using promotion.")
            st.subheader("📚 Previous Class / Year Results")
            hist_classes=execute("""SELECT DISTINCT c.id,c.class_name,c.section,rm.academic_year
                                   FROM result_marks rm JOIN classes c ON c.id=rm.class_id
                                   WHERE c.school_id=? ORDER BY rm.academic_year DESC,c.class_name,c.section""",(sid,),True) or []
            if hist_classes:
                hmap={f"{x[1]} - {x[2] or ''} | Year {x[3]}":x for x in hist_classes}
                hc=hmap[st.selectbox("View a separate historical class/year",list(hmap),key="history_class")]
                hdf=detailed_results_csv(sid,hc[0],hc[3])
                st.dataframe(hdf,use_container_width=True,hide_index=True)
                st.download_button("⬇️ Download Historical Class Result CSV",hdf.to_csv(index=False).encode(),"historical_class_results.csv","text/csv",key="historical_results_csv")

    elif choice == "Attendance":
        st.header("📅 Attendance");
        classes = execute("SELECT id,class_name,section FROM classes WHERE school_id=?", (sid,), True) or []
        if classes:
            co = {f"{x[1]} - {x[2] or ''}": x[0] for x in classes};
            cid = co[st.selectbox("Class", list(co))];
            ad = st.date_input("Attendance Date", date.today());
            sts = execute(
                "SELECT id,name,roll_number FROM students WHERE school_id=? AND class_id=? AND active=1 ORDER BY roll_number",
                (sid, cid), True) or []
            for s in sts:
                old = one("SELECT status FROM attendance WHERE student_id=? AND attendance_date=?", (s[0], str(ad)));
                status = st.selectbox(f"{s[1]} (Roll {s[2]})", ["Present", "Absent", "Late", "Leave"],
                                      index=["Present", "Absent", "Late", "Leave"].index(old[0]) if old else 0,
                                      key=f"att{s[0]}")
                if st.button(f"Save {s[1]}", key=f"attb{s[0]}"):
                    if old:
                        execute("UPDATE attendance SET status=?,recorded_by=? WHERE student_id=? AND attendance_date=?",
                                (status, user["id"], s[0], str(ad)))
                    else:
                        execute(
                            "INSERT INTO attendance(school_id,student_id,attendance_date,status,recorded_by,created_at) VALUES(?,?,?,?,?,?)",
                            (sid, s[0], str(ad), status, user["id"], now()))
                    st.success("Saved.")
            att_csv=attendance_csv_df(sid,cid)
            st.subheader("⬇️ Attendance Export")
            if att_csv.empty:
                st.info("No attendance records available for this class yet.")
            else:
                st.dataframe(att_csv,use_container_width=True,hide_index=True)
                st.download_button("⬇️ Download Student Attendance CSV",att_csv.to_csv(index=False).encode(),
                                   "student_attendance.csv","text/csv",key="student_attendance_csv")
    elif choice == "Subject Attendance":
        st.header("📚 Subject-wise Student Attendance")
        classes = execute("SELECT id,class_name,section FROM classes WHERE school_id=? ORDER BY class_name,section",(sid,),fetch=True) or []
        subs = execute("SELECT id,subject_name FROM subjects WHERE school_id=? ORDER BY subject_name",(sid,),fetch=True) or []
        if not classes or not subs:
            st.warning("Create classes and subjects first.")
        else:
            cmap={f"{x[1]} - {x[2] or ''}":x[0] for x in classes}
            cid=cmap[st.selectbox("Class",list(cmap),key="sa_class")]
            smap={f"{x[1]}":x[0] for x in subs}
            subid=smap[st.selectbox("Subject",list(smap),key="sa_subject")]
            ad=st.date_input("Attendance Date",date.today(),key="sa_date")
            sts=execute("SELECT id,name,roll_number FROM students WHERE school_id=? AND class_id=? AND active=1 ORDER BY roll_number",
                        (sid,cid),fetch=True) or []
            for s in sts:
                old=one("""SELECT status FROM subject_attendance WHERE student_id=? AND subject_id=? AND attendance_date=?""",
                        (s[0],subid,str(ad)))
                opts=["Present","Absent","Late","Leave"]
                status=st.selectbox(f"{s[1]} (Roll {s[2]})",opts,index=opts.index(old[0]) if old else 0,
                                    key=f"sa_{s[0]}_{subid}")
                remarks=st.text_input(f"Remarks - {s[1]}",key=f"sar_{s[0]}_{subid}")
                if st.button(f"Save {s[1]}",key=f"sab_{s[0]}_{subid}"):
                    if old:
                        execute("""UPDATE subject_attendance SET status=?,remarks=?,recorded_by=?
                                  WHERE student_id=? AND subject_id=? AND attendance_date=?""",
                                (status,remarks,user["id"],s[0],subid,str(ad)))
                    else:
                        execute("""INSERT INTO subject_attendance
                                  (school_id,student_id,subject_id,attendance_date,status,remarks,recorded_by,created_at)
                                  VALUES(?,?,?,?,?,?,?,?)""",
                                (sid,s[0],subid,str(ad),status,remarks,user["id"],now()))
                    log(user["id"],"SAVE_SUBJECT_ATTENDANCE",f"student={s[0]},subject={subid},date={ad}")
                    st.success("Saved.")
            df=execute("""SELECT s.name,s.roll_number,c.class_name,c.section,sub.subject_name,
                                 sa.attendance_date,sa.status,COALESCE(sa.remarks,'')
                          FROM subject_attendance sa JOIN students s ON s.id=sa.student_id
                          JOIN classes c ON c.id=s.class_id JOIN subjects sub ON sub.id=sa.subject_id
                          WHERE sa.school_id=? AND s.class_id=? AND sa.subject_id=?
                          ORDER BY sa.attendance_date DESC,s.roll_number""",
                       (sid,cid,subid),fetch=True) or []
            adf=pd.DataFrame(df,columns=["Student","Roll No","Class","Section","Subject","Date","Status","Remarks"])
            st.subheader("Subject Attendance Records")
            st.dataframe(adf,use_container_width=True,hide_index=True)
            st.download_button("⬇️ Download Subject Attendance CSV",adf.to_csv(index=False).encode(),
                               "subject_attendance.csv","text/csv")

    elif choice == "Teacher Attendance":
        st.header("👩‍🏫 Teacher Attendance")
        teachers=execute("SELECT id,name,username FROM users WHERE school_id=? AND role='teacher' AND active=1 ORDER BY name",
                         (sid,),fetch=True) or []
        ad=st.date_input("Attendance Date",date.today(),key="ta_date")
        for t in teachers:
            old=one("SELECT status FROM teacher_attendance WHERE teacher_id=? AND attendance_date=?",(t[0],str(ad)))
            opts=["Present","Absent","Late","Leave"]
            status=st.selectbox(f"{t[1]} ({t[2]})",opts,index=opts.index(old[0]) if old else 0,key=f"ta_{t[0]}")
            remarks=st.text_input(f"Remarks - {t[1]}",key=f"tar_{t[0]}")
            if st.button(f"Save {t[1]}",key=f"tab_{t[0]}"):
                if old:
                    execute("""UPDATE teacher_attendance SET status=?,remarks=?,recorded_by=?
                               WHERE teacher_id=? AND attendance_date=?""",
                            (status,remarks,user["id"],t[0],str(ad)))
                else:
                    execute("""INSERT INTO teacher_attendance
                               (school_id,teacher_id,attendance_date,status,remarks,recorded_by,created_at)
                               VALUES(?,?,?,?,?,?,?)""",
                            (sid,t[0],str(ad),status,remarks,user["id"],now()))
                log(user["id"],"SAVE_TEACHER_ATTENDANCE",f"teacher={t[0]},date={ad}")
                st.success("Saved.")
        tr=execute("""SELECT u.name,u.username,ta.attendance_date,ta.status,COALESCE(ta.remarks,'')
                     FROM teacher_attendance ta JOIN users u ON u.id=ta.teacher_id
                     WHERE ta.school_id=? ORDER BY ta.attendance_date DESC,u.name""",
                   (sid,),fetch=True) or []
        tdf=pd.DataFrame(tr,columns=["Teacher","Username","Date","Status","Remarks"])
        st.dataframe(tdf,use_container_width=True,hide_index=True)
        st.download_button("⬇️ Download Teacher Attendance CSV",tdf.to_csv(index=False).encode(),
                           "teacher_attendance.csv","text/csv")

    elif choice == "Timetable":
        st.header("🕐 Timetable");
        classes = execute("SELECT id,class_name,section FROM classes WHERE school_id=?", (sid,), True) or [];
        subs = execute("SELECT id,subject_name FROM subjects WHERE school_id=?", (sid,), True) or [];
        teachers = execute("SELECT id,name FROM users WHERE school_id=? AND role='teacher' AND active=1", (sid,),
                           True) or []
        if classes:
            co = {f"{x[1]} - {x[2] or ''}": x[0] for x in classes};
            cid = co[st.selectbox("Class", list(co))];
            day = st.selectbox("Day", ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]);
            period = st.text_input("Period");
            subid = st.selectbox("Subject", [x[0] for x in subs],
                                 format_func=lambda i: next(x[1] for x in subs if x[0] == i)) if subs else None;
            tid = st.selectbox("Teacher", [x[0] for x in teachers],
                               format_func=lambda i: next(x[1] for x in teachers if x[0] == i)) if teachers else None;
            start = st.text_input("Start Time");
            end = st.text_input("End Time");
            room = st.text_input("Room")
            if st.button("Add Timetable Entry"): execute(
                "INSERT INTO timetable(school_id,class_id,day_of_week,period_name,subject_id,teacher_id,start_time,end_time,room) VALUES(?,?,?,?,?,?,?,?,?)",
                (sid, cid, day, period, subid, tid, start, end, room));st.success("Added.");st.rerun()
            rows = execute(
                "SELECT day_of_week,period_name,start_time,end_time,room FROM timetable WHERE school_id=? AND class_id=? ORDER BY id",
                (sid, cid), True) or [];
            st.dataframe(pd.DataFrame(rows, columns=["Day", "Period", "Start", "End", "Room"]),
                         use_container_width=True, hide_index=True)
    elif choice == "Search Student":
        st.header("🔎 Search Student");
        q = st.text_input("Name or Roll Number")
        if q:
            rows = execute(
                "SELECT s.id,s.name,s.roll_number,c.class_name,c.section FROM students s JOIN classes c ON s.class_id=c.id WHERE s.school_id=? AND s.active=1 AND (s.name LIKE ? OR s.roll_number LIKE ?) ORDER BY s.name",
                (sid, f"%{q}%", f"%{q}%"), True) or []
            for s in rows:
                r = student_result(s[0]);
                st.subheader(f"{s[1]} — Roll {s[2]} — {s[3]} {s[4] or ''}");
                st.dataframe(r[1], use_container_width=True, hide_index=True);
                st.write(f"Total **{r[2]:g}** | **{r[3]:.2f}%** | Grade **{r[4]}** | Result **{r[5]}**")
    elif choice == "Fee Management":
        st.header("💰 Fee Management")
        st.caption(
            "Simple class → cycle → student fee control. Principal has full control. "
            "Teachers/management need Manage Fees permission."
        )

        live = one(
            """SELECT role,can_view_fees,can_manage_fees FROM users
               WHERE id=? AND active=1 AND school_id=?""",
            (user["id"], sid)
        )
        if not live:
            st.error("Account is no longer active.")
            st.stop()
        if live[0] != "principal" and not bool(live[1]) and not bool(live[2]):
            st.error("You do not have permission to access Fee Management.")
            st.stop()

        can_manage_fee = live[0] == "principal" or bool(live[2])

        classes_fee = execute(
            """SELECT id,class_name,COALESCE(section,'')
               FROM classes WHERE school_id=?
               ORDER BY class_name,section""",
            (sid,), fetch=True
        ) or []

        if not classes_fee:
            st.warning("Add a class before managing fees.")
            st.stop()

        # ==============================================================
        # 1. MAIN CONTROL: CLASS + FEE CYCLE
        # ==============================================================
        class_map = {
            f"{x[1]} — Section {x[2]}": x[0]
            for x in classes_fee
        }

        st.subheader("📌 Select Class & Fee Cycle")
        c1, c2, c3 = st.columns(3)
        selected_class_label = c1.selectbox(
            "Class / Section", list(class_map), key="fee_main_class"
        )
        selected_class_id = class_map[selected_class_label]

        selected_type = c2.selectbox(
            "Fee Cycle", ["Monthly", "Semester", "Yearly"], key="fee_main_type"
        )

        years = fee_year_options(sid, selected_type, selected_class_id)
        selected_year = c3.selectbox(
            "Year", years, key="fee_main_year"
        )

        if selected_type == "Monthly":
            cycle_labels = {
                date(2000, m, 1).strftime("%B"): m for m in range(1, 13)
            }
            default_month_index = date.today().month - 1 if int(selected_year) == date.today().year else 0
            cycle_label = st.selectbox(
                "Month", list(cycle_labels),
                index=default_month_index,
                key="fee_main_month"
            )
            selected_cycle = cycle_labels[cycle_label]
        elif selected_type == "Semester":
            cycle_labels = {"Spring": 1, "Fall": 2}
            cycle_label = st.selectbox(
                "Semester", list(cycle_labels), key="fee_main_semester"
            )
            selected_cycle = cycle_labels[cycle_label]
        else:
            selected_cycle = 1
            cycle_label = "Year"

        selected_key = fee_key_from_parts(
            selected_type, int(selected_year), selected_cycle
        )
        selected_period_label = fee_label_from_parts(
            selected_type, int(selected_year), selected_cycle
        )
        selected_due_date = fee_due_date(
            selected_type, int(selected_year), selected_cycle
        )

        # Load the selected class/type once per rerun. The same dataframe is reused
        # for the selected cycle, payment list, previous balances and class report.
        class_fee_df = fee_records_df(
            sid,
            class_id=selected_class_id,
            fee_type=selected_type,
        )
        if class_fee_df.empty:
            current_cycle_df = class_fee_df.copy()
        else:
            current_cycle_df = class_fee_df[
                (class_fee_df["Academic Year"].astype(str) == str(selected_year))
                & (class_fee_df["Fee Key"].astype(str) == str(selected_key))
            ].copy()

        # Active students are shown even if they do not have a fee record yet.
        class_students = execute(
            """SELECT s.id,s.name,s.roll_number,c.class_name,COALESCE(c.section,'')
               FROM students s JOIN classes c ON c.id=s.class_id
               WHERE s.school_id=? AND s.class_id=? AND s.active=1
               ORDER BY s.roll_number,s.name""",
            (sid, selected_class_id), fetch=True
        ) or []

        total_due = float(current_cycle_df["Net Payable"].sum()) if not current_cycle_df.empty else 0.0
        total_paid = float(current_cycle_df["Paid"].sum()) if not current_cycle_df.empty else 0.0
        total_remaining = float(current_cycle_df["Remaining"].sum()) if not current_cycle_df.empty else 0.0
        paid_count = int((current_cycle_df["Remaining"] <= 0.005).sum()) if not current_cycle_df.empty else 0
        outstanding_count = int((current_cycle_df["Remaining"] > 0.005).sum()) if not current_cycle_df.empty else 0
        missing_count = max(0, len(class_students) - len(current_cycle_df))

        a,b,c,d,e = st.columns(5)
        a.metric("Students", len(class_students))
        b.metric("Selected Fee", f"{total_due:,.2f}")
        c.metric("Paid", f"{total_paid:,.2f}")
        d.metric("Remaining", f"{total_remaining:,.2f}")
        e.metric("Paid / Missing", f"{paid_count} / {missing_count}")

        st.markdown(
            f"### {selected_class_label} — {selected_period_label}"
        )
        st.caption(
            f"Cycle: **{selected_type}** | Academic Year: **{selected_year}** | "
            f"Due: **{selected_due_date.isoformat()}** | "
            f"Students with outstanding balance: **{outstanding_count}**"
        )

        display_cols = [
            "Student","Roll No","Class","Section","Fee Type","Period",
            "Net Payable","Paid","Remaining","Status","Due Date"
        ]
        if current_cycle_df.empty:
            st.info(
                "No fee record exists for this selected cycle yet. "
                "You can add the fee for one student below or create the cycle for the whole class."
            )
        else:
            st.dataframe(
                current_cycle_df[display_cols],
                use_container_width=True, hide_index=True
            )

        # ==============================================================
        # 2. INDIVIDUAL STUDENT FEE — THE MAIN REQUESTED FEATURE
        # ==============================================================
        st.divider()
        st.subheader("👤 Set Fee for One Student")
        st.caption(
            "Select a student from this class and enter that student's exact fee for "
            f"**{selected_period_label}**. This record belongs only to this cycle."
        )

        if not class_students:
            st.info("No active students in this class.")
        else:
            student_map = {
                f"{r[1]} — Roll {r[2]}": r for r in class_students
            }
            individual_student = student_map[
                st.selectbox(
                    "Student Name",
                    list(student_map),
                    key="individual_fee_student"
                )
            ]
            individual_id = int(individual_student[0])

            existing_student_fee = current_cycle_df[
                current_cycle_df["Student ID"] == individual_id
            ].copy() if not current_cycle_df.empty else pd.DataFrame()

            if existing_student_fee.empty:
                current_base = 0.0
                current_discount = 0.0
                current_late = 0.0
                current_paid = 0.0
                current_fee_id = None
                st.info(
                    f"No fee has been added yet for {individual_student[1]} in "
                    f"{selected_period_label}."
                )
            else:
                er = existing_student_fee.iloc[0]
                current_base = float(er["Base Fee"])
                current_discount = float(er["Discount"])
                current_late = float(er["Late Fee"])
                current_paid = float(er["Paid"])
                current_fee_id = int(er["Fee ID"])
                st.info(
                    f"Existing record: Fee **{er['Net Payable']:,.2f}** | "
                    f"Paid **{er['Paid']:,.2f}** | Remaining **{er['Remaining']:,.2f}**"
                )

            i1,i2,i3 = st.columns(3)
            individual_amount = i1.number_input(
                "Student Total Fee",
                min_value=0.0,
                value=float(current_base),
                step=100.0,
                key="individual_fee_amount"
            )
            individual_discount = i2.number_input(
                "Discount / Waiver",
                min_value=0.0,
                value=float(current_discount),
                step=100.0,
                key="individual_fee_discount"
            )
            individual_late = i3.number_input(
                "Late Fee",
                min_value=0.0,
                value=float(current_late),
                step=100.0,
                key="individual_fee_late"
            )

            individual_net = max(
                0.0,
                individual_amount - individual_discount + individual_late
            )
            st.info(
                f"**{individual_student[1]}** — {selected_period_label} | "
                f"Net Payable: **{individual_net:,.2f}** | "
                f"Already Paid: **{current_paid:,.2f}** | "
                f"New Remaining: **{max(0.0, individual_net-current_paid):,.2f}**"
            )

            if individual_net < current_paid - 0.005:
                st.error(
                    "The new fee cannot be lower than the amount already paid. "
                    "Add the correct fee or adjust the record before taking more payments."
                )
            elif can_manage_fee and st.button(
                "💾 Save This Student's Fee",
                type="primary",
                key="save_individual_student_fee"
            ):
                save_fee_record(
                    sid, individual_id, selected_type,
                    selected_period_label, selected_key,
                    selected_due_date, individual_amount,
                    individual_discount, individual_late,
                    f"Individual fee set by {user['name']}",
                    user["id"], selected_cycle
                )
                log(
                    user["id"], "SET_INDIVIDUAL_FEE",
                    f"student={individual_id};class={selected_class_id};"
                    f"cycle={selected_key};amount={individual_amount}"
                )
                st.success(
                    f"Fee saved for {individual_student[1]} — {selected_period_label}."
                )
                st.rerun()
            elif not can_manage_fee:
                st.info("View-only access. Ask the Principal for Manage Fees permission.")

        # ==============================================================
        # 3. PREPARE NEXT CYCLE WITH A DIFFERENT FEE
        # ==============================================================
        st.divider()
        st.subheader("➡️ Prepare Next Fee Cycle")
        st.caption(
            "Use this when the next month/semester/year starts and the Principal wants "
            "to increase or change the fee. The old cycle is never changed."
        )

        next_year, next_cycle = next_fee_cycle_parts(
            selected_type, int(selected_year), selected_cycle
        )
        next_key = fee_key_from_parts(selected_type, next_year, next_cycle)
        next_label = fee_label_from_parts(selected_type, next_year, next_cycle)
        next_due = fee_due_date(selected_type, next_year, next_cycle)

        next_existing = fee_records_df(
            sid,
            class_id=selected_class_id,
            fee_type=selected_type,
            academic_year=str(next_year),
            fee_key=next_key
        )

        n1,n2 = st.columns(2)
        n1.metric("Next Cycle", next_label)
        n2.metric("Existing Student Records", len(next_existing))

        if can_manage_fee:
            nx1,nx2,nx3 = st.columns(3)
            next_amount = nx1.number_input(
                "New Fee Per Student",
                min_value=0.0,
                value=0.0,
                step=100.0,
                key="next_cycle_amount"
            )
            next_discount = nx2.number_input(
                "Next Cycle Discount",
                min_value=0.0,
                value=0.0,
                step=100.0,
                key="next_cycle_discount"
            )
            next_late = nx3.number_input(
                "Next Cycle Late Fee",
                min_value=0.0,
                value=0.0,
                step=100.0,
                key="next_cycle_late"
            )

            st.info(
                f"Next cycle: **{next_label}** | Due: **{next_due.isoformat()}** | "
                f"Net per student: **{max(0.0,next_amount-next_discount+next_late):,.2f}**"
            )

            if st.button(
                f"💾 Set {next_label} Fee For Whole Class",
                type="primary",
                key="create_next_cycle_class_fee"
            ):
                if next_amount <= 0:
                    st.error("Next cycle fee must be greater than zero.")
                elif next_discount > next_amount:
                    st.error("Discount cannot be greater than the fee.")
                else:
                    created, existing, student_count, cycle_count_done = generate_class_fee_schedule(
                        sid, selected_class_id, selected_type,
                        next_amount, next_discount, next_late,
                        date(next_year, 1 if selected_type != "Monthly" else next_cycle, 1),
                        1, user["id"],
                        f"Next cycle fee set from {selected_period_label}"
                    )
                    st.success(
                        f"{next_label} prepared: {created} new student fee record(s). "
                        f"{existing} existing record(s) were kept unchanged."
                    )
                    st.rerun()

            # Individual next-cycle fee is useful when one student has a different fee.
            if class_students:
                next_student_map = {
                    f"{r[1]} — Roll {r[2]}": r for r in class_students
                }
                next_student = next_student_map[
                    st.selectbox(
                        "Or set a different fee for one student in the next cycle",
                        list(next_student_map),
                        key="next_cycle_individual_student"
                    )
                ]
                next_student_existing = fee_records_df(
                    sid,
                    student_id=int(next_student[0]),
                    fee_type=selected_type,
                    academic_year=str(next_year),
                    fee_key=next_key
                )
                old_next_amount = (
                    float(next_student_existing.iloc[0]["Base Fee"])
                    if not next_student_existing.empty else float(next_amount)
                )
                next_one_amount = st.number_input(
                    "Individual Next-Cycle Fee",
                    min_value=0.0,
                    value=old_next_amount,
                    step=100.0,
                    key="next_individual_amount"
                )
                if st.button(
                    f"💾 Save {next_student[1]}'s {next_label} Fee",
                    key="save_next_individual_fee"
                ):
                    if next_one_amount <= 0:
                        st.error("Fee must be greater than zero.")
                    else:
                        save_fee_record(
                            sid, int(next_student[0]), selected_type,
                            next_label, next_key, next_due,
                            next_one_amount, 0.0, 0.0,
                            f"Individual next-cycle fee set by {user['name']}",
                            user["id"], next_cycle
                        )
                        st.success(
                            f"{next_student[1]}'s fee for {next_label} was saved separately."
                        )
                        st.rerun()
        else:
            st.info("View-only access. Ask the Principal for Manage Fees permission.")

        # ==============================================================
        # 4. PAYMENTS — ONLY FOR THE SELECTED CLASS/CYCLE
        # ==============================================================
        st.divider()
        st.subheader("💳 Record Payment")
        outstanding = (
            current_cycle_df[current_cycle_df["Remaining"] > 0.005].copy()
            if not current_cycle_df.empty else pd.DataFrame()
        )

        if outstanding.empty:
            st.info("No outstanding payment in the selected cycle.")
        else:
            pay_map = {
                f"{r['Student']} — Roll {r['Roll No']} — Remaining {r['Remaining']:,.2f}": r
                for _, r in outstanding.iterrows()
            }
            pay_rec = pay_map[
                st.selectbox(
                    "Student With Outstanding Fee",
                    list(pay_map), key="class_fee_payment_student"
                )
            ]

            p1,p2,p3 = st.columns(3)
            payment_amount = p1.number_input(
                "Payment Amount",
                min_value=0.0,
                max_value=float(pay_rec["Remaining"]),
                value=0.0, step=100.0,
                key="class_fee_payment_amount"
            )
            payment_date = p2.date_input(
                "Payment Date", date.today(), key="class_fee_payment_date"
            )
            receipt = p3.text_input(
                "Receipt Number (optional)", key="class_fee_receipt"
            )

            st.info(
                f"{pay_rec['Student']} | {pay_rec['Period']} | "
                f"Fee: **{pay_rec['Net Payable']:,.2f}** | "
                f"Paid: **{pay_rec['Paid']:,.2f}** | "
                f"Remaining: **{pay_rec['Remaining']:,.2f}**"
            )

            if can_manage_fee and st.button(
                "💾 Save Payment", type="primary", key="class_fee_save_payment"
            ):
                if payment_amount <= 0:
                    st.error("Payment must be greater than zero.")
                else:
                    execute(
                        """INSERT INTO fee_payments
                           (fee_id,amount,payment_date,receipt_no,notes,recorded_by,created_at)
                           VALUES(?,?,?,?,?,?,?)""",
                        (
                            int(pay_rec["Fee ID"]), float(payment_amount),
                            str(payment_date), receipt.strip(), "",
                            user["id"], now()
                        )
                    )
                    log(
                        user["id"], "RECORD_FEE_PAYMENT",
                        f"fee={int(pay_rec['Fee ID'])},amount={payment_amount},receipt={receipt.strip()}"
                    )

                    # A fully paid cycle can prepare the next cycle, but never
                    # transfers or merges the previous balance into it.
                    updated_paid = float(pay_rec["Paid"]) + float(payment_amount)
                    if updated_paid >= float(pay_rec["Net Payable"]) - 0.005:
                        ensure_next_fee_cycle(int(pay_rec["Student ID"]))

                    st.success(
                        "Payment recorded. This payment belongs only to the selected "
                        f"cycle ({selected_period_label})."
                    )
                    st.rerun()
            elif not can_manage_fee:
                st.info("View-only access. Ask the Principal for Manage Fees permission.")

        # ==============================================================
        # 5. PREVIOUS BALANCES — ALWAYS SEPARATE
        # ==============================================================
        st.divider()
        st.subheader("⚠️ Previous / Other Outstanding Cycles")
        all_class_df = class_fee_df
        previous_outstanding = (
            all_class_df[
                (all_class_df["Fee Key"].astype(str) != str(selected_key)) &
                (all_class_df["Remaining"] > 0.005)
            ].copy()
            if not all_class_df.empty else pd.DataFrame()
        )

        if previous_outstanding.empty:
            st.success("No other outstanding balance for this class.")
        else:
            previous_cols = [
                "Student","Roll No","Fee Type","Period","Academic Year",
                "Net Payable","Paid","Remaining","Status"
            ]
            st.dataframe(
                previous_outstanding[previous_cols],
                use_container_width=True, hide_index=True
            )
            st.warning(
                f"Previous/other outstanding balance: "
                f"**{float(previous_outstanding['Remaining'].sum()):,.2f}**. "
                "This amount is NOT included in the selected cycle totals."
            )

        # ==============================================================
        # 6. STUDENT LEDGER
        # ==============================================================
        st.divider()
        st.subheader("📋 Student Fee Ledger")
        if class_students:
            ledger_map = {
                f"{r[1]} — Roll {r[2]}": r for r in class_students
            }
            ledger_student = ledger_map[
                st.selectbox(
                    "Student", list(ledger_map), key="fee_history_student"
                )
            ]

            ledger = fee_records_df(
                sid, student_id=int(ledger_student[0]), fee_type=selected_type
            )

            if ledger.empty:
                st.info("No fee history for this student.")
            else:
                l1,l2,l3,l4 = st.columns(4)
                l1.metric("Total Assessed", f"{float(ledger['Net Payable'].sum()):,.2f}")
                l2.metric("Total Paid", f"{float(ledger['Paid'].sum()):,.2f}")
                l3.metric("Total Remaining", f"{float(ledger['Remaining'].sum()):,.2f}")
                l4.metric(
                    "Outstanding Cycles",
                    int((ledger["Remaining"] > 0.005).sum())
                )

                selected_ledger = ledger[
                    ledger["Fee Key"].astype(str) == str(selected_key)
                ]
                other_ledger = ledger[
                    ledger["Fee Key"].astype(str) != str(selected_key)
                ]

                st.markdown("**Selected Cycle**")
                if selected_ledger.empty:
                    st.info("No fee record for this student in the selected cycle.")
                else:
                    st.dataframe(
                        selected_ledger[
                            ["Student","Roll No","Fee Type","Period",
                             "Academic Year","Net Payable","Paid",
                             "Remaining","Status","Due Date"]
                        ],
                        use_container_width=True, hide_index=True
                    )

                st.markdown("**Other / Previous Cycles — Kept Separate**")
                if other_ledger.empty:
                    st.info("No other fee cycles recorded.")
                else:
                    st.dataframe(
                        other_ledger[
                            ["Student","Roll No","Fee Type","Period",
                             "Academic Year","Net Payable","Paid",
                             "Remaining","Status","Due Date"]
                        ],
                        use_container_width=True, hide_index=True
                    )

                payment_rows = execute(
                    """SELECT f.fee_type,COALESCE(f.period_label,f.fee_month),
                              COALESCE(f.academic_year,substr(f.fee_month,1,4)),
                              p.amount,p.payment_date,COALESCE(p.receipt_no,'')
                       FROM fee_payments p
                       JOIN fee_records f ON f.id=p.fee_id
                       WHERE f.school_id=? AND f.student_id=?
                       ORDER BY p.payment_date DESC,p.id DESC""",
                    (sid, int(ledger_student[0])), fetch=True
                ) or []

                st.markdown("**Payment History**")
                if payment_rows:
                    payment_df = pd.DataFrame(
                        payment_rows,
                        columns=[
                            "Fee Type","Period","Academic Year",
                            "Amount Paid","Payment Date","Receipt No"
                        ]
                    )
                    st.dataframe(
                        payment_df, use_container_width=True, hide_index=True
                    )
                else:
                    st.info("No payments recorded yet.")

                ledger_csv = ledger.to_csv(index=False).encode()
                st.download_button(
                    "⬇️ Download This Student Ledger",
                    ledger_csv,
                    f"{ledger_student[1].replace(' ','_')}_fee_ledger.csv",
                    "text/csv",
                    key="student_fee_ledger_download"
                )

        # ==============================================================
        # 7. SIMPLE SELECTED CLASS/CYCLE DOWNLOAD
        # ==============================================================
        st.divider()
        st.subheader("📤 Selected Class / Cycle Report")
        if current_cycle_df.empty:
            st.info("No records to download for this selected cycle.")
        else:
            report_df = current_cycle_df[display_cols].copy()
            st.download_button(
                "⬇️ Download Selected Class Fee Report",
                report_df.to_csv(index=False).encode(),
                f"class_fee_{selected_type.lower()}_{selected_year}_{selected_cycle}.csv",
                "text/csv",
                key="selected_cycle_download"
            )
            st.caption(
                "This download contains only the selected class and selected "
                f"{selected_type.lower()} cycle — previous balances are not mixed into it."
            )

    elif choice == "Student Feedback":
        st.header("💬 Student Performance Feedback")
        students=execute("""SELECT s.id,s.name,s.roll_number,c.class_name,c.section
                            FROM students s JOIN classes c ON c.id=s.class_id
                            WHERE s.school_id=? AND s.active=1 ORDER BY s.name""",(sid,),fetch=True) or []
        if students:
            smap={f"{s[1]} | Roll {s[2]} | {s[3]} {s[4] or ''}":s for s in students}
            ss=smap[st.selectbox("Student",list(smap))]
            level=st.selectbox("Performance Level",["Excellent","Very Good","Good","Needs Improvement","Needs Urgent Attention"])
            feedback=st.text_area("Feedback for Parent")
            if st.button("Save Feedback",type="primary"):
                if not feedback.strip(): st.error("Enter feedback.")
                else:
                    execute("""INSERT INTO student_feedback
                               (school_id,student_id,teacher_id,feedback,performance_level,created_at,updated_at)
                               VALUES(?,?,?,?,?,?,?)""",
                            (sid,ss[0],user["id"],feedback.strip(),level,now(),now()))
                    log(user["id"],"CREATE_STUDENT_FEEDBACK",f"student={ss[0]}")
                    st.success("Feedback saved for the parent.")
            old=execute("""SELECT sf.performance_level,sf.feedback,sf.created_at,u.name
                           FROM student_feedback sf JOIN users u ON u.id=sf.teacher_id
                           WHERE sf.student_id=? ORDER BY sf.id DESC""",(ss[0],),fetch=True) or []
            st.dataframe(pd.DataFrame(old,columns=["Performance","Feedback","Date","Teacher"]),
                         use_container_width=True,hide_index=True)
        else:
            st.info("No students available.")

    elif choice == "Institution Report":
        st.header("📈 Institution Report")
        stats=[("Classes",one("SELECT COUNT(*) FROM classes WHERE school_id=?",(sid,))[0]),
               ("Students",one("SELECT COUNT(*) FROM students WHERE school_id=?",(sid,))[0]),
               ("Teachers",one("SELECT COUNT(*) FROM users WHERE school_id=? AND role='teacher'",(sid,))[0]),
               ("Principals",one("SELECT COUNT(*) FROM users WHERE school_id=? AND role='principal'",(sid,))[0]),
               ("Management",one("SELECT COUNT(*) FROM users WHERE school_id=? AND role='management'",(sid,))[0]),
               ("Parents",one("SELECT COUNT(*) FROM users WHERE school_id=? AND role='parent'",(sid,))[0])]
        st.dataframe(pd.DataFrame(stats,columns=["Metric","Value"]),use_container_width=True,hide_index=True)
        perf=[]
        for cl in execute("SELECT id,class_name,section FROM classes WHERE school_id=?", (sid,), fetch=True) or []:
            df = detailed_results_csv(sid, cl[0])
            if not df.empty:
                # clean Percentage column to numbers, ignore % signs and text
                df["Percentage"] = pd.to_numeric(df["Percentage"].astype(str).str.replace('%', ''), errors="coerce")
                avg = df["Percentage"].mean(skipna=True)
                perf.append({"Class": cl[1], "Section": cl[2], "Students": len(df),
                             "Average %": round(avg, 2) if pd.notna(avg) else 0.0})
        if perf:
            pdf=pd.DataFrame(perf).sort_values("Average %",ascending=False)
            st.dataframe(pdf,use_container_width=True,hide_index=True)
            st.success(f"Best-performing class: {pdf.iloc[0]['Class']} - {pdf.iloc[0]['Section']} ({pdf.iloc[0]['Average %']}%)")
        else: st.info("No results available yet.")

    elif choice == "My Account":
        st.header("🔐 My Account Privacy")
        live_permissions = one(
            "SELECT can_change_username,can_change_password FROM users WHERE id=? AND active=1",
            (user["id"],)
        )
        live_can_username = bool(live_permissions and live_permissions[0])
        live_can_password = bool(live_permissions and live_permissions[1])

        if not live_can_username and not live_can_password:
            st.info("Admin has not granted permission to change your username or password.")
        if live_can_username:
            nu=st.text_input("New Username",value=user["username"])
            if st.button("Change Username"):
                if not nu.strip(): st.error("Username cannot be empty.")
                elif nu.strip()!=user["username"] and one("SELECT id FROM users WHERE username=?",(nu.strip(),)):
                    st.error("Username already exists.")
                elif nu.strip()==user["username"]: st.info("This is already your username.")
                else:
                    execute("UPDATE users SET username=? WHERE id=?",(nu.strip(),user["id"]))
                    log(user["id"],"CHANGE_USERNAME",nu.strip())
                    st.success("Username changed."); st.rerun()
        if live_can_password:
            old=st.text_input("Current Password",type="password")
            new=st.text_input("New Password",type="password")
            con=st.text_input("Confirm New Password",type="password")
            if st.button("Change Password"):
                stored=one("SELECT password FROM users WHERE id=?",(user["id"],))
                if not stored or not verify_password(old,stored[0]): st.error("Current password is incorrect.")
                elif len(new)<6 or new!=con: st.error("Password must match and contain 6+ characters.")
                else:
                    execute("UPDATE users SET password=? WHERE id=?",(hash_password(new),user["id"]))
                    log(user["id"],"CHANGE_PASSWORD")
                    st.success("Password changed.")

    elif choice == "Accounts & Permissions":
        st.header("👥 Accounts & Permissions")
        st.info("The Principal controls school-level permissions. Fee access is separate from fee management: View Fees lets staff see records; Manage Fees also allows creating fee records, schedules and payments.")

        if user["role"] == "principal":
            st.subheader("➕ Create Management Account")
            mn=st.text_input("Management Staff Name")
            mu=st.text_input("Management Username")
            mp=st.text_input("Management Password",type="password")
            if st.button("Create Management Account",key="create_management_account"):
                if not mn.strip() or not mu.strip() or len(mp)<6:
                    st.error("Enter name, username and password (6+ characters).")
                elif one("SELECT id FROM users WHERE username=?",(mu.strip(),)):
                    st.error("Username already exists.")
                else:
                    execute("""INSERT INTO users(username,password,name,role,school_id,active,can_view_dashboard,created_at)
                               VALUES(?,?,?,?,?,1,1,?)""",
                            (mu.strip(),hash_password(mp),mn.strip(),"management",sid,now()))
                    log(user["id"],"CREATE_MANAGEMENT",mu.strip())
                    st.success("Management account created.")
                    st.rerun()

        rows = execute("""SELECT id,name,username,role,active,
                                 can_view_fees,can_manage_fees,can_manage_attendance,can_manage_results,
                                 can_manage_students,can_manage_classes,can_manage_accounts,
                                 can_change_username,can_change_password,can_view_dashboard
                          FROM users
                          WHERE school_id=? AND role IN ('teacher','student','parent','management')
                          ORDER BY CASE role WHEN 'teacher' THEN 1 WHEN 'management' THEN 2 WHEN 'parent' THEN 3 ELSE 4 END,name""",
                       (sid,),True) or []
        if rows:
            st.subheader("School Accounts")
            st.dataframe(pd.DataFrame(rows,columns=[
                "ID","Name","Username","Role","Active","View Fees","Manage Fees","Manage Attendance",
                "Manage Results","Manage Students","Manage Classes","Manage Accounts",
                "Username Change","Password Change","Dashboard"]),
                use_container_width=True,hide_index=True)

        if user["role"] == "principal":
            st.subheader("🔐 Staff Permissions")
            staff=[x for x in rows if x[3] in ("teacher","management")]
            if staff:
                smap={f"{x[1]} ({x[2]}) — {x[3].title()}":x for x in staff}
                ch=smap[st.selectbox("Select Staff Account",list(smap),key="staff_permission_account")]
                c1,c2=st.columns(2)
                with c1:
                    vfee=st.checkbox("View Fee Management",value=bool(ch[5]),help="Allows the account to open and view fee information.")
                    mfee=st.checkbox("Manage Fees",value=bool(ch[6]),help="Allows creating/editing fee records, generating schedules and recording payments. This automatically requires View Fees.")
                    matt=st.checkbox("Manage Attendance",value=bool(ch[7]))
                    mres=st.checkbox("Manage Results",value=bool(ch[8]))
                    mstu=st.checkbox("Manage Students",value=bool(ch[9]))
                with c2:
                    mcls=st.checkbox("Manage Classes",value=bool(ch[10]))
                    mac=st.checkbox("Manage Accounts",value=bool(ch[11]))
                    cu=st.checkbox("Allow Username Change",value=bool(ch[12]))
                    cp=st.checkbox("Allow Password Change",value=bool(ch[13]))
                    vd=st.checkbox("Allow Dashboard",value=bool(ch[14]))
                if st.button("💾 Save Staff Permissions",type="primary",key="save_staff_permissions"):
                    vfee_final = bool(vfee or mfee)
                    execute("""UPDATE users SET can_view_fees=?,can_manage_fees=?,can_manage_attendance=?,
                               can_manage_results=?,can_manage_students=?,can_manage_classes=?,can_manage_accounts=?,
                               can_change_username=?,can_change_password=?,can_view_dashboard=?
                               WHERE id=? AND school_id=?""",
                            (int(vfee_final),int(mfee),int(matt),int(mres),int(mstu),int(mcls),int(mac),
                             int(cu),int(cp),int(vd),ch[0],sid))
                    log(user["id"],"STAFF_PERMISSION_UPDATE",f"staff={ch[0]},view_fees={vfee_final},manage_fees={bool(mfee)}")
                    st.success("Permissions updated successfully.")
                    st.rerun()
                st.subheader("🗑️ Delete Teacher Account")
                teacher_map={f"{x[1]} ({x[2]})":x for x in staff if x[3]=="teacher"}
                if teacher_map:
                    dt=teacher_map[st.selectbox("Teacher who has left",list(teacher_map),key="delete_teacher")]
                    tconfirm=st.checkbox("I confirm this teacher has left the institution and should be permanently deleted.",key="confirm_delete_teacher")
                    if tconfirm and st.button("🗑️ Permanently Delete Teacher",key="delete_teacher_btn"):
                        execute("DELETE FROM users WHERE id=? AND school_id=? AND role='teacher'",(dt[0],sid))
                        execute("UPDATE classes SET incharge_teacher_id=NULL WHERE incharge_teacher_id=?",(dt[0],))
                        log(user["id"],"DELETE_TEACHER",f"teacher={dt[0]};name={dt[1]}")
                        st.success("Teacher account deleted.")
                        st.rerun()
            else:
                st.info("No teacher or management accounts exist yet.")

        st.divider()
        st.subheader("👨‍👩‍👧 Create Parent Account & Link Student")
        p_name = st.text_input("Parent Name")
        p_user = st.text_input("Parent Username")
        p_pw = st.text_input("Parent Password", type="password")
        parent_students = execute("SELECT id,name,roll_number FROM students WHERE school_id=? AND active=1 ORDER BY name",(sid,),True) or []
        if parent_students:
            pmap = {f"{x[1]} (Roll {x[2]})": x[0] for x in parent_students}
            p_student = pmap[st.selectbox("Link Parent To Student",list(pmap),key="principal_parent_student")]
            if st.button("Create Parent Account",key="principal_create_parent"):
                if not p_name.strip() or not p_user.strip() or len(p_pw)<6:
                    st.error("Enter parent name, unique username and password of at least 6 characters.")
                elif one("SELECT id FROM users WHERE username=?",(p_user.strip(),)):
                    st.error("Username already exists.")
                else:
                    ok,msg=create_user(p_user.strip(),p_pw,p_name.strip(),"parent",
                                       school_id=sid,student_id=p_student)
                    if ok:
                        pu=one("SELECT id FROM users WHERE username=?",(p_user.strip(),))
                        if pu:
                            execute("INSERT OR IGNORE INTO parent_student(parent_user_id,student_id) VALUES(?,?)",(pu[0],p_student))
                        log(user["id"],"CREATE_PARENT",p_user.strip())
                        st.success("Parent account created and linked.")
                        st.rerun()
                    else:
                        st.error(msg)
        else:
            st.warning("Add a student before creating a parent account.")
    elif choice == "Notifications":
        st.header("📱 SMS / WhatsApp Notifications")
        st.info(
            "This module prepares and records notifications. Live SMS/WhatsApp delivery requires an external provider/API and its credentials; the app does not pretend to send messages without one.")
        sts = execute("SELECT id,name,phone FROM students WHERE school_id=? AND active=1 ORDER BY name", (sid,),
                      True) or []
        if sts:
            mp = {f"{x[1]} — {x[2] or 'No phone'}": x for x in sts};
            ss = mp[st.selectbox("Student", list(mp))];
            channel = st.selectbox("Channel", ["SMS", "WhatsApp"]);
            msg = st.text_area("Message",
                               value=f"Dear Parent, this is a notification from {school[0]} regarding {ss[1]}.")
            if st.button("Prepare Notification"):
                execute(
                    "INSERT INTO notifications(school_id,student_id,recipient_type,channel,message,status,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (sid, ss[0], "Parent", channel, msg, "Prepared", user["id"], now()));
                st.success("Notification saved. Connect your provider API before using live delivery.")
            n = execute(
                "SELECT channel,message,status,created_at FROM notifications WHERE school_id=? ORDER BY id DESC LIMIT 100",
                (sid,), True) or [];
            st.dataframe(pd.DataFrame(n, columns=["Channel", "Message", "Status", "Created"]), use_container_width=True,
                         hide_index=True)

# ---------------- STUDENT / PARENT PORTALS ----------------
elif user["role"] in ("student", "parent"):
    sid = user["school_id"]
    if not school_active(sid):
        st.error("School suspended/expired.")
        st.stop()

    st.title("🎓 Student / Parent Portal")

    if user["role"] == "student":
        student_ids = [user["student_id"]] if user["student_id"] else []
    else:
        student_ids = [
            x[0] for x in (
                execute("SELECT student_id FROM parent_student WHERE parent_user_id=?",
                        (user["id"],), fetch=True) or []
            )
        ]

    portal_menu = ["Profile / Results", "Attendance", "Teacher Feedback", "My Account"]
    portal_choice = st.sidebar.radio("Portal Menu", portal_menu)

    if not student_ids:
        st.warning("No student is linked to this account.")
    else:
        labels={}
        for x in student_ids:
            r=student_result(x)
            if r:
                labels[f"{r[0][1]} — Roll {r[0][2]} — {r[0][3]} {r[0][4] or ''}"]=x

        if not labels:
            st.warning("No valid student record found.")
        else:
            chosen=labels[st.selectbox("Student",list(labels))]

            if portal_choice == "Profile / Results":
                r=student_result(chosen)
                st.subheader(f"{r[0][1]} — Roll {r[0][2]} — {r[0][3]} {r[0][4] or ''}")
                st.dataframe(r[1],use_container_width=True,hide_index=True)
                a,b,c,d=st.columns(4)
                a.metric("Total",f"{r[2]:g}"); b.metric("Percentage",f"{r[3]:.2f}%")
                c.metric("Grade",r[4]); d.metric("Result",r[5])
                st.write(f"**Attendance:** {attendance_display(chosen)}")
                pb=pdf_bytes(chosen)
                if pb:
                    st.download_button("📄 Download Result Card",pb,"result_card.pdf","application/pdf")

            elif portal_choice == "Attendance":
                att=execute("""SELECT attendance_date,status,remarks FROM attendance
                               WHERE student_id=? ORDER BY attendance_date DESC LIMIT 200""",
                            (chosen,),fetch=True) or []
                st.subheader("📅 General Attendance")
                if att:
                    adf=pd.DataFrame(att,columns=["Date","Status","Remarks"])
                    st.dataframe(adf,use_container_width=True,hide_index=True)
                    st.download_button("⬇️ Download Attendance CSV",adf.to_csv(index=False).encode(),
                                       "student_attendance.csv","text/csv")
                else:
                    st.info("Attendance Not Added")

                sa=execute("""SELECT sa.attendance_date,sub.subject_name,sa.status,sa.remarks
                              FROM subject_attendance sa JOIN subjects sub ON sub.id=sa.subject_id
                              WHERE sa.student_id=? ORDER BY sa.attendance_date DESC""",
                           (chosen,),fetch=True) or []
                st.subheader("📚 Subject-wise Attendance")
                if sa:
                    sdf=pd.DataFrame(sa,columns=["Date","Subject","Status","Remarks"])
                    st.dataframe(sdf,use_container_width=True,hide_index=True)
                    st.download_button("⬇️ Download Subject Attendance CSV",
                                       sdf.to_csv(index=False).encode(),"subject_attendance.csv","text/csv")
                else:
                    st.info("Subject attendance not added.")

            elif portal_choice == "Teacher Feedback":
                feedback=execute("""SELECT sf.performance_level,sf.feedback,sf.created_at,u.name
                                    FROM student_feedback sf JOIN users u ON u.id=sf.teacher_id
                                    WHERE sf.student_id=? ORDER BY sf.id DESC""",
                                 (chosen,),fetch=True) or []
                st.subheader("💬 Teacher / In-Charge Feedback")
                if feedback:
                    st.dataframe(pd.DataFrame(feedback,columns=["Performance","Feedback","Date","Teacher"]),
                                 use_container_width=True,hide_index=True)
                else:
                    st.info("No teacher feedback has been added yet.")

            elif portal_choice == "My Account":
                live_permissions = one(
                    "SELECT can_change_username,can_change_password FROM users WHERE id=? AND active=1",
                    (user["id"],)
                )
                live_can_username = bool(live_permissions and live_permissions[0])
                live_can_password = bool(live_permissions and live_permissions[1])

                if not live_can_username and not live_can_password:
                    st.info("Admin has not granted permission to change your username or password.")
                if live_can_username:
                    nu=st.text_input("New Username",value=user["username"])
                    if st.button("Change Username"):
                        if not nu.strip(): st.error("Username cannot be empty.")
                        elif nu.strip()!=user["username"] and one("SELECT id FROM users WHERE username=?",(nu.strip(),)):
                            st.error("Username already exists.")
                        elif nu.strip()==user["username"]: st.info("This is already your username.")
                        else:
                            execute("UPDATE users SET username=? WHERE id=?",(nu.strip(),user["id"]))
                            log(user["id"],"CHANGE_USERNAME",nu.strip()); st.success("Username changed."); st.rerun()
                if live_can_password:
                    old=st.text_input("Current Password",type="password")
                    new=st.text_input("New Password",type="password")
                    con=st.text_input("Confirm New Password",type="password")
                    if st.button("Change Password"):
                        stored=one("SELECT password FROM users WHERE id=?",(user["id"],))
                        if not stored or not verify_password(old,stored[0]): st.error("Current password is incorrect.")
                        elif len(new)<6 or new!=con: st.error("Password must match and contain 6+ characters.")
                        else:
                            execute("UPDATE users SET password=? WHERE id=?",(hash_password(new),user["id"]))
                            log(user["id"],"CHANGE_PASSWORD"); st.success("Password changed.")

st.divider();
st.caption("🎓 Multi-Institution Educational Management Platform • Performance-optimized SQLite mode")
