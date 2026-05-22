"""
BrainLock - A Beautiful Password Manager / Auth App
Author: Senior Dev
Tech: PyQt5 + SQLite + bcrypt
"""

import sys
import sqlite3
import bcrypt
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFrame, QStackedWidget,
    QComboBox, QGraphicsDropShadowEffect, QScrollArea, QSizePolicy
)
from PyQt5.QtCore import (
    Qt, QPropertyAnimation, QEasingCurve, QTimer, QPoint,
    QSequentialAnimationGroup, pyqtSignal, QRect
)
from PyQt5.QtGui import (
    QFont, QFontDatabase, QColor, QPalette, QLinearGradient,
    QBrush, QPainter, QPixmap, QIcon, QPainterPath, QPen
)


DB_PATH = "brainlock.db"

SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What city were you born in?",
    "What is your mother's maiden name?",
    "What was the name of your first school?",
    "What is your favourite book?",
    "What was your childhood nickname?",
    "What street did you grow up on?",
    "What is the name of your favourite teacher?",
]


def init_db():
    """Create tables if they don't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT UNIQUE NOT NULL,
                password   TEXT NOT NULL,
                q1         TEXT NOT NULL,
                a1         TEXT NOT NULL,
                q2         TEXT NOT NULL,
                a2         TEXT NOT NULL,
                q3         TEXT NOT NULL,
                a3         TEXT NOT NULL
            )
        """)
        conn.commit()


def hash_text(text: str) -> str:
    """Hash a plain-text string with bcrypt."""
    return bcrypt.hashpw(text.strip().lower().encode(), bcrypt.gensalt()).decode()


def verify_text(plain: str, hashed: str) -> bool:
    """Check plain text against a bcrypt hash."""
    return bcrypt.checkpw(plain.strip().lower().encode(), hashed.encode())


def register_user(username, password, q1, a1, q2, a2, q3, a3) -> tuple[bool, str]:
    """Insert new user. Returns (success, message)."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (username, password, q1, a1, q2, a2, q3, a3) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    username.strip(),
                    hash_text(password),
                    q1, hash_text(a1),
                    q2, hash_text(a2),
                    q3, hash_text(a3),
                )
            )
            conn.commit()
        return True, "Account created! ✨"
    except sqlite3.IntegrityError:
        return False, "Username already exists 🌸"
    except Exception as e:
        return False, str(e)


def login_user(username, password) -> tuple[bool, str]:
    """Validate login credentials. Returns (success, message)."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT password FROM users WHERE username = ?",
            (username.strip(),)
        ).fetchone()
    if not row:
        return False, "User not found 💭"
    if verify_text(password, row[0]):
        return True, "Welcome back! 💖"
    return False, "Incorrect password 🔐"


def get_security_questions(username) -> list[str]:
    """Return the 3 security question texts for a user."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT q1, q2, q3 FROM users WHERE username = ?",
            (username.strip(),)
        ).fetchone()
    return list(row) if row else []


def verify_security_answers(username, a1, a2, a3) -> bool:
    """Check all 3 security answers."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT a1, a2, a3 FROM users WHERE username = ?",
            (username.strip(),)
        ).fetchone()
    if not row:
        return False
    return all([
        verify_text(a1, row[0]),
        verify_text(a2, row[1]),
        verify_text(a3, row[2]),
    ])


def reset_password(username, new_password) -> bool:
    """Update password after successful security check."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (hash_text(new_password), username.strip())
        )
        conn.commit()
    return cur.rowcount > 0


# ─────────────────────────────────────────────
#  STYLE CONSTANTS
# ─────────────────────────────────────────────
PINK        = "#ff4da6"
PURPLE      = "#b366ff"
DARK_PINK   = "#e6008a"
LIGHT_BG    = "#fff0f5"
CARD_BG     = "#ffffff"
LAVENDER    = "#ede0ff"
MUTED_TEXT  = "#b399c2"
ERROR_RED   = "#ff6b9d"
SUCCESS_GRN = "#a78bfa"

STYLE_SHEET = """
/* ── App-wide ── */
QWidget {
    background: transparent;
    font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    color: #3d1a4f;
}

/* ── Scroll area ── */
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { width: 6px; background: #f3e6f9; border-radius: 3px; }
QScrollBar::handle:vertical { background: #d4a8f7; border-radius: 3px; }

/* ── Generic label ── */
QLabel { background: transparent; }

/* ── Line Edit ── */
QLineEdit {
    background: #fdf5ff;
    border: 2px solid #e8d5f5;
    border-radius: 16px;
    padding: 12px 20px;
    font-size: 14px;
    color: #3d1a4f;
    selection-background-color: #e0b3ff;
}
QLineEdit:focus {
    border: 2px solid #b366ff;
    background: #fff8ff;
}
QLineEdit::placeholder { color: #c9a8e0; }

/* ── Combo box ── */
QComboBox {
    background: #fdf5ff;
    border: 2px solid #e8d5f5;
    border-radius: 16px;
    padding: 12px 20px;
    font-size: 13px;
    color: #3d1a4f;
}
QComboBox:focus { border: 2px solid #b366ff; }
QComboBox::drop-down { border: none; width: 30px; }
QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid #b366ff;
    margin-right: 8px;
}
QComboBox QAbstractItemView {
    background: #fff8ff;
    border: 1px solid #e8d5f5;
    border-radius: 12px;
    selection-background-color: #f0d6ff;
    padding: 6px;
    color: #3d1a4f;
}

/* ── Push buttons ── */
QPushButton {
    border-radius: 18px;
    padding: 13px 30px;
    font-size: 15px;
    font-weight: 600;
    border: none;
}
QPushButton#primary {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #ff4da6, stop:1 #b366ff
    );
    color: white;
}
QPushButton#primary:hover {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #e6008a, stop:1 #9933ff
    );
}
QPushButton#primary:pressed { padding-top: 15px; }

QPushButton#secondary {
    background: #f3e6fc;
    color: #b366ff;
    border: 2px solid #ddb8f7;
}
QPushButton#secondary:hover { background: #ead4fa; }

QPushButton#link {
    background: transparent;
    color: #b366ff;
    font-size: 13px;
    font-weight: 500;
    padding: 4px 8px;
    text-decoration: underline;
}
QPushButton#link:hover { color: #ff4da6; }
"""


# ─────────────────────────────────────────────
#  HELPER WIDGETS
# ─────────────────────────────────────────────

def shadow(widget, blur=20, color="#c0a0d0", opacity=80, dx=0, dy=4):
    """Attach a drop-shadow effect to a widget."""
    fx = QGraphicsDropShadowEffect()
    fx.setBlurRadius(blur)
    fx.setOffset(dx, dy)
    c = QColor(color)
    c.setAlpha(opacity)
    fx.setColor(c)
    widget.setGraphicsEffect(fx)
    return fx


class GradientFrame(QFrame):
    """A QFrame that paints a pink→purple gradient background."""

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect()
        grad = QLinearGradient(0, 0, r.width(), r.height())
        grad.setColorAt(0.0, QColor("#fff0f5"))
        grad.setColorAt(1.0, QColor("#f3e6fc"))
        p.fillRect(r, QBrush(grad))
        super().paintEvent(event)


class Card(QFrame):
    """Rounded white card with soft shadow."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            "QFrame { background: white; border-radius: 28px; }"
        )
        shadow(self, blur=35, color="#c0a0d0", opacity=55, dy=8)


class TitleLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(
            "font-size: 28px; font-weight: 700; "
            "background: transparent; color: #6200a0;"
        )


class SubLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(
            "font-size: 13px; color: #b399c2; background: transparent;"
        )


class FieldLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(
            "font-size: 12px; font-weight: 600; color: #9a5fc7;"
            "background: transparent; margin-left: 4px;"
        )


class StatusLabel(QLabel):
    """Shows success/error messages."""
    def __init__(self, parent=None):
        super().__init__("", parent)
        self.setAlignment(Qt.AlignCenter)
        self.setWordWrap(True)
        self.setStyleSheet("background: transparent; font-size: 13px;")

    def success(self, msg):
        self.setText(msg)
        self.setStyleSheet(
            "background: #f0fff4; color: #7c3aed; border-radius: 10px;"
            "padding: 8px; font-size: 13px;"
        )

    def error(self, msg):
        self.setText(msg)
        self.setStyleSheet(
            "background: #fff0f5; color: #e6008a; border-radius: 10px;"
            "padding: 8px; font-size: 13px;"
        )

    def clear_msg(self):
        self.setText("")
        self.setStyleSheet("background: transparent; font-size: 13px;")


def primary_btn(text) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("primary")
    b.setCursor(Qt.PointingHandCursor)
    return b


def secondary_btn(text) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("secondary")
    b.setCursor(Qt.PointingHandCursor)
    return b


def link_btn(text) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("link")
    b.setCursor(Qt.PointingHandCursor)
    return b


def field(placeholder, echo=False) -> QLineEdit:
    e = QLineEdit()
    e.setPlaceholderText(placeholder)
    if echo:
        e.setEchoMode(QLineEdit.Password)
    e.setMinimumHeight(48)
    return e


def vspace(n=10) -> QWidget:
    w = QWidget()
    w.setFixedHeight(n)
    return w


# ─────────────────────────────────────────────
#  PAGES
# ─────────────────────────────────────────────

class LoginPage(QWidget):
    """The main sign-in screen."""
    switch_register = pyqtSignal()
    switch_forgot   = pyqtSignal()
    login_success   = pyqtSignal(str)   # emits username

    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        # ── Outer background ──
        bg = GradientFrame()
        bg_layout = QVBoxLayout(bg)
        bg_layout.setAlignment(Qt.AlignCenter)
        root.addWidget(bg)

        # ── Card ──
        card = Card()
        card.setFixedWidth(420)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(40, 40, 40, 40)
        cl.setSpacing(12)

        # Emoji + title
        emoji = QLabel("🔐")
        emoji.setAlignment(Qt.AlignCenter)
        emoji.setStyleSheet("font-size: 48px; background: transparent;")
        cl.addWidget(emoji)

        cl.addWidget(TitleLabel("BrainLock"))
        cl.addWidget(SubLabel("Your secure sanctuary 🌸"))
        cl.addWidget(vspace(10))

        # Username
        cl.addWidget(FieldLabel("Username"))
        self.user_in = field("Enter your username")
        cl.addWidget(self.user_in)

        # Password
        cl.addWidget(FieldLabel("Password"))
        self.pass_in = field("Enter your password", echo=True)
        cl.addWidget(self.pass_in)
        cl.addWidget(vspace(4))

        # Status
        self.status = StatusLabel()
        cl.addWidget(self.status)

        # Login button
        self.login_btn = primary_btn("Sign In ✨")
        self.login_btn.setMinimumHeight(52)
        self.login_btn.clicked.connect(self._do_login)
        cl.addWidget(self.login_btn)

        # Forgot password
        row = QHBoxLayout()
        row.setAlignment(Qt.AlignCenter)
        fp = link_btn("Forgot Password?")
        fp.clicked.connect(self.switch_forgot.emit)
        row.addWidget(fp)
        cl.addLayout(row)

        cl.addWidget(vspace(6))

        # Register
        reg_row = QHBoxLayout()
        reg_row.setAlignment(Qt.AlignCenter)
        reg_row.addWidget(SubLabel("New here?"))
        reg_btn = link_btn("Create account")
        reg_btn.clicked.connect(self.switch_register.emit)
        reg_row.addWidget(reg_btn)
        cl.addLayout(reg_row)

        bg_layout.addWidget(card, alignment=Qt.AlignCenter)

    def _do_login(self):
        u = self.user_in.text().strip()
        p = self.pass_in.text()
        if not u or not p:
            self.status.error("Please fill in all fields 🌸")
            return
        ok, msg = login_user(u, p)
        if ok:
            self.status.success(msg)
            QTimer.singleShot(500, lambda: self.login_success.emit(u))
        else:
            self.status.error(msg)


class RegisterPage(QWidget):
    """Account creation screen with 3 security questions."""
    switch_login    = pyqtSignal()
    register_done   = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        bg = GradientFrame()
        bg_layout = QVBoxLayout(bg)
        bg_layout.setAlignment(Qt.AlignCenter)
        root.addWidget(bg)

        # Scrollable card for long form
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setFixedWidth(460)
        scroll.setMaximumHeight(680)
        scroll.setStyleSheet("background: transparent;")

        card = Card()
        cl = QVBoxLayout(card)
        cl.setContentsMargins(40, 40, 40, 40)
        cl.setSpacing(10)

        emoji = QLabel("🌸")
        emoji.setAlignment(Qt.AlignCenter)
        emoji.setStyleSheet("font-size: 44px; background: transparent;")
        cl.addWidget(emoji)
        cl.addWidget(TitleLabel("Create Account"))
        cl.addWidget(SubLabel("Join BrainLock today ✨"))
        cl.addWidget(vspace(8))

        # ── Credentials ──
        cl.addWidget(FieldLabel("Username"))
        self.user_in = field("Choose a username")
        cl.addWidget(self.user_in)

        cl.addWidget(FieldLabel("Password"))
        self.pass_in = field("Create a strong password", echo=True)
        cl.addWidget(self.pass_in)

        cl.addWidget(FieldLabel("Confirm Password"))
        self.pass2_in = field("Repeat your password", echo=True)
        cl.addWidget(self.pass2_in)

        cl.addWidget(vspace(8))

        # ── Security questions ──
        divider = QLabel("─── Security Questions ───")
        divider.setAlignment(Qt.AlignCenter)
        divider.setStyleSheet(
            "color: #c9a8e0; font-size: 12px; background: transparent;"
        )
        cl.addWidget(divider)
        cl.addWidget(vspace(4))

        self.q_combos = []
        self.a_fields = []
        for i in range(3):
            cl.addWidget(FieldLabel(f"Question {i+1}"))
            combo = QComboBox()
            combo.addItems(SECURITY_QUESTIONS)
            combo.setMinimumHeight(48)
            cl.addWidget(combo)
            self.q_combos.append(combo)

            cl.addWidget(FieldLabel(f"Your Answer"))
            ans = field(f"Answer to question {i+1}")
            cl.addWidget(ans)
            self.a_fields.append(ans)
            cl.addWidget(vspace(4))

        # ── Status + submit ──
        self.status = StatusLabel()
        cl.addWidget(self.status)

        btn = primary_btn("Create Account 💖")
        btn.setMinimumHeight(52)
        btn.clicked.connect(self._do_register)
        cl.addWidget(btn)

        back_row = QHBoxLayout()
        back_row.setAlignment(Qt.AlignCenter)
        back_row.addWidget(SubLabel("Already have an account?"))
        back_btn = link_btn("Sign in")
        back_btn.clicked.connect(self.switch_login.emit)
        back_row.addWidget(back_btn)
        cl.addLayout(back_row)

        scroll.setWidget(card)
        shadow(scroll, blur=0)   # shadow on card itself
        bg_layout.addWidget(scroll, alignment=Qt.AlignCenter)

    def _do_register(self):
        u  = self.user_in.text().strip()
        p  = self.pass_in.text()
        p2 = self.pass2_in.text()
        answers = [f.text() for f in self.a_fields]
        questions = [c.currentText() for c in self.q_combos]

        if not u or not p:
            self.status.error("Username and password are required 🌸"); return
        if p != p2:
            self.status.error("Passwords don't match 💫"); return
        if len(p) < 6:
            self.status.error("Password must be at least 6 characters 🔒"); return
        if any(not a.strip() for a in answers):
            self.status.error("Please answer all security questions 🌺"); return
        # Check for duplicate questions
        if len(set(questions)) < 3:
            self.status.error("Please choose 3 different questions ✨"); return

        ok, msg = register_user(u, p, *[x for pair in zip(questions, answers) for x in pair])
        if ok:
            self.status.success(msg)
            QTimer.singleShot(800, self.register_done.emit)
        else:
            self.status.error(msg)


class ForgotPage(QWidget):
    """Multi-step password recovery: username → questions → reset."""
    switch_login = pyqtSignal()

    STEP_USER  = 0
    STEP_QA    = 1
    STEP_RESET = 2

    def __init__(self):
        super().__init__()
        self._username = ""
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        bg = GradientFrame()
        bg_layout = QVBoxLayout(bg)
        bg_layout.setAlignment(Qt.AlignCenter)
        root.addWidget(bg)

        self.stack = QStackedWidget()
        self.stack.setFixedWidth(440)

        # ── Step 0: Enter username ──
        s0 = Card()
        l0 = QVBoxLayout(s0)
        l0.setContentsMargins(40, 40, 40, 40)
        l0.setSpacing(12)

        QLabel("🔑", s0)
        emoji0 = QLabel("🔑")
        emoji0.setAlignment(Qt.AlignCenter)
        emoji0.setStyleSheet("font-size: 44px; background: transparent;")
        l0.addWidget(emoji0)
        l0.addWidget(TitleLabel("Forgot Password"))
        l0.addWidget(SubLabel("Enter your username to continue"))
        l0.addWidget(vspace(10))
        l0.addWidget(FieldLabel("Username"))
        self.fp_user = field("Your username")
        l0.addWidget(self.fp_user)
        self.fp_status0 = StatusLabel()
        l0.addWidget(self.fp_status0)
        btn0 = primary_btn("Continue →")
        btn0.setMinimumHeight(50)
        btn0.clicked.connect(self._step0_next)
        l0.addWidget(btn0)
        back0 = link_btn("← Back to Login")
        back0.clicked.connect(self.switch_login.emit)
        l0.addWidget(back0, alignment=Qt.AlignCenter)
        self.stack.addWidget(s0)

        # ── Step 1: Security questions ──
        s1 = Card()
        l1 = QVBoxLayout(s1)
        l1.setContentsMargins(40, 40, 40, 40)
        l1.setSpacing(10)

        emoji1 = QLabel("🛡️")
        emoji1.setAlignment(Qt.AlignCenter)
        emoji1.setStyleSheet("font-size: 44px; background: transparent;")
        l1.addWidget(emoji1)
        l1.addWidget(TitleLabel("Security Check"))
        l1.addWidget(SubLabel("Answer your security questions"))
        l1.addWidget(vspace(8))

        self.q_labels = []
        self.a_inputs = []
        for i in range(3):
            ql = FieldLabel(f"Question {i+1}")
            l1.addWidget(ql)
            self.q_labels.append(ql)
            ai = field(f"Your answer")
            l1.addWidget(ai)
            self.a_inputs.append(ai)
            l1.addWidget(vspace(2))

        self.fp_status1 = StatusLabel()
        l1.addWidget(self.fp_status1)
        btn1 = primary_btn("Verify Answers ✨")
        btn1.setMinimumHeight(50)
        btn1.clicked.connect(self._step1_verify)
        l1.addWidget(btn1)
        self.stack.addWidget(s1)

        # ── Step 2: New password ──
        s2 = Card()
        l2 = QVBoxLayout(s2)
        l2.setContentsMargins(40, 40, 40, 40)
        l2.setSpacing(12)

        emoji2 = QLabel("🌷")
        emoji2.setAlignment(Qt.AlignCenter)
        emoji2.setStyleSheet("font-size: 44px; background: transparent;")
        l2.addWidget(emoji2)
        l2.addWidget(TitleLabel("New Password"))
        l2.addWidget(SubLabel("Choose a fresh password 🌸"))
        l2.addWidget(vspace(10))
        l2.addWidget(FieldLabel("New Password"))
        self.new_pass = field("Create new password", echo=True)
        l2.addWidget(self.new_pass)
        l2.addWidget(FieldLabel("Confirm Password"))
        self.new_pass2 = field("Repeat new password", echo=True)
        l2.addWidget(self.new_pass2)
        self.fp_status2 = StatusLabel()
        l2.addWidget(self.fp_status2)
        btn2 = primary_btn("Reset Password 💖")
        btn2.setMinimumHeight(50)
        btn2.clicked.connect(self._step2_reset)
        l2.addWidget(btn2)
        self.stack.addWidget(s2)

        bg_layout.addWidget(self.stack, alignment=Qt.AlignCenter)

    def show_page(self):
        """Reset to step 0 each time the page is opened."""
        self.stack.setCurrentIndex(self.STEP_USER)
        self.fp_user.clear()
        self.fp_status0.clear_msg()
        for ai in self.a_inputs:
            ai.clear()
        self.new_pass.clear()
        self.new_pass2.clear()

    def _step0_next(self):
        u = self.fp_user.text().strip()
        if not u:
            self.fp_status0.error("Please enter your username"); return
        qs = get_security_questions(u)
        if not qs:
            self.fp_status0.error("Username not found 💭"); return
        self._username = u
        for i, ql in enumerate(self.q_labels):
            ql.setText(qs[i])
        self.stack.setCurrentIndex(self.STEP_QA)

    def _step1_verify(self):
        answers = [f.text() for f in self.a_inputs]
        if any(not a.strip() for a in answers):
            self.fp_status1.error("Please answer all questions"); return
        if verify_security_answers(self._username, *answers):
            self.stack.setCurrentIndex(self.STEP_RESET)
        else:
            self.fp_status1.error("Some answers are incorrect 🔐")

    def _step2_reset(self):
        p  = self.new_pass.text()
        p2 = self.new_pass2.text()
        if not p:
            self.fp_status2.error("Please enter a new password"); return
        if p != p2:
            self.fp_status2.error("Passwords don't match 💫"); return
        if len(p) < 6:
            self.fp_status2.error("At least 6 characters required 🔒"); return
        if reset_password(self._username, p):
            self.fp_status2.success("Password reset! 🎉 Redirecting...")
            QTimer.singleShot(1000, self.switch_login.emit)
        else:
            self.fp_status2.error("Something went wrong, try again")


class DashboardPage(QWidget):
    """Post-login dashboard."""
    logout = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        bg = GradientFrame()
        bg_layout = QVBoxLayout(bg)
        bg_layout.setAlignment(Qt.AlignCenter)
        root.addWidget(bg)

        card = Card()
        card.setFixedWidth(480)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(50, 50, 50, 50)
        cl.setSpacing(16)

        self.welcome = QLabel("Welcome! 💖")
        self.welcome.setAlignment(Qt.AlignCenter)
        self.welcome.setStyleSheet(
            "font-size: 32px; font-weight: 700; color: #6200a0; background: transparent;"
        )
        cl.addWidget(self.welcome)

        subtitle = QLabel("You're safely logged into BrainLock 🔐")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #b399c2; font-size: 14px; background: transparent;")
        cl.addWidget(subtitle)

        cl.addWidget(vspace(20))

        # Feature tiles
        tiles = [
            ("🌸", "Passwords Stored", "0"),
            ("💜", "Security Score", "Strong"),
            ("✨", "Last Login", "Just now"),
        ]
        tiles_row = QHBoxLayout()
        tiles_row.setSpacing(12)
        for emoji, label, val in tiles:
            tile = QFrame()
            tile.setStyleSheet(
                "QFrame { background: #fdf5ff; border-radius: 18px; "
                "border: 1.5px solid #e8d5f5; }"
            )
            tl = QVBoxLayout(tile)
            tl.setContentsMargins(16, 16, 16, 16)
            tl.setSpacing(4)
            em = QLabel(emoji)
            em.setAlignment(Qt.AlignCenter)
            em.setStyleSheet("font-size: 26px; background: transparent; border: none;")
            tl.addWidget(em)
            lbl = QLabel(label)
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("color: #b399c2; font-size: 11px; background: transparent; border: none;")
            tl.addWidget(lbl)
            vl = QLabel(val)
            vl.setAlignment(Qt.AlignCenter)
            vl.setStyleSheet("color: #6200a0; font-size: 13px; font-weight: 700; background: transparent; border: none;")
            tl.addWidget(vl)
            tiles_row.addWidget(tile)
        cl.addLayout(tiles_row)

        cl.addWidget(vspace(16))

        # Motivational pill
        pill = QLabel("Your secrets are safe with us 🌺")
        pill.setAlignment(Qt.AlignCenter)
        pill.setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #ff4da6, stop:1 #b366ff);"
            "color: white; border-radius: 20px; padding: 12px 24px; font-size: 13px; font-weight: 600;"
        )
        cl.addWidget(pill)

        cl.addWidget(vspace(10))

        # Logout
        logout_btn = secondary_btn("Sign Out")
        logout_btn.setMinimumHeight(48)
        logout_btn.clicked.connect(self.logout.emit)
        cl.addWidget(logout_btn)

        shadow(card, blur=40, color="#c0a0d0", opacity=60, dy=10)
        bg_layout.addWidget(card, alignment=Qt.AlignCenter)

    def set_username(self, username: str):
        self.welcome.setText(f"Welcome, {username}! 💖")


# ─────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────

class BrainLock(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BrainLock 🔐")
        self.setMinimumSize(900, 650)
        self.resize(960, 700)
        self._build()

    def _build(self):
        # Central stacked widget
        self.pages = QStackedWidget()
        self.setCentralWidget(self.pages)

        # Instantiate pages
        self.login_page     = LoginPage()
        self.register_page  = RegisterPage()
        self.forgot_page    = ForgotPage()
        self.dashboard_page = DashboardPage()

        self.pages.addWidget(self.login_page)      # index 0
        self.pages.addWidget(self.register_page)   # index 1
        self.pages.addWidget(self.forgot_page)     # index 2
        self.pages.addWidget(self.dashboard_page)  # index 3

        # ── Wire signals ──
        self.login_page.switch_register.connect(lambda: self.pages.setCurrentIndex(1))
        self.login_page.switch_forgot.connect(self._open_forgot)
        self.login_page.login_success.connect(self._on_login)

        self.register_page.switch_login.connect(lambda: self.pages.setCurrentIndex(0))
        self.register_page.register_done.connect(lambda: self.pages.setCurrentIndex(0))

        self.forgot_page.switch_login.connect(lambda: self.pages.setCurrentIndex(0))

        self.dashboard_page.logout.connect(self._on_logout)

        self.pages.setCurrentIndex(0)

    def _open_forgot(self):
        self.forgot_page.show_page()
        self.pages.setCurrentIndex(2)

    def _on_login(self, username: str):
        self.dashboard_page.set_username(username)
        self.pages.setCurrentIndex(3)

    def _on_logout(self):
        self.login_page.user_in.clear()
        self.login_page.pass_in.clear()
        self.login_page.status.clear_msg()
        self.pages.setCurrentIndex(0)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def main():
    init_db()

    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE_SHEET)

    # Set default palette tints
    pal = app.palette()
    pal.setColor(QPalette.Window, QColor(LIGHT_BG))
    pal.setColor(QPalette.WindowText, QColor("#3d1a4f"))
    app.setPalette(pal)

    win = BrainLock()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
