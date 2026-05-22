# 🔐 BrainLock

A beautiful, modern desktop authentication app built with PyQt5.

## ✨ Features
- Secure registration with bcrypt-hashed passwords & security answers
- Stylish login with "Forgot Password?" flow
- 3-step password recovery via security questions
- Aesthetic pink + purple gradient UI

## 🛠 Installation

```bash

python -m venv venv
source venv/bin/activate  

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python brainlock.py
```

## 🗂 File Structure
```
brainlock/
├── brainlock.py      # Main application (all-in-one)
├── requirements.txt  # Python dependencies
└── brainlock.db      # Auto-created SQLite database on first run
```

## 🔐 Security Notes
- Passwords are hashed with bcrypt (work factor 12)
- Security answers are also bcrypt-hashed before storage
- All comparisons use constant-time `checkpw` to prevent timing attacks
- No plain-text secrets are ever written to disk
