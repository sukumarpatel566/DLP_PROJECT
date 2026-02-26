# Intelligent Web-Based DLP System

A comprehensive Data Loss Prevention (DLP) system with AI-based anomaly detection, AES encryption, and a modern React dashboard.

## 🚀 Key Features
- **Intelligent Scanning**: Detects Credit Cards, Aadhaar, PAN, API Keys, Passwords, etc.
- **Support**: PDF, DOCX, and Text file scanning.
- **Secure Storage**: Files are AES-encrypted before being saved to disk.
- **RBAC**: Administrative and User roles with JWT authentication.
- **Anomaly Detection**: Tracks suspicious behavior (upload frequency, file sizes, failed logins).
- **Analytics Dashboard**: Visual charts for security audits and activity monitoring.

## 🛠️ Tech Stack
- **Frontend**: React.js, Vite, Recharts, Lucide Icons, React-Toastify.
- **Backend**: Python Flask, SQLAlchemy, JWT, Cryptography, Scikit-learn (pre-requisite for services).
- **Database**: MySQL.

---

## ⚙️ Setup Instructions

### 1. Database Setup
1. Ensure MySQL is installed and running.
2. Execute the `database/schema.sql` to create the database and tables.

### 2. Backend Setup
1. Navigate to the `backend` folder.
2. Create a `.env` file from `.env.example`:
   ```bash
   cp .env.example .env
   ```
3. Update `DATABASE_URL` with your MySQL credentials in `.env`.
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Run the server:
   ```bash
   python app.py
   ```

### 3. Frontend Setup
1. Navigate to the `frontend` folder.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev
   ```
4. Access the app at `http://localhost:3000`.

---

## 🛡️ Security Note
- Default password hashing is done via `bcrypt`.
- All uploads are stored in `backend/uploads` in encrypted format.
- To view logs or analytics, register a user with the **Admin** role during registration.

### Generating a Secure AES Key
If you see a Fernet key error, generate a valid key using this command:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Copy the output and paste it into your `backend/.env` file as `AES_KEY`.
