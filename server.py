from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
import random
import hashlib
import os

app = Flask(__name__)
# CORS, farklı portlardan (HTML dosyamızdan) gelen isteklere izin verir
CORS(app)

# ---------------------------------------------------------
# BURAYA KENDİ MAİL BİLGİLERİNİ GİRMELİSİN
# Gmail kullanıyorsan "Uygulama Şifresi" oluşturman gerekir!
# ---------------------------------------------------------
GENDERICI_MAIL = os.getenv("MAIL_USER", "samiortakaya63@gmail.com")
GENDERICI_SIFRE = os.getenv("MAIL_PASS", "kfvw exzo dvxq ogzf")
# ---------------------------------------------------------

# Geçici OTP (Doğrulama kodları) hafızası
pending_otps = {}

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

def get_db():
    if DATABASE_URL:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        return conn, '%s'
    else:
        conn = sqlite3.connect('siber_kasa.db')
        return conn, '?'

# Veritabanını Başlatma
def init_db():
    try:
        conn, ph = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT,
                encrypted_vault TEXT
            )
        ''')
        conn.commit()
        conn.close()
        print("Veritabani basariyla hazirlandi.")
    except Exception as e:
        print(f"Veritabani baslatma hatasi: {e}")
        if not DATABASE_URL:
            try:
                if os.path.exists('siber_kasa.db'):
                    os.remove('siber_kasa.db')
                conn = sqlite3.connect('siber_kasa.db')
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        email TEXT PRIMARY KEY,
                        password_hash TEXT,
                        encrypted_vault TEXT
                    )
                ''')
                conn.commit()
                conn.close()
            except Exception as inner_e:
                print(f"SQLite onarim hatasi: {inner_e}")

init_db()

# --- E-POSTA GÖNDERME FONKSİYONU ---
def send_email(alici_mail, otp_kodu):
    try:
        subject = "Siber Kasa - Doğrulama Kodunuz"
        body = f"Kayıt işlemini tamamlamak için doğrulama kodunuz: {otp_kodu}\n\nBu kodu kimseyle paylaşmayın."
        
        msg = MIMEMultipart()
        msg['From'] = GENDERICI_MAIL
        msg['To'] = alici_mail
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Gmail SMTP Sunucusuna bağlan
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls() # Güvenli bağlantı başlat
        server.login(GENDERICI_MAIL, GENDERICI_SIFRE)
        
        # Maili Gönder
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Mail gonderme hatasi:", e)
        return False

# --- 0. ADIM: SİTEYİ YAYINLAMA (HOSTING) ---
@app.route('/')
def serve_index():
    # Bu klasördeki index.html dosyasını ekrana basar
    return send_from_directory('.', 'index.html')

@app.route('/health')
def health_check():
    return jsonify({"status": "ok", "service": "siberkasa", "version": "2.0"}), 200

# --- 1. ADIM: KAYIT OLMA ---
@app.route('/register', methods=['POST'])
def handle_register():
    data = request.json or {}
    email = data.get('email')
    pwd = data.get('password')
    
    if not email or not pwd:
        return jsonify({"success": False, "message": "E-posta ve şifre gereklidir."}), 400

    try:
        conn, ph = get_db()
        cursor = conn.cursor()
        cursor.execute(f"SELECT email FROM users WHERE email={ph}", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Bu e-posta zaten kayıtlı!"})
        
        # Şifreyi Hashle (SHA-256)
        hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()
        
        # Veritabanına kaydet
        cursor.execute(f"INSERT INTO users (email, password_hash, encrypted_vault) VALUES ({ph}, {ph}, {ph})", 
                       (email, hashed_pwd, "")) # İlk başta kasa boş
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Kayıt başarılı!"})
    except Exception as e:
        print("Kayit hatasi:", e)
        return jsonify({"success": False, "message": f"Sunucu hatası: {str(e)}"}), 500

# --- 3. ADIM: GİRİŞ YAPMA ---
@app.route('/login', methods=['POST'])
def handle_login():
    data = request.json or {}
    email = data.get('email')
    pwd = data.get('password')
    
    if not email or not pwd:
        return jsonify({"success": False, "message": "E-posta ve şifre gereklidir."}), 400

    hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()
    
    try:
        conn, ph = get_db()
        cursor = conn.cursor()
        cursor.execute(f"SELECT encrypted_vault FROM users WHERE email={ph} AND password_hash={ph}", (email, hashed_pwd))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return jsonify({"success": True, "encrypted_vault": user[0]})
        else:
            return jsonify({"success": False, "message": "E-Posta veya Şifre yanlış!"})
    except Exception as e:
        print("Giris hatasi:", e)
        return jsonify({"success": False, "message": f"Sunucu hatası: {str(e)}"}), 500

# --- 4. ADIM: KASAYI GÜNCELLEME ---
@app.route('/save_vault', methods=['POST'])
def handle_save_vault():
    data = request.json or {}
    email = data.get('email')
    encrypted_vault = data.get('encrypted_vault')
    
    if not email:
        return jsonify({"success": False, "message": "Geçersiz istek"}), 400

    try:
        conn, ph = get_db()
        cursor = conn.cursor()
        cursor.execute(f"UPDATE users SET encrypted_vault={ph} WHERE email={ph}", (encrypted_vault, email))
        conn.commit()
        conn.close()
        
        return jsonify({"success": True})
    except Exception as e:
        print("Kasa kayit hatasi:", e)
        return jsonify({"success": False, "message": f"Sunucu hatası: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "="*50)
    print(f" SIBER KASA SUNUCUSU BASLATILDI (PORT: {port})")
    print(f" Yerel Ağ / Sunucu Erişimi: http://0.0.0.0:{port}")
    print("="*50 + "\n")
    app.run(debug=True, host='0.0.0.0', port=port)
