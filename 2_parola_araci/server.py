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
GENDERICI_MAIL = "samiortakaya63@gmail.com"
GENDERICI_SIFRE = "kfvw exzo dvxq ogzf" 
# ---------------------------------------------------------

# Geçici OTP (Doğrulama kodları) hafızası
pending_otps = {}

# Veritabanını (SQLite) Başlatma
def init_db():
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

# --- 1. ADIM: OTP TALEBİ ---
@app.route('/send_otp', methods=['POST'])
def handle_send_otp():
    data = request.json
    email = data.get('email')
    
    # Kullanıcı zaten var mı kontrol et
    conn = sqlite3.connect('siber_kasa.db')
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE email=?", (email,))
    if cursor.fetchone():
        return jsonify({"success": False, "message": "Bu e-posta zaten kayıtlı!"})
    
    # 6 haneli kod üret
    otp = str(random.randint(100000, 999999))
    pending_otps[email] = otp
    
    # Gerçek Maili Gönder (Şifre girildiyse çalışır)
    if GENDERICI_SIFRE != "uygulama_sifren_buraya_gelecek":
        mail_gitti_mi = send_email(email, otp)
        if not mail_gitti_mi:
            return jsonify({"success": False, "message": "Mail gönderilirken hata oluştu. Lütfen server.py'deki mail şifrenizi kontrol edin."})
    
    # Geliştirme aşamasında terminale de basalım görelim
    print(f"\n[SISTEM UYARISI] {email} adresine gonderilen kod: {otp}\n")
    
    return jsonify({"success": True, "message": "Doğrulama kodu gönderildi!"})

# --- 2. ADIM: KAYIT OLMA (OTP DOĞRULAYIP VERİTABANINA YAZMA) ---
@app.route('/register', methods=['POST'])
def handle_register():
    data = request.json
    email = data.get('email')
    pwd = data.get('password')
    otp_input = data.get('otp')
    
    # Kod doğru mu?
    if pending_otps.get(email) != otp_input:
        return jsonify({"success": False, "message": "Hatalı doğrulama kodu!"})
    
    # Kod doğruysa arka planda şifreyi Hashle (SHA-256)
    hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()
    
    # Veritabanına kaydet
    conn = sqlite3.connect('siber_kasa.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, password_hash, encrypted_vault) VALUES (?, ?, ?)", 
                   (email, hashed_pwd, "")) # İlk başta kasa boş
    conn.commit()
    conn.close()
    
    # Geçici hafızadan sil
    del pending_otps[email]
    
    return jsonify({"success": True, "message": "Kayıt başarılı!"})

# --- 3. ADIM: GİRİŞ YAPMA ---
@app.route('/login', methods=['POST'])
def handle_login():
    data = request.json
    email = data.get('email')
    pwd = data.get('password')
    
    hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()
    
    conn = sqlite3.connect('siber_kasa.db')
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_vault FROM users WHERE email=? AND password_hash=?", (email, hashed_pwd))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"success": True, "encrypted_vault": user[0]})
    else:
        return jsonify({"success": False, "message": "E-Posta veya Şifre yanlış!"})

# --- 4. ADIM: KASAYI GÜNCELLEME ---
@app.route('/save_vault', methods=['POST'])
def handle_save_vault():
    data = request.json
    email = data.get('email')
    encrypted_vault = data.get('encrypted_vault')
    
    conn = sqlite3.connect('siber_kasa.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET encrypted_vault=? WHERE email=?", (encrypted_vault, email))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

if __name__ == '__main__':
    print("\n" + "="*50)
    print(" SIBER KASA SUNUCUSU BASLATILDI (PORT: 5000)")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)

