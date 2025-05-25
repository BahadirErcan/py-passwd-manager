import random
import sqlite3
import re
import sys
try:
    import pyperclip
except ImportError:
    pyperclip = None

from cryptography.fernet import Fernet

# Şifreleme anahtarı
key = b'1vLzdP1hvR8sSHFcpELoyq9HnuUL4_clqD2CEfJF6oY='
fernet = Fernet(key)

randpasschrctrs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890:;!?@_-()"

def init_db():
    conn = sqlite3.connect('sifreler.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS sifreler (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hesap_adi TEXT UNIQUE,
            sifre TEXT
        )
    ''')
    conn.commit()
    return conn

def sifrele(sifre):
    return fernet.encrypt(sifre.encode()).decode()

def sifre_coz(sifre_crypted):
    return fernet.decrypt(sifre_crypted.encode()).decode()

def sifre_kaydet(conn, hesap_adi, sifre):
    if not sifre_gucluk_kontrol(sifre):
        print("UYARI: Şifreniz zayıf! Güçlü bir şifre seçmeniz önerilir.")
    c = conn.cursor()
    sifre_enc = sifrele(sifre)
    try:
        c.execute('INSERT INTO sifreler (hesap_adi, sifre) VALUES (?, ?)', (hesap_adi, sifre_enc))
        conn.commit()
        print("Şifreniz kaydedildi!")
    except sqlite3.IntegrityError:
        print(f"'{hesap_adi}' hesabı zaten kayıtlı. Güncellemek için güncelleme seçeneğini kullanın.")

def sifreleri_goster(conn):
    c = conn.cursor()
    c.execute('SELECT hesap_adi, sifre FROM sifreler')
    kayitlar = c.fetchall()
    if not kayitlar:
        print("Kaydedilmiş şifre bulunamadı.")
        return
    print("Kaydedilen Şifreler:")
    for hesap_adi, sifre_enc in kayitlar:
        try:
            sifre = sifre_coz(sifre_enc)
        except Exception:
            sifre = "<Şifre çözme hatası>"
        print(f"{hesap_adi} : {sifre}")
    if pyperclip:
        secim = input("Şifreleri panoya kopyalamak için hesap adı girin (veya Enter ile geç): ").strip()
        if secim:
            sifre = sifre_getir(conn, secim)
            if sifre is not None:
                pyperclip.copy(sifre)
                print(f"'{secim}' hesabının şifresi panoya kopyalandı.")
            else:
                print(f"'{secim}' adlı hesap bulunamadı.")
    else:
        print("Not: pyperclip modülü yüklü değil, panoya kopyalama özelliği kullanılamıyor.")

def sifre_getir(conn, hesap_adi):
    c = conn.cursor()
    c.execute('SELECT sifre FROM sifreler WHERE hesap_adi=?', (hesap_adi,))
    kayit = c.fetchone()
    if kayit:
        try:
            return sifre_coz(kayit[0])
        except Exception:
            return None
    else:
        return None

def sifre_uret(length):
    if length > len(randpasschrctrs):
        print(f"En fazla {len(randpasschrctrs)} karakter seçebilirsiniz. Varsayılan uzunluk 12 olarak ayarlandı.")
        length = 12
    sifre = "".join(random.sample(randpasschrctrs, length))
    print(f"Oluşturulan şifre: {sifre}")
    if pyperclip:
        pyperclip.copy(sifre)
        print("Şifre panoya kopyalandı.")
    return sifre

def sifre_sil(conn, hesap_adi):
    c = conn.cursor()
    c.execute('SELECT * FROM sifreler WHERE hesap_adi = ?', (hesap_adi,))
    if c.fetchone() is None:
        print(f"'{hesap_adi}' adlı hesap bulunamadı.")
        return
    confirm = input(f"'{hesap_adi}' hesabını silmek istediğinize emin misiniz? (E/H): ").strip().lower()
    if confirm == 'e':
        c.execute('DELETE FROM sifreler WHERE hesap_adi = ?', (hesap_adi,))
        conn.commit()
        print(f"'{hesap_adi}' hesabı silindi.")
    else:
        print("Silme işlemi iptal edildi.")

def sifre_guncelle(conn, hesap_adi, yeni_sifre):
    if not sifre_gucluk_kontrol(yeni_sifre):
        print("UYARI: Yeni şifreniz zayıf! Güçlü bir şifre seçmeniz önerilir.")
    c = conn.cursor()
    c.execute('SELECT * FROM sifreler WHERE hesap_adi = ?', (hesap_adi,))
    if c.fetchone() is None:
        print(f"'{hesap_adi}' adlı hesap bulunamadı.")
        return
    sifre_enc = sifrele(yeni_sifre)
    c.execute('UPDATE sifreler SET sifre = ? WHERE hesap_adi = ?', (sifre_enc, hesap_adi))
    conn.commit()
    print(f"'{hesap_adi}' hesabının şifresi güncellendi.")

def sifre_gucluk_kontrol(sifre):
    if len(sifre) < 8:
        return False
    if not re.search(r'[A-Z]', sifre):
        return False
    if not re.search(r'[a-z]', sifre):
        return False
    if not re.search(r'[0-9]', sifre):
        return False
    if not re.search(r'[!@#\$%\^&\*\(\)_\-\+=\[\]\{\};:\'",<>\./\?\\\|]', sifre):
        return False
    return True

def sifre_ara(conn, aranan):
    c = conn.cursor()
    c.execute("SELECT hesap_adi FROM sifreler WHERE hesap_adi LIKE ?", ('%'+aranan+'%',))
    sonuçlar = c.fetchall()
    if not sonuçlar:
        print("Aramanıza uygun hesap bulunamadı.")
        return []
    print("Arama sonuçları:")
    for i, (hesap_adi,) in enumerate(sonuçlar, 1):
        print(f"{i}. {hesap_adi}")
    return [hesap_adi for (hesap_adi,) in sonuçlar]

def sifre_dışa_aktar(conn, dosya_adi):
    c = conn.cursor()
    c.execute('SELECT hesap_adi, sifre FROM sifreler')
    tüm_kayitlar = c.fetchall()
    if not tüm_kayitlar:
        print("Dışa aktarılacak şifre bulunamadı.")
        return
    with open(dosya_adi, 'w', encoding='utf-8') as f:
        for hesap_adi, sifre_enc in tüm_kayitlar:
            f.write(f"{hesap_adi}:{sifre_enc}\n")
    print(f"Tüm şifreler '{dosya_adi}' dosyasına dışa aktarıldı.")

def sifre_içe_aktar(conn, dosya_adi):
    try:
        with open(dosya_adi, 'r', encoding='utf-8') as f:
            satirlar = f.readlines()
    except FileNotFoundError:
        print(f"'{dosya_adi}' dosyası bulunamadı.")
        return
    c = conn.cursor()
    eklenen = 0
    for satir in satirlar:
        if ':' not in satir:
            continue
        hesap_adi, sifre_enc = satir.strip().split(':', 1)
        c.execute('SELECT * FROM sifreler WHERE hesap_adi = ?', (hesap_adi,))
        if c.fetchone():
            continue 
        c.execute('INSERT INTO sifreler (hesap_adi, sifre) VALUES (?, ?)', (hesap_adi, sifre_enc))
        eklenen += 1
    conn.commit()
    print(f"{eklenen} adet şifre veritabanına aktarıldı.")

def main():
    conn = init_db()
    while True:
        print("""
[1] Şifre kaydet
[2] Şifre üret ve kaydet
[3] Kaydedilen şifreleri göster
[4] Şifre sil
[5] Şifre güncelle
[6] Şifre ara
[7] Şifreleri dışa aktar
[8] Şifreleri içe aktar
[0] Çıkış
""")
        try:
            islem = int(input("İşlemi girin: "))
        except ValueError:
            print("Lütfen geçerli bir sayı girin.")
            continue

        if islem == 1:
            hesap_adi = input("Hesap adı: ")
            sifre = input("Şifre: ")
            sifre_kaydet(conn, hesap_adi, sifre)

        elif islem == 2:
            hesap_adi = input("Hesap adı: ")
            try:
                length = int(input(f"Şifre uzunluğu (en fazla {len(randpasschrctrs)}): "))
            except ValueError:
                print("Geçerli bir sayı girin. Varsayılan uzunluk 12 alınacak.")
                length = 12
            sifre = sifre_uret(length)
            sifre_kaydet(conn, hesap_adi, sifre)

        elif islem == 3:
            sifreleri_goster(conn)

        elif islem == 4:
            hesap_adi = input("Silinecek hesap adı: ")
            sifre_sil(conn, hesap_adi)

        elif islem == 5:
            hesap_adi = input("Güncellenecek hesap adı: ")
            yeni_sifre = input("Yeni şifre: ")
            sifre_guncelle(conn, hesap_adi, yeni_sifre)

        elif islem == 6:
            aranan = input("Arama terimi (hesap adı içinde): ").strip()
            sifre_ara(conn, aranan)

        elif islem == 7:
            dosya_adi = input("Dışa aktarılacak dosya adı (örn: backup.txt): ").strip()
            sifre_dışa_aktar(conn, dosya_adi)

        elif islem == 8:
            dosya_adi = input("İçe aktarılacak dosya adı (örn: backup.txt): ").strip()
            sifre_içe_aktar(conn, dosya_adi)

        elif islem == 0:
            print("Çıkılıyor...")
            break

        else:
            print("Geçersiz işlem seçimi.")

    conn.close()

if __name__ == '__main__':
    main()