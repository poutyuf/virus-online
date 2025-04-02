# -*- coding: utf-8 -*-

# --- Gerekli Modüllerin Kontrolü ve Otomatik Kurulumu ---
import sys
import subprocess
import importlib.util
import os
import time
import json
import re  # Regex için gerekli
import traceback

print(">>> Gerekli kütüphaneler kontrol ediliyor...")
required_packages = {
    'requests': 'requests',
    'telebot': 'pyTelegramBotAPI'
}
packages_installed_successfully = True

for import_name, package_name in required_packages.items():
    spec = importlib.util.find_spec(import_name)
    if spec is None:
        print(f"--- Uyarı: '{import_name}' ({package_name}) kütüphanesi bulunamadı.")
        print(f"--- Otomatik olarak kuruluyor: pip install {package_name}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
            print(f"--- '{package_name}' başarıyla kuruldu.")
        except subprocess.CalledProcessError as e:
            print(f"!!! Hata: '{package_name}' kurulurken sorun oluştu: {e.returncode}")
            print(f"!!! Lütfen manuel olarak kurmayı deneyin: pip install {package_name}")
            packages_installed_successfully = False
        except Exception as e:
            print(f"!!! Hata: '{package_name}' kurulurken beklenmedik bir sorun: {e}")
            packages_installed_successfully = False

if not packages_installed_successfully:
    print("\n!!! Gerekli kütüphaneler kurulamadığı için program sonlandırılıyor.")
    exit(1)

print(">>> Kütüphane kontrolü tamamlandı.\n")
# --- Kontrol ve Kurulum Bitti ---

import telebot
import requests

# --- SABİT BAŞLIK VE GELİŞTİRİCİ BİLGİSİ ---
print("="*35)
print("      #kartsikenpoutyuf") # Hashtag isteğe göre değiştirilebilir
print("      Geliştirici: @pouyuf")
print("="*35 + "\n")
# --- BİTİŞ ---

# --- Yapılandırma Girişleri ---
# UYARI: Sunucuda input() yerine ortam değişkeni (os.environ.get) kullan!
print("Lütfen Telegram Bot Token'ınızı girin:")
BOT_TOKEN = input("Bot Token: ").strip()
if not BOT_TOKEN:
    print("Hata: Bot Token girilmedi."); exit(1)

print("\nLütfen botun admin Telegram Kullanıcı ID'sini girin (Sayısal ID):")
ADMIN_ID_STR = input("Admin Kullanıcı ID: ").strip()
try:
    ADMIN_ID = int(ADMIN_ID_STR)
except ValueError:
    print("Hata: Geçersiz Kullanıcı ID'si. Sadece rakamlardan oluşmalı."); exit(1)
# --- API URL VE DİĞER YAPILANDIRMA BİLGİLERİ ---
XCHECKER_API_URL = "https://xchecker.cc/api.php" # API URL'si değişirse buradan güncelleyin
print("\n" + "-"*35)
print("      BOT AYARLARI")
print("-" * 35)
print(f" Admin ID           : {ADMIN_ID}")
# print(f" Admin Kart Limiti  : SINIRSIZ") # Bilgi amaçlı kaldırıldı, kontrol mekanizması güncellendi
print(f" Normal K. Limiti   : 1")
print(f" API Endpoint       : {XCHECKER_API_URL}")
print(f" API Anahtarı Durumu: KULLANILMIYOR") # API anahtarı gerekiyorsa kodda düzenleme yapılmalı
print(f" SSL Doğrulaması    : AKTİF") # requests içinde verify=True varsayılan, değiştirmek için requests.get(..., verify=False)
print("-" * 35)
# --- BİTİŞ ---

# --- Telegram Bot Başlatma ---
print("\n>>> Telegram Botu Başlatılıyor...")
try:
    # Varsayılan parse_mode='MarkdownV2' olarak değiştirmek daha güvenli olabilir
    # Ancak mevcut kod Markdown'a göre yazıldığı için şimdilik böyle bırakıyoruz.
    # Gerekirse 'MarkdownV2' yapıp escape_markdown fonksiyonunu ona göre güncelleyin.
    bot = telebot.TeleBot(BOT_TOKEN, parse_mode='Markdown')
    bot_info = bot.get_me()
    print(f">>> Telegram Bot Token doğrulandı: @{bot_info.username}")
    print(">>> Bot başarıyla bağlandı ve komutları dinliyor...")
except telebot.apihelper.ApiTelegramException as e:
    print(f"!!! Hata: Telegram API'ye bağlanılamadı. Token geçersiz veya ağ sorunu olabilir: {e}")
    exit(1)
except Exception as e:
    print(f"!!! Bot başlatılırken beklenmedik bir hata oluştu: {e}")
    traceback.print_exc(); exit(1)

# --- YARDIMCI FONKSİYONLAR ---

def escape_markdown(text):
    """
    Metin içindeki potansiyel Markdown (V1) özel karakterlerinden kaçınır.
    Not: MarkdownV2 daha fazla karakter gerektirir.
    """
    if not isinstance(text, str): # Gelen veri string değilse string'e çevir
        text = str(text)
    # Markdown V1 için genellikle kaçınılması gerekenler: _, *, `, [
    escape_chars = r'_*`['
    # Karakterlerin başına backslash ekle
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', text)

# --- API Çağrısı için Yardımcı Fonksiyon ---
def check_card(cc, mes, ano, cvv):
    api_status = "⚠️ Bilinmiyor"
    raw_response_data = "Yanıt alınamadı"
    try:
        expYear = str(ano)
        # Yıl formatını kontrol et ve YY formatına çevir
        if len(expYear) == 4:
            if expYear.startswith("20") and expYear[2:].isdigit() and int(expYear) >= 2000:
                 expYear = expYear[-2:]
            else:
                return {'success': False, 'status': "❌ Geçersiz Yıl (YYYY formatı hatalı)", 'raw_response': "Yıl 20xx formatında ve geçerli bir yıl olmalı."}
        elif len(expYear) == 2 and expYear.isdigit():
            # YY formatı zaten uygun, bir şey yapmaya gerek yok
             pass
        else:
            return {'success': False, 'status': "❌ Geçersiz Yıl Formatı", 'raw_response': "Yıl YY veya 20YY formatında olmalı."}

        # API'ye gönderilecek format: KKNO|AA|YY|CVV
        cc_data_string = f'{cc}|{mes}|{expYear}|{cvv}'
        params = {'cc': cc_data_string}
        # Tarayıcı gibi görünmek için User-Agent ekleniyor
        headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36' } # User Agent güncellendi
        # API isteği (timeout süresi eklendi)
        response = requests.get(XCHECKER_API_URL, params=params, headers=headers, timeout=40) # Timeout artırıldı
        raw_response_data = response.text # Ham yanıtı sakla (hata ayıklama için)
        response.raise_for_status() # HTTP hata kodları için (4xx, 5xx) exception fırlat

        # --- Yanıt İşleme ---
        try:
            data = response.json() # Yanıtı JSON olarak parse etmeye çalış
            raw_response_data = json.dumps(data, indent=2, ensure_ascii=False) # JSON'ı formatlı sakla
            api_status_key = data.get("status", "").strip().lower() # Durum bilgisini al, küçük harfe çevir
            error_key = data.get("error") # Hata mesajı var mı?
            message_key = data.get("message", "") # API'den gelen ek mesaj (bazı API'lerde olabilir)
            details = data.get("details", message_key or "N/A") # Detayları al, yoksa message'ı kullan, o da yoksa N/A

            if error_key: # Eğer API direkt bir hata mesajı döndürdüyse
                # Hata mesajını da escape etmek iyi olabilir
                api_status = f"⚠️ API Hatası: {escape_markdown(error_key)}"
                return {'success': False, 'status': api_status, 'raw_response': raw_response_data}

            # Başarılı durumlar
            elif api_status_key in ["success", "live", "approved", "charge", "charged"]:
                bank_name = data.get("bankName", data.get("bank", "N/A")) # Banka adını al (farklı key'ler olabilir)
                # Hem banka adını hem de detayları escape et
                api_status = f"✅ Live | Banka: {escape_markdown(bank_name)} | Detay: {escape_markdown(details)}"
                return {'success': True, 'status': api_status, 'raw_response': raw_response_data}

            # Başarısız (Ölü) durumlar
            elif api_status_key in ["dead", "declined", "incorrect_cvc", "insufficient_funds", "pickup_card", "stolen_card", "lost_card", "expired_card", "error", "failed"]:
                 # Hem sebebi hem de detayları escape et
                 safe_reason = escape_markdown(api_status_key.replace('_',' ').title())
                 safe_details = escape_markdown(details)
                 api_status = f"❌ Dead | Sebep: {safe_reason} | Detay: {safe_details}"
                 return {'success': False, 'status': api_status, 'raw_response': raw_response_data}

            # Bilinmeyen durumlar
            else:
                # Durumu ve detayları escape et
                 safe_status_key = escape_markdown(api_status_key)
                 safe_details = escape_markdown(details)
                 if details != "N/A":
                     api_status = f"❓ Yanıt Anlaşılamadı | API Durum='{safe_status_key}' | Detay='{safe_details}'"
                 else:
                     api_status = f"❓ Yanıt Anlaşılamadı (JSON) | API Durum='{safe_status_key}'"
                 return {'success': False, 'status': api_status, 'raw_response': raw_response_data}

        # JSON parse hatası
        except json.JSONDecodeError:
            return {'success': False, 'status': "⚠️ API Yanıt Formatı Hatalı (JSON Değil)", 'raw_response': raw_response_data}

    # İstek zaman aşımı
    except requests.exceptions.Timeout:
        return {'success': False, 'status': "⏳ API Zaman Aşımı (Sunucu Yanıt Vermedi)", 'raw_response': "Timeout"}
    # HTTP Hataları (401, 403, 404, 429, 5xx vb.)
    except requests.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code
        if status_code in [401, 403]: api_status = "🔒 API Yetki Hatası (Token/Key Gerekli veya Yanlış?)"
        elif status_code == 404: api_status = "❓ API Yolu Bulunamadı (URL Yanlış?)"
        elif status_code == 429: api_status = "⏳ API Rate Limit Aşıldı (Çok Fazla İstek)"
        else: api_status = f"🌐 API Sunucu Hatası (Kod: {status_code})"
        return {'success': False, 'status': api_status, 'raw_response': raw_response_data}
    # Diğer ağ/bağlantı hataları
    except requests.exceptions.RequestException as req_err:
        print(f"Ağ Hatası: {req_err}") # Konsola detaylı yazdır
        return {'success': False, 'status': f"🔌 Ağ/Bağlantı Hatası ({type(req_err).__name__})", 'raw_response': str(req_err)}
    # Kod içindeki beklenmedik diğer hatalar
    except Exception as e:
        print(f"check_card içinde beklenmedik hata: {e}")
        traceback.print_exc() # Hatanın tam izini konsola yazdır
        return {'success': False, 'status': f"⚙️ İç Sistem Hatası ({type(e).__name__})", 'raw_response': str(e)}

# --- Telegram Bot İşleyicileri ---

# /start ve /help komutları için
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    user_id = message.from_user.id
    is_admin = (user_id == ADMIN_ID)
    # Admin için limit belirtilmiyor, normal kullanıcı için 1
    limit_text = "sınırsız sayıda" if is_admin else "1 kartı"
    help_text = (
        f"👋 Hoş Geldiniz {escape_markdown(message.from_user.first_name)}!\n\n" # Kullanıcı adını da escape et
        f"Bu bot ile kredi kartı bilgilerini kontrol edebilirsiniz.\n"
        f"Adminler `{limit_text}`, normal kullanıcılar `{limit_text}` kontrol edebilir.\n\n"
        f"ℹ️ Kullanılabilir komutlar için `/cmds` yazın.\n\n"
        f"**Kart Kontrol Formatı:**\n`/check KKNO|AA|YY|CVV`\n*veya*\n`/check KKNO|AA|YYYY|CVV`\n\n"
        f"➡️ Yıl `YY` (örn: 25) veya `YYYY` (örn: 2025) formatında olabilir.\n"
        f"➡️ Komutlar: `/check`, `/chk`, `/kontrol`\n\n"
        f"**Adminler İçin Çoklu Kart Kontrolü:**\n"
        f"`/check` (veya `/chk`, `/kontrol`)\n"
        f"`KART1|AA|YY|CVV`\n"
        f"`KART2|AA|YY|CVV`\n"
        f"`...`\n\n"
        f"**Geliştirici:** @pouyuf\n" # Kullanıcı adları genellikle sorun çıkarmaz
        f"**⚠️ Uyarı:** Lütfen botu yasal amaçlarla kullanın. Sorumluluk size aittir."
    )
    try:
        # Markdown formatında gönder
        bot.reply_to(message, help_text, parse_mode='Markdown')
    except Exception as e:
        print(f"Welcome/Help mesajı gönderilirken hata oluştu: {e}")
        try: # Fallback: Normal metin olarak göndermeyi dene
             bot.reply_to(message, help_text, parse_mode=None)
        except: pass # Bu da başarısız olursa yapacak bir şey yok

# /cmds komutu için
@bot.message_handler(commands=['cmds'])
def send_commands_list(message):
    # Bu metin sabit olduğu için genellikle escape gerekmez, ancak emin olmak için yapılabilir.
    commands_text = (
        "🤖 **Kullanılabilir Komutlar:**\n\n"
        "🔹 `/start`, `/help`\n"
        "   - Botu başlatır ve bu yardım mesajını gösterir.\n\n"
        "🔹 `/check`, `/chk`, `/kontrol`\n"
        "   - Belirtilen formattaki kredi kartı/kartlarını kontrol eder.\n"
        "   - *Format:* `KKNO|AA|YY|CVV` veya `KKNO|AA|YYYY|CVV`\n"
        "   - *Adminler:* Komuttan sonra alt alta birden fazla kart girebilir.\n\n"
        "🔹 `/cmds`\n"
        "   - Bu komut listesini gösterir.\n\n"
        "**Geliştirici:** @pouyuf"
    )
    try:
        bot.reply_to(message, commands_text, parse_mode='Markdown')
    except Exception as e:
        print(f"Komut listesi gönderilirken hata: {e}")
        try:
            bot.reply_to(message, commands_text, parse_mode=None)
        except: pass

# /check, /chk, /kontrol komutları için
@bot.message_handler(commands=['check', 'chk', 'kontrol'])
def handle_check_command(message):
    chat_id = message.chat.id
    user_id = message.from_user.id
    is_admin = (user_id == ADMIN_ID)
    # Normal kullanıcılar için limit 1, adminler için limit kontrolü yapılmayacak
    max_cards_user = 1

    # Kart formatını kontrol etmek için Regex Deseni:
    # 13-19 haneli kart numarası
    # 01-12 ay
    # YY veya 20YY yıl formatı (2000 ve sonrası)
    # 3 veya 4 haneli CVV
    pattern = re.compile(r'^(\d{13,19})\|(0[1-9]|1[0-2])\|(\d{2}|20\d{2})\|(\d{3,4})$')

    # Komutu ve argümanları ayır
    command_parts = message.text.split(' ', 1)
    # Argüman kısmını al, yoksa boş string
    input_text = command_parts[1].strip() if len(command_parts) > 1 else ""

    cards_to_process_raw = []

    # Kullanıcı admin ise ve input_text boşsa (örn: sadece /check yazdıysa)
    # VEYA admin ise ve input_text içinde newline varsa (alt alta kart girdiyse)
    if is_admin and (not input_text or '\n' in input_text):
        # Eğer sadece komut yazıldıysa (input_text boşsa), cevap bekle
        if not input_text and message.reply_to_message is None:
             lines = message.text.split('\n')[1:] # İlk satır komut, sonrakiler kartlar
             cards_to_process_raw = [l.strip() for l in lines if l.strip()]
        # Eğer komutla birlikte kartlar da yazıldıysa
        elif input_text:
             lines = input_text.split('\n')
             cards_to_process_raw = [l.strip() for l in lines if l.strip()]

        # Admin kart girmediyse uyar
        if not cards_to_process_raw:
            return bot.reply_to(message, "Admin: Lütfen `/check` komutundan sonraki satırlara kontrol edilecek kartları `KKNO|AA|YY|CVV` formatında girin.")

    # Kullanıcı normal ise veya admin tek satırda kart girdiyse
    else:
        # Normal kullanıcı birden fazla satır girmeye çalışırsa hata ver
        if not is_admin and '\n' in input_text:
            return bot.reply_to(message, "Hata: Normal kullanıcılar tek seferde sadece 1 kart kontrol edebilir.\nFormat: `/check KKNO|AA|YY|CVV`", parse_mode='Markdown')
        # Tek satır girdisi varsa listeye ekle
        if input_text:
            cards_to_process_raw = [input_text]
        # Hiçbir şey girilmediyse formatı hatırlat
        else:
             return bot.reply_to(message,"Lütfen kontrol edilecek kartı belirtin.\nFormat: `/check KKNO|AA|YY|CVV`", parse_mode='Markdown')

    # Normal kullanıcı limit kontrolü
    if not is_admin and len(cards_to_process_raw) > max_cards_user:
        return bot.reply_to(message, f"Hata: Tek seferde en fazla {max_cards_user} kart kontrol edebilirsiniz. ({len(cards_to_process_raw)} adet gönderildi).")
    # Adminler için bir üst sınır koymak isterseniz (örneğin 1000) buraya ekleyebilirsiniz:
    # elif is_admin and len(cards_to_process_raw) > 1000:
    #    return bot.reply_to(message, f"Hata: Güvenlik nedeniyle tek seferde en fazla 1000 kart kontrol edilebilir. ({len(cards_to_process_raw)} adet gönderildi).")

    # Kartları doğrula ve geçerli/geçersiz olarak ayır
    cards_to_process_data = []
    invalid_formats = []
    for line in cards_to_process_raw:
        match = pattern.match(line)
        if match:
            # Yıl formatını burada tekrar kontrol etmeye gerek yok, check_card içinde yapılıyor.
            cards_to_process_data.append(match.groups())
        else:
            # Geçersiz formatları da escape etmek iyi bir fikir olabilir
            invalid_formats.append(line)

    # İşlenecek geçerli kart yoksa hata ver
    if not cards_to_process_data:
        error_msg = "Hata: Geçerli formatta (`KKNO|AA|YY|CVV` veya `KKNO|AA|YYYY|CVV`) kart bulunamadı."
        if invalid_formats:
            # Geçersiz formatları güvenli hale getir (Markdown karakterlerinden kaçın)
            escaped_invalid = [escape_markdown(inv) for inv in invalid_formats] # Escape et
            error_msg += "\n\nGeçersiz Girdiler (İlk 5):\n" + "\n".join([f"`{inv}`" for inv in escaped_invalid[:5]])
            if len(invalid_formats) > 5: error_msg += "\n..."
        return bot.reply_to(message, error_msg, parse_mode='Markdown')

    # İşlem Başlıyor Mesajı
    processing_msg = None
    # status_msg içindeki backtickler sorun yaratmaz ama emin olmak için escape edilebilir
    safe_card_count = escape_markdown(str(len(cards_to_process_data)))
    status_msg = f"⏳ `{safe_card_count}` adet kart kontrol ediliyor..."
    if invalid_formats:
        safe_invalid_count = escape_markdown(str(len(invalid_formats)))
        status_msg += f"\n⚠️ `{safe_invalid_count}` adet geçersiz formatlı girdi göz ardı edildi."
    try:
        processing_msg = bot.reply_to(message, status_msg, parse_mode='Markdown')
    except Exception as e:
        print(f"İşlem mesajı gönderilemedi: {e}")
        # Mesaj gönderilemese de işleme devam et

    # --- Kart Kontrol Döngüsü ---
    results = []
    live_count = 0
    dead_count = 0
    error_count = 0
    start_time = time.time()
    print(f"\n--- Kontrol Başladı (Kullanıcı: {user_id}, Kart Sayısı: {len(cards_to_process_data)}) ---")

    for i, card_data in enumerate(cards_to_process_data):
        cc, mes, ano, cvv = card_data # Kart bilgilerini al
        status_str = "⚠️ Bilinmiyor" # Bu check_card içinde escape edilecek
        is_live = False
        is_dead = False

        try:
            # API'yi çağır (check_card artık escape edilmiş string döndürecek)
            check_result = check_card(cc, mes, ano, cvv)
            # Gelen sonucun sözlük ve 'status' anahtarı içerdiğini kontrol et
            if isinstance(check_result, dict) and 'status' in check_result:
                # status_str'ı doğrudan al, çünkü check_card içinde escape edildi
                status_str = check_result['status']
                if check_result.get('success', False): # 'success' anahtarı varsa ve True ise live kabul et
                    is_live = True
                # Yanıtta escape edilmiş 'dead', 'declined' gibi ifadeler varsa dead kabul et
                # Not: Bu kontrol escape nedeniyle artık tam çalışmayabilir, is_live kontrolü daha güvenilir.
                # is_dead = not is_live # Daha basit bir yaklaşım
                elif any(term in check_result['status'].lower() for term in ["dead", "declined", "error", "failed", "incorrect", "insufficient", "stolen", "lost", "expired", "pickup"]):
                     is_dead = True

            else:
                # Beklenmedik bir yanıt formatı geldiyse
                status_str = escape_markdown(f"⚠️ API Yanıt İşleme Hatası (Beklenmedik Format: {type(check_result).__name__})")
                print(f"HATA: CC {cc[-4:]} için beklenmedik API yanıtı: {check_result}")

        # Döngü içindeki spesifik hataları yakala
        except Exception as loop_err:
            print(f"HATA: CC {cc[-4:]} işlenirken döngü hatası: {loop_err}")
            traceback.print_exc()
            status_str = escape_markdown(f"⚠️ İç Döngü Hatası ({type(loop_err).__name__})")

        # Sayaçları güncelle
        if is_live: live_count += 1
        elif is_dead: dead_count +=1
        else: error_count +=1

        # --- SONUÇ FORMATLAMA ---
        # Kart detaylarını escape ETMİYORUZ çünkü `` içine alacağız.
        # Ancak KESİNLİKLE TAM KART BİLGİSİ GÖNDERMEMELİSİNİZ.
        # GÜVENLİK RİSKİ! Maskeleme yapın:
        # masked_cc = f"{cc[:4]}********{cc[-4:]}"
        # masked_cvv = "***"
        # card_details_str = f"{masked_cc}|{mes}|{ano}|{masked_cvv}"
        card_details_str = f"{cc}|{mes}|{ano}|{cvv}" # GÜVENLİK RİSKİ! ORİJİNAL BIRAKILDI!

        # status_str zaten check_card içinde escape edildiği için tekrar escape etmeye gerek yok.
        status_line = f"Durum: {status_str}" # Direkt kullan
        if not is_live and not is_dead: # Bilinmeyen durumsa soru işareti ekle
             status_line += " ❓"

        # Loglama (Orijinal status_str loglanabilir, escape edilmemiş hali)
        # Orijinal status'u almak için check_result'tan tekrar okuyabiliriz veya check_card'ı değiştirebiliriz.
        # Şimdilik loglamada escape edilmiş hali kalsın:
        print(f"  -> Kart: {card_details_str} | Sonuç: {status_str}")

        # Telegram için formatla
        # UYARI: TAM KART BİLGİSİ TELEGRAM'A GÖNDERİLİYOR!
        # card_details_str içinde Markdown karakteri OLMADIĞINDAN emin olun veya escape edin.
        # Şu anki formatta | ve rakamlar olduğu için sorun olmamalı.
        formatted_result = f"💳 `{card_details_str}`\n{status_line}"
        results.append(formatted_result)
        # --- FORMATLAMA SONU ---

        # Admin çoklu kontrol yapıyorsa ve son kart değilse kısa bir bekleme ekle (API rate limit'e takılmamak için)
        if is_admin and len(cards_to_process_data) > 1 and i < len(cards_to_process_data) - 1:
            time.sleep(0.6) # Bekleme süresi API'ye göre ayarlanabilir

    # --- Kontrol Sonu & Sonuçları Gönderme ---
    end_time = time.time()
    duration = round(end_time - start_time, 2)
    print(f"--- Kontrol Bitti ({duration} saniye) ---")

    # Özet mesajını oluştur (sayıları da escape etmek daha güvenli)
    safe_live = escape_markdown(str(live_count))
    safe_dead = escape_markdown(str(dead_count))
    safe_error = escape_markdown(str(error_count))
    summary = f"✅ Live: `{safe_live}` | ❌ Dead: `{safe_dead}` | ⚠️ Error: `{safe_error}`"
    # Final mesajını birleştir
    # Duration'ı escape etmeye gerek yok.
    final_reply = f"🏁 Kontrol Tamamlandı ({duration} saniye)\n{summary}\n\n" + "\n\n".join(results)

    # Geçersiz formatlar varsa sona ekle
    if invalid_formats:
        # invalid_formats listesindeki elemanlar yukarıda zaten escape edildi
        escaped_invalid = [escape_markdown(inv) for inv in invalid_formats] # Tekrar escape etmeye gerek yok aslında
        safe_invalid_len = escape_markdown(str(len(invalid_formats)))
        final_reply += f"\n\n--- Göz Ardı Edilenler ({safe_invalid_len}) ---\n"
        # inv içinde Markdown olabilecek karakter yoksa backtick içine almak güvenli
        final_reply += "\n".join([f"`{inv}`" for inv in escaped_invalid[:10]]) # İlk 10 tanesini göster
        if len(invalid_formats) > 10: final_reply += "\n..."

    # Sonuçları güvenli bir şekilde gönder (uzun mesajları böler)
    send_results_safe(chat_id, final_reply, processing_msg, parse_mode='Markdown')

# --- Güvenli Mesaj Gönderme Fonksiyonu (Uzun Mesajları Böler) ---
# (send_results_safe fonksiyonu önceki haliyle kalabilir, değişiklik gerekmiyor)
def send_results_safe(chat_id, text_content, original_message_info, parse_mode='Markdown'):
    MAX_MSG_LENGTH = 4096 # Telegram API mesaj limiti
    try:
        # Mesaj kısaysa ve işlem mesajı varsa, onu düzenle
        if original_message_info and len(text_content) <= MAX_MSG_LENGTH:
             bot.edit_message_text(
                 chat_id=chat_id,
                 message_id=original_message_info.message_id,
                 text=text_content,
                 parse_mode=parse_mode
            )
        # Mesaj uzunsa veya işlem mesajı yoksa, yeni mesaj(lar) gönder
        else:
            # Varsa eski işlem mesajını silmeyi dene
            if original_message_info:
                try:
                    bot.delete_message(chat_id, original_message_info.message_id)
                except Exception:
                    pass # Silinemezse önemli değil

            # Mesajı bölerek gönder
            start = 0
            while start < len(text_content):
                # Nerede bölüneceğini bul (önce çift newline, sonra tek newline, sonra limit)
                end = -1
                # En mantıklı bölme noktası: Sonuçlar arasındaki çift newline
                possible_end_double = text_content.rfind('\n\n', start, start + MAX_MSG_LENGTH)
                if possible_end_double > start : # Başlangıçtan sonra bulunduysa
                    end = possible_end_double
                    split_len = 2 # '\n\n'
                else:
                     # Tek newline ile bölmeyi dene
                     possible_end_single = text_content.rfind('\n', start, start + MAX_MSG_LENGTH)
                     if possible_end_single > start :
                         end = possible_end_single
                         split_len = 1 # '\n'
                     else:
                          # Hiç newline yoksa veya çok kısaysa, karakter limitine göre böl
                          end = start + MAX_MSG_LENGTH
                          split_len = 0 # Bölme karakteri yok

                # Parçayı al
                part = text_content[start:end]
                # Parçayı gönder
                bot.send_message(chat_id, part, parse_mode=parse_mode, disable_web_page_preview=True) # Önizlemeleri kapat

                # Sonraki başlangıç noktasını ayarla
                start = end + split_len

                # Çok hızlı göndermemek için küçük bir bekleme
                if start < len(text_content):
                    time.sleep(0.7)

    # Hata Durumları
    except telebot.apihelper.ApiTelegramException as e:
        error_desc = str(e.description).lower()
        print(f"!!! Telegram Mesaj Gönderme Hatası (Kod: {e.error_code}): {e.description}")
        # Markdown parse hatası
        if e.error_code == 400 and ('entity' in error_desc or 'markdown' in error_desc):
            print("--- Markdown parse hatası oluştu. Normal metin olarak gönderiliyor...")
            try:
                # Parse mode olmadan tekrar dene
                 send_results_safe(chat_id, text_content, original_message_info, parse_mode=None)
            except Exception as fb_md:
                print(f"--- Fallback (normal metin) gönderme hatası: {fb_md}")
                try: # Son çare: Hata mesajı gönder
                    # Hata mesajını da escape etmeye gerek yok, basit metin
                    bot.send_message(chat_id,"⚠️ Sonuçlar gönderilirken formatlama hatası oluştu. Lütfen geliştirici ile iletişime geçin.", parse_mode=None)
                except: pass
        # Rate limit hatası
        elif e.error_code == 429:
            retry_after = 2 # Varsayılan bekleme süresi
            try: # Retry-After süresini JSON'dan veya mesajdan almaya çalış
                if e.result_json and 'parameters' in e.result_json and 'retry_after' in e.result_json['parameters']:
                    retry_after = int(e.result_json['parameters']['retry_after']) + 1
                else:
                    match = re.search(r'retry after (\d+)', e.description, re.I)
                    if match: retry_after = int(match.group(1)) + 1
                print(f"--- Rate limit aşıldı. {retry_after} saniye bekleniyor...")
                # Kullanıcıyı bilgilendirirken Markdown kullanmaktan kaçınmak daha güvenli olabilir
                bot.send_message(chat_id, f"⏳ Çok fazla istek! Lütfen {retry_after} saniye sonra tekrar deneyin.", parse_mode=None)
                time.sleep(retry_after)
                # Rate limit sonrası tekrar göndermeyi deneyebiliriz ancak bu karmaşıklaşabilir.
                # Şimdilik sadece kullanıcıyı bilgilendiriyoruz.
            except Exception as pe:
                print(f"--- Retry-After parse hatası: {pe}. Varsayılan süre ({retry_after}s) bekleniyor.")
                try: bot.send_message(chat_id, f"⏳ Çok fazla istek! Lütfen birkaç saniye sonra tekrar deneyin.", parse_mode=None)
                except: pass
                time.sleep(retry_after)
        # Mesaj çok uzun hatası (bölme algoritması başarısız olduysa)
        elif "message is too long" in error_desc:
             print("!!! Bölme algoritmasına rağmen mesaj çok uzun hatası!")
             try: bot.send_message(chat_id, "⚠️ Hata: Oluşturulan yanıt Telegram limitlerinden uzun olduğu için gönderilemedi.", parse_mode=None)
             except: pass
        # Diğer API hataları
        else:
            try: bot.send_message(chat_id, f"⚠️ Telegram API Hatası (Kod: {e.error_code}). Sonuçlar gönderilemedi. Tekrar deneyin veya geliştiriciye bildirin.", parse_mode=None)
            except Exception as fb_other: print(f"--- Diğer API hatası fallback mesajı gönderilemedi: {fb_other}")

    # Kod içindeki diğer beklenmedik hatalar
    except Exception as e:
        print(f"!!! Mesaj gönderme fonksiyonunda beklenmedik hata: {e}")
        traceback.print_exc()
        try:
            bot.send_message(chat_id, "⚙️ Sonuçlar gönderilirken beklenmedik bir sistem hatası oluştu!", parse_mode=None)
        except Exception as fb_final:
            print(f"--- Genel hata fallback mesajı gönderilemedi: {fb_final}")


# Bilinmeyen komutlara veya mesajlara yanıt vermemesi için (opsiyonel)
# İsterseniz buraya bir "Anlamadım" mesajı ekleyebilirsiniz.
@bot.message_handler(func=lambda message: True)
def echo_all(message):
    # print(f"Bilinmeyen mesaj alındı: {message.text}") # Debug için
    # bot.reply_to(message, "Anlamadım. Kullanılabilir komutlar için /cmds yazabilirsiniz.")
    pass # Şimdilik hiçbir şey yapma

# --- Bot Polling Başlatma (Sürekli Çalışma ve Hata Yönetimi) ---
if __name__ == '__main__':
    print("\n" + "="*35)
    print(" Ana Polling Döngüsü Başlatılıyor... (CTRL+C ile durdurulabilir)")
    print("="*35 + "\n")
    while True: # Botun sürekli çalışması için sonsuz döngü
        try:
            # Botu başlat ve yeni mesajları dinle
            # none_stop=True: Hata olsa bile durma
            # interval: Mesajları ne sıklıkla kontrol edeceği (saniye)
            # timeout: Uzun polling için bekleme süresi (saniye)
            bot.polling(none_stop=True, interval=1, timeout=30)

        # Bağlantı Hataları
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
            error_type = type(e).__name__
            print(f"!!! {error_type}: Bağlantı sorunu veya zaman aşımı. İnternet bağlantısını veya Telegram sunucularını kontrol edin.")
            print(f"    Detay: {e}")
            print("--- 15 saniye beklenip tekrar denenecek...")
            time.sleep(15)

        # Telegram API Hataları
        except telebot.apihelper.ApiTelegramException as e:
            print(f"!!! Telegram API Hatası! Kod: {e.error_code}, Açıklama: {e.description}")
            # Token geçersiz veya iptal edilmiş
            if e.error_code == 401 or "unauthorized" in str(e.description).lower():
                print("\n !!! BOT TOKEN GEÇERSİZ VEYA İPTAL EDİLMİŞ !!! ")
                print("--- Program sonlandırılıyor. Lütfen geçerli bir token girin.")
                break # Döngüden çık, programı bitir
            # Bot başka bir yerde çalışıyor (conflict)
            elif e.error_code == 409:
                print("--- Conflict (409): Bot başka bir oturumda çalışıyor olabilir.")
                print("--- 30 saniye beklenip tekrar denenecek...")
                time.sleep(30)
            # Rate limit (ana döngüde de yakalayabiliriz ama nadir)
            elif e.error_code == 429:
                 retry_after = 5 # Varsayılan bekleme
                 try: # Süreyi almaya çalış
                     if e.result_json and 'parameters' in e.result_json and 'retry_after' in e.result_json['parameters']:
                         retry_after = int(e.result_json['parameters']['retry_after']) + 1
                     else:
                         match = re.search(r'retry after (\d+)', e.description, re.I)
                         if match: retry_after = int(match.group(1)) + 1
                     print(f"--- Ana döngüde Rate limit (429) algılandı. {retry_after} saniye bekleniyor...")
                 except Exception as p: print(f"--- Retry parse err ({p}). Varsayılan {retry_after}sn bekleniyor.")
                 time.sleep(retry_after)
            # Diğer API hataları (400 Bad Request dahil, eğer send_results_safe içinde yakalanamazsa)
            else:
                print(f"--- Diğer Telegram API Hatası ({e.error_code}). 30 saniye bekleniyor...")
                time.sleep(30)

        # Diğer Beklenmedik Hatalar
        except Exception as e:
            print(f"\n !!! BEKLENMEDİK GENEL HATA !!! Tür: {type(e).__name__}")
            print(f"    Mesaj: {e}")
            traceback.print_exc() # Hatanın tam detayını yazdır
            print("--- Program devam etmeyi deneyecek. 15 saniye bekleniyor...")
            time.sleep(15)

        # Döngü arasında çok kısa bir bekleme (CPU kullanımını azaltmak için)
        time.sleep(1)