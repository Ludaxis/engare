<div dir="rtl">

# انگاره

**تنها چشمان مقصود خواهند دید.**

انگاره ویدیوهای رمزنگاری‌شده را درون ویدیوهای معمولی پنهان می‌کند. هر کسی که ویدیو را تماشا کند، یک ویدیوی عادی می‌بیند. فقط کسی که کلید درست را دارد می‌تواند محتوای واقعی را استخراج کند.

نام‌گذاری‌شده از روی پیک‌های شاهنشاهی ایران باستان (*آنگاریون*) — پیک‌های ویژه‌ای که پیام‌های مهرشده‌شان فقط توسط گیرنده مورد نظر قابل باز شدن بود. ۲٬۵۰۰ سال بعد، همان اصل به جای طومار، ویدیو حمل می‌کند.

## چگونه کار می‌کند

</div>

```
شما یک ویدیوی گربه ضبط می‌کنید.
درون آن، یک ویدیوی کاملاً متفاوت پنهان می‌کنید.
هر کسی که پخش کند، گربه را می‌بیند.
دوست شما — با کلید — حقیقت را می‌بیند.
کلید اشتباه؟ فقط یک ویدیوی گربه. بدون خطا. بدون اثر.
```

<div dir="rtl">

- **رمزنگاری AES-256-GCM** — رمزنگاری احراز هویت‌شده (سطح نظامی، ضد دستکاری)
- **استگانوگرافی LSB** — تغییر کمتر از ۲.۵٪ مقادیر پیکسل (نامرئی برای چشم)
- **تبادل کلید X25519** — رمزنگاری منحنی بیضوی مدرن
- **رمزنگاری فریم‌به‌فریم** — هر فریم کلید منحصر به فرد دارد
- **انکارپذیری کامل** — کلید اشتباه یک ویدیوی عادی تولید می‌کند، هیچ مدرکی از پنهان بودن چیزی وجود ندارد

## نصب

</div>

```bash
# پیش‌نیازها: Python 3.9+, FFmpeg
pip install -e .

# یا اجرای مستقیم:
python -m engare
```

<div dir="rtl">

نصب FFmpeg:

</div>

```bash
# macOS
brew install ffmpeg

# Ubuntu/Debian
sudo apt install ffmpeg

# Windows
# https://ffmpeg.org/download.html :دانلود از
```

<div dir="rtl">

## شروع سریع

### ۱. ساخت هویت

</div>

```bash
engare keygen reza
# کلید در ~/.engare/ ذخیره می‌شود

# با محافظت رمز عبور:
engare keygen reza --encrypt
# کلید خصوصی با scrypt + AES-256-GCM رمزنگاری می‌شود
```

<div dir="rtl">

### ۲. وارد کردن کلید عمومی دوست

</div>

```bash
engare import ali "کلید-عمومی-base64"
```

<div dir="rtl">

### ۳. پنهان کردن ویدیو

</div>

```bash
# با جفت‌کلید (امن‌ترین):
engare encode --cover beach.mp4 --secret evidence.mp4 \
  --identity reza --recipient ali --output vacation.mkv

# با رمز عبور (ساده‌تر):
engare encode --cover beach.mp4 --secret evidence.mp4 \
  --password "رمز-مشترک" --output vacation.mkv

# با ویدیو به عنوان کلید (آفلاین، تحویل فیزیکی):
engare encode --cover beach.mp4 --secret evidence.mp4 \
  --video-key /usb/key-video.mp4 --output vacation.mkv

# کدک H.264 بدون اتلاف (فایل ۲ تا ۵ برابر کوچک‌تر):
engare encode --cover beach.mp4 --secret evidence.mp4 \
  --password "رمز" --codec h264 --output vacation.mp4

# پیش‌نمایش ظرفیت بدون رمزنگاری:
engare encode --cover beach.mp4 --message "تست" \
  --password "x" --output x --dry-run
```

<div dir="rtl">

### ۴. استخراج محتوای پنهان

</div>

```bash
# با جفت‌کلید:
engare decode --input vacation.mkv \
  --identity ali --sender reza --output revealed.mkv

# با رمز عبور:
engare decode --input vacation.mkv \
  --password "رمز-مشترک" --output revealed.mkv
```

<div dir="rtl">

### ۵. پنهان کردن پیام متنی

</div>

```bash
engare encode --cover beach.mp4 --message "ساعت ۸ فردا" \
  --password "secret" --output vacation.mkv

engare decode --input vacation.mkv --password "secret"
# خروجی: Message: ساعت ۸ فردا
```

<div dir="rtl">

### ۶. بررسی داده پنهان

</div>

```bash
engare verify --input vacation.mkv
# بررسی وجود داده پنهان (بدون رمزگشایی)
```

<div dir="rtl">

## سه حالت کلید

| حالت | نحوه کار | مناسب برای |
|------|---------|-----------|
| **جفت‌کلید** | تبادل کلید X25519 — هر کس کلید را محلی تولید می‌کند | ارتباط امن مداوم |
| **رمز عبور** | عبارت مشترک، کلید از طریق scrypt | پیام‌های سریع یک‌باره |
| **ویدیو به عنوان کلید** | یک فایل ویدیو خودش کلید است — روی فلش USB | امنیت بدون اینترنت |

## امنیت

- **متن‌باز بودن امنیت را کاهش نمی‌دهد.** الگوریتم AES-256 دانش عمومی است — هر دولتی می‌داند چگونه کار می‌کند. همچنان غیرقابل شکستن است. امنیت در کلید است، نه در کد (اصل کرکهافس).
- **AES-256-GCM** — رمزنگاری احراز هویت‌شده. هر دستکاری شناسایی می‌شود.
- **کلیدهای یکتا فریم‌به‌فریم** — از طریق HKDF. هیچ دو فریمی کلید مشترک ندارند.
- **X25519** — تبادل کلید منحنی بیضوی مدرن (مشابه Signal و WireGuard).
- **کلید اشتباه = ویدیوی عادی.** بدون پیام خطا، بدون اثر، بدون مدرک.

## فرمت خروجی

انگاره از دو کدک بدون اتلاف پشتیبانی می‌کند:

- **FFV1** (پیش‌فرض، `--codec ffv1`) — کانتینر MKV. بزرگ‌ترین فایل‌ها.
- **H.264 بدون اتلاف** (`--codec h264`) — کانتینر MP4. با libx264rgb و CRF 0. ۲ تا ۵ برابر کوچک‌تر از FFV1.

## رابط برنامه‌نویسی

برای استفاده برنامه‌نویسی (رابط گرافیکی، اسکریپت):

```python
from engare.core import KeyConfig, encode_text, decode

key = KeyConfig(mode="password", password="secret")
encode_text("cover.mp4", "پیام پنهان", key, "output.mkv")
result = decode("output.mkv", key)
```

## مستندات

- [معماری](docs/architecture.md) — طراحی سیستم، جریان داده، فرمت بسته‌بندی
- [مدل امنیتی](docs/security.md) — مدل تهدید، انتخاب‌های رمزنگاری، محدودیت‌ها
- [مشارکت](docs/contributing.md) — راه‌اندازی، تست، قوانین کد

## مجوز

GPL-3.0 — آزاد به معنای آزادی.

---

[English README](README.md)

</div>
