import re
from datetime import datetime

# عينة لملف سجلات وهمي (Log Data) يمثل محاولات دخول على خادم أو نظام
LOG_DATA = """
192.168.1.10 - - [10/Nov/2026:08:12:00] "POST /login HTTP/1.1" 200 532
192.168.1.45 - - [10/Nov/2026:08:12:05] "POST /login HTTP/1.1" 401 230
192.168.1.45 - - [10/Nov/2026:08:12:08] "POST /login HTTP/1.1" 401 230
192.168.1.45 - - [10/Nov/2026:08:12:12] "POST /login HTTP/1.1" 401 230
192.168.1.45 - - [10/Nov/2026:08:12:15] "POST /login HTTP/1.1" 401 230
192.168.1.45 - - [10/Nov/2026:08:12:18] "POST /login HTTP/1.1" 401 230
10.0.0.5 - - [10/Nov/2026:08:15:30] "GET /dashboard HTTP/1.1" 200 1200
192.168.1.88 - - [10/Nov/2026:08:20:00] "POST /login HTTP/1.1" 403 150
192.168.1.88 - - [10/Nov/2026:08:20:02] "POST /login HTTP/1.1" 403 150
"""

def parse_logs(log_text):
    """
    دالة لتحليل السجلات واستخراج عنوان الآيب حالة الطلب والمسار
    """
    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>[^\]]+)\] "(?P<method>\w+) (?P<path>[^\s]+)[^"]+" (?P<status>\d+) (?P<size>\d+)')
    
    parsed_entries = []
    for line in log_text.strip().split('\n'):
        match = log_pattern.match(line)
        if match:
            parsed_entries.append(match.groupdict())
            
    return parsed_entries

def detect_brute_force(entries, threshold=3):
    """
    اكتشاف هجمات التخمين (Brute Force) عن طريق تكرار حالات الدخول الفاشلة (401 أو 403) لنفس الآيب
    """
    failed_attempts = {}
    
    for entry in entries:
        if entry['status'] in ['401', '403']:
            ip = entry['ip']
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= threshold}
    return suspicious_ips

def main():
    print("=" * 50)
    print("       Python Security Log Analyzer & SIEM Lite      ")
    print("=" * 50)
    
    print(f"\n[+] جارٍ تحليل السجلات في الوقت الحالي: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    entries = parse_logs(LOG_DATA)
    print(f"[+] تم تحليل {len(entries)} حدث/سجل بنجاح.\n")
    
    # فحص التهديدات الأمنية
    print("[*] فحص محاولات الوصول غير المصرّح بها وهجمات التخمين (Brute Force)...")
    alerts = detect_brute_force(entries, threshold=3)
    
    if alerts:
        print("\n[تحذير أمني] تم اكتشاف عناوين آيب مشبوهة تحاول تنفيذ هجمات محتملة:")
        for ip, count in alerts.items():
            print(f"   - IP: {ip} | عدد المحاولات الفاشلة: {count} مرات")
    else:
        print("\n[+] لم يتم رصد أي نشاط مشبوه أو هجمات تخمين.")
        
    print("\n" + "=" * 50)
    print("تم إتمام الفحص بنجاح.")

if __name__ == "__main__":
    main()