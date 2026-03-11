"""
Скрипт для анализа сетевых логов и уязвимостей с использованием VirusTotal и Vulners API.
Обнаруживает подозрительные IP и опасные CVE (CVSS >= 7.0), отправляет уведомления,
сохраняет результаты и строит график.

"""

import os
import time
import json
import pandas as pd
import requests
import matplotlib.pyplot as plt
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter

# ---------- Конфигурация (из переменных окружения) ----------
VT_API_KEY = os.getenv("VT_API_KEY", "")                # Ключ VirusTotal
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY", "")      # Ключ Vulners 
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", "")
EMAIL_TO = os.getenv("EMAIL_TO", "")

# Параметры для ограничения запросов (VirusTotal free: 4 запроса в минуту)
VT_DELAY = 15  # секунд между запросами

# Порог CVSS для опасных уязвимостей
CVSS_THRESHOLD = 7.0

# ---------- Вспомогательные функции ----------
def is_public_ip(ip):
    """Проверяет, является ли IP публичным (не из частных диапазонов)"""
    private_ranges = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
        ("127.0.0.0", "127.255.255.255"),
    ]
    try:
        parts = list(map(int, ip.split('.')))
        if len(parts) != 4:
            return False
        ip_num = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        for start, end in private_ranges:
            s = sum(int(x) << (24 - 8 * i) for i, x in enumerate(start.split('.')))
            e = sum(int(x) << (24 - 8 * i) for i, x in enumerate(end.split('.')))
            if s <= ip_num <= e:
                return False
        return True
    except:
        return False

def vt_ip_report(ip):
    """Запрашивает отчет об IP у VirusTotal. Возвращает словарь со статистикой."""
    if not VT_API_KEY:
        print(f"[VT] Нет API ключа, пропускаем проверку {ip}")
        return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats
        else:
            print(f"[VT] Ошибка {response.status_code} для {ip}: {response.text}")
            return None
    except Exception as e:
        print(f"[VT] Исключение для {ip}: {e}")
        return None

def vulners_cve_info(cve_id):
    """
    Запрашивает информацию о CVE у Vulners. Возвращает CVSS балл (float) или None.
    """
    url = f"https://vulners.com/api/v3/search/id/?id={cve_id}"
    headers = {}
    if VULNERS_API_KEY:
        headers["X-API-KEY"] = VULNERS_API_KEY

    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"[Vulners] Ошибка {response.status_code} для {cve_id}")
            return None

        data = response.json()
        if data.get("result") != "OK":
            print(f"[Vulners] Результат не OK для {cve_id}")
            return None

        documents = data.get("data", {}).get("documents", {})
        if not documents:
            print(f"[Vulners] Нет документов для {cve_id}")
            return None

        # Поиск документа (сначала точный ключ, потом по вхождению)
        doc = documents.get(f"CVELIST:{cve_id}")
        if doc is None:
            for key, candidate in documents.items():
                if cve_id in key:
                    doc = candidate
                    break

        if doc is None:
            print(f"[Vulners] Документ с CVE {cve_id} не найден в ответе")
            return None

        # Вспомогательная функция для извлечения числа из объекта CVSS
        def extract_score(cvss_obj):
            if not isinstance(cvss_obj, dict):
                return None
            # Приоритет: baseScore (иногда используется)
            if "baseScore" in cvss_obj:
                try:
                    return float(cvss_obj["baseScore"])
                except (ValueError, TypeError):
                    pass
            # Затем score (как в ваших логах)
            if "score" in cvss_obj:
                try:
                    return float(cvss_obj["score"])
                except (ValueError, TypeError):
                    pass
            return None

        cvss_score = None

        # Пробуем cvss3
        cvss3 = doc.get("cvss3")
        if cvss3 and isinstance(cvss3, dict):
            if "cvssV3" in cvss3 and isinstance(cvss3["cvssV3"], dict):
                cvss_score = extract_score(cvss3["cvssV3"])
            else:
                cvss_score = extract_score(cvss3)

        # Если нет, пробуем cvss2
        if cvss_score is None:
            cvss2 = doc.get("cvss2")
            if cvss2 and isinstance(cvss2, dict):
                if "cvssV2" in cvss2 and isinstance(cvss2["cvssV2"], dict):
                    cvss_score = extract_score(cvss2["cvssV2"])
                else:
                    cvss_score = extract_score(cvss2)

        # Если нет, пробуем прямое поле cvss
        if cvss_score is None:
            cvss = doc.get("cvss")
            if cvss is not None:
                if isinstance(cvss, dict):
                    cvss_score = extract_score(cvss)
                else:
                    try:
                        cvss_score = float(cvss)
                    except (ValueError, TypeError):
                        pass

        if cvss_score is None:
            print(f"[Vulners] Не удалось найти CVSS для {cve_id}")
            return None

        return float(cvss_score)

    except Exception as e:
        print(f"[Vulners] Исключение для {cve_id}: {e}")
        return None

def send_telegram(message):
    """Отправляет сообщение в Telegram"""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[Telegram] Не настроен, пропускаем")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}
    try:
        r = requests.post(url, json=payload)
        if r.status_code != 200:
            print(f"[Telegram] Ошибка: {r.text}")
    except Exception as e:
        print(f"[Telegram] Исключение: {e}")

def send_email(subject, body):
    """Отправляет email"""
    if not SMTP_USER or not SMTP_PASSWORD or not EMAIL_TO:
        print("[Email] Не настроен, пропускаем")
        return
    msg = MIMEMultipart()
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("[Email] Уведомление отправлено")
    except Exception as e:
        print(f"[Email] Ошибка: {e}")

def simulate_block(ip):
    """Имитация блокировки IP (просто вывод)"""
    print(f"[БЛОКИРОВКА] IP {ip} заблокирован (симуляция)")

# ---------- Основной скрипт ----------
def main():
    print("Запуск анализа...")

    # 1. Загрузка данных
    try:
        df = pd.read_csv("network_logs.csv")
        print(f"Загружено {len(df)} записей из network_logs.csv")
    except Exception as e:
        print(f"Ошибка чтения network_logs.csv: {e}")
        return

    try:
        with open("vulners_data.json", "r") as f:
            vulners_data = json.load(f)
        print("Загружен vulners_data.json")
    except Exception as e:
        print(f"Ошибка чтения vulners_data.json: {e}")
        return

    # 2. Извлечение уникальных публичных IP из логов
    all_ips = set(df["src_ip"].tolist() + df["dst_ip"].tolist())
    public_ips = [ip for ip in all_ips if is_public_ip(ip)]
    print(f"Найдено {len(public_ips)} публичных IP для проверки в VirusTotal")

    # 3. Проверка IP через VirusTotal
    suspicious_ips = []  # список словарей с ip и статистикой
    for ip in public_ips:
        print(f"Проверка IP {ip}...")
        stats = vt_ip_report(ip)
        if stats:
            # Если есть хоть одно malicious или suspicious, считаем подозрительным
            if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                suspicious_ips.append({
                    "ip": ip,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                })
                print(f"  -> ПОДОЗРИТЕЛЬНЫЙ: malicious={stats['malicious']}, suspicious={stats['suspicious']}")
            else:
                print(f"  -> чистый")
        time.sleep(VT_DELAY)  # соблюдаем rate limit

    # 4. Проверка CVE через Vulners
    cve_list = vulners_data.get("cve_ids", [])
    cve_results = []
    for cve in cve_list:
        print(f"Проверка {cve}...")
        cvss = vulners_cve_info(cve)
        if cvss is not None:
            cve_results.append({
                "cve": cve,
                "cvss": cvss,
                "dangerous": cvss >= CVSS_THRESHOLD
            })
            if cvss >= CVSS_THRESHOLD:
                print(f"  -> ОПАСНАЯ (CVSS={cvss})")
            else:
                print(f"  -> CVSS={cvss}")
        else:
            cve_results.append({"cve": cve, "cvss": None, "dangerous": False})
        time.sleep(1)  # небольшая пауза для вежливости

    # 5. Формирование списка угроз
    threats = []
    for ip_info in suspicious_ips:
        threats.append({
            "type": "IP",
            "name": ip_info["ip"],
            "details": f"malicious={ip_info['malicious']}, suspicious={ip_info['suspicious']}"
        })
    for cve_info in cve_results:
        if cve_info["dangerous"]:
            threats.append({
                "type": "CVE",
                "name": cve_info["cve"],
                "details": f"CVSS={cve_info['cvss']}"
            })

    # 6. Реакция на угрозы
    if threats:
        print("\n" + "="*50)
        print("ОБНАРУЖЕНЫ УГРОЗЫ:")
        for t in threats:
            print(f"  - {t['type']}: {t['name']} ({t['details']})")
            if t['type'] == "IP":
                simulate_block(t['name'])
        print("="*50)

        # Отправка уведомлений
        subject = f"Обнаружены угрозы ({len(threats)})"
        body = "Список угроз:\n"
        for t in threats:
            body += f"- {t['type']}: {t['name']} ({t['details']})\n"

        send_telegram(body)
        send_email(subject, body)
    else:
        print("Угроз не обнаружено.")

    # 7. Сохранение результатов
    results = {
        "timestamp": datetime.now().isoformat(),
        "suspicious_ips": suspicious_ips,
        "cve_analysis": cve_results,
        "threats": threats
    }
    with open("analysis_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("Результаты сохранены в analysis_results.json")

    # Дополнительно сохраняем в CSV для удобства
    if suspicious_ips:
        df_ips = pd.DataFrame(suspicious_ips)
        df_ips.to_csv("suspicious_ips.csv", index=False)
    if cve_results:
        df_cve = pd.DataFrame(cve_results)
        df_cve.to_csv("cve_analysis.csv", index=False)

    # 8. Построение графика (распределение CVSS-баллов)
    cvss_scores = [c["cvss"] for c in cve_results if c["cvss"] is not None]
    if cvss_scores:
        plt.figure(figsize=(10, 6))
        plt.hist(cvss_scores, bins=10, edgecolor='black', alpha=0.7)
        plt.axvline(x=CVSS_THRESHOLD, color='red', linestyle='--', label=f'Порог опасности ({CVSS_THRESHOLD})')
        plt.xlabel("CVSS балл")
        plt.ylabel("Количество CVE")
        plt.title("Распределение CVSS баллов по анализируемым CVE")
        plt.legend()
        plt.grid(axis='y', alpha=0.3)
        plt.savefig("cvss_distribution.png")
        print("График сохранён в cvss_distribution.png")
    else:
        print("Нет данных CVSS для построения графика.")

    # Дополнительно можно построить топ-5 IP по количеству обращений из логов
    ip_counts = Counter(df["src_ip"].tolist() + df["dst_ip"].tolist())
    top_ips = ip_counts.most_common(5)
    if top_ips:
        plt.figure(figsize=(10, 6))
        ips, counts = zip(*top_ips)
        colors = ['red' if ip in [s['ip'] for s in suspicious_ips] else 'blue' for ip in ips]
        plt.bar(ips, counts, color=colors)
        plt.xlabel("IP адрес")
        plt.ylabel("Количество обращений")
        plt.title("Топ-5 IP по активности (красные - подозрительные)")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig("top_ips.png")
        print("График топ-5 IP сохранён в top_ips.png")

    print("Анализ завершён.")

if __name__ == "__main__":
    main()
