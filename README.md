В файлах network_logs.csv и vulners_data.json расположены данные для запросов в API VirusTotal и API Vulners соотвественно.
При перед запуском программы необходимо добавить следующие переменные окружения: VT_API_KEY, ULNERS_API_KEY

Результатом программы бкдет слудующие файлы 
  analysis_results.json - полный отчёт с временной меткой, списком подозрительных IP, анализом CVE и угрозами.
  cve_analysis.csv - таблица CVE с указанием CVSS и пометкой об опасности
  suspicious_ips.csv — таблица подозрительных IP и их статистики. (**не создается** нет подозрительных IP 
  в примере)
  
Строит графики:
  cvss_distribution.png - гистограмма распределения CVSS-баллов по всем проверенным CVE (с вертикальной линией порога 7.0).
  top_ips.png - столбчатая диаграмма топ-5 самых активных IP из логов, где красным выделены подозрительные IP.
так

Настройка уведомлений в Telegram (TELEGRAM_TOKEN и TELEGRAM_CHAT_ID)
  Создайте бота и получите TELEGRAM_TOKEN (Пример: 7234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw)
  TELEGRAM_CHAT_ID Чат-айди — это уникальный идентификатор вашего диалога с ботом.  (например, 123456789)
  
Для добавления Настройка email-уведомлений (на примере Gmail)
  SMTP_SERVER: smtp.gmail.com
  SMTP_USER: your-email@gmail.com
  SMTP_PASSWORD: 16-значный пароль приложения (App Password)
  EMAIL_FROM:your-email@gmail.com.
  EMAIL_TO: Адрес электронной почты, на который вы хотите получать уведомления (может быть тем же самым или другим).
  
Примечание: API Vulners работает через VPN 
