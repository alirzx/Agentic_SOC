# نصب Soorin Agentic SOC روی اوبونتو ۲۲.۰۴

راهنمای نصب از صفر روی یک ماشین تازه. ریپوی رسمی:

**https://github.com/SoorinSecurity/Agentic_SOC**

ایمیج‌های دمو از **همین ریپو** بیلد می‌شوند (نه ایمیج‌های آپ‌استریم)، تا پلی‌بوک‌ها و تغییرات خودتان داخل کانتینر باشند.

---

## پیش‌نیاز سخت‌افزار

| مورد | حداقل | پیشنهادی |
|------|--------|----------|
| RAM آزاد | ۴ گیگ | ۸ گیگ یا بیشتر |
| دیسک آزاد | ۱۰ گیگ | ۲۰ گیگ |
| معماری | amd64 یا arm64 | amd64 |
| سیستم‌عامل | Ubuntu 22.04 LTS | همان |

پورت‌هایی که باید آزاد باشند: `5000` (وب)، `8888` (API)، `8887` (Agents)، `5432` (Postgres)، `6379` (Redis)، `9092` (Kafka).

---

## مسیر سریع (یک دستور)

اگر ماشین تازه است و می‌خواهید git، Docker، Node و pnpm خودکار نصب شوند:

```bash
curl -fsSL https://raw.githubusercontent.com/SoorinSecurity/Agentic_SOC/main/install.sh | bash
```

از داخل یک کلون موجود:

```bash
./install.sh
```

اگر `curl | bash` را دوست ندارید، مراحل دستی زیر را بروید.

---

## مسیر دستی از صفر

### ۱) سیستم را به‌روز کنید

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg lsb-release git unzip
```

### ۲) Docker Engine + Compose v2

پکیج snap داکر را نصب نکنید؛ از ریپوی رسمی Docker استفاده کنید:

```bash
sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker "$USER"
newgrp docker
```

اگر هنوز `permission denied` دیدید، یک‌بار logout/login یا reboot کنید.

بررسی:

```bash
docker --version
docker compose version
docker run --rm hello-world
```

### ۳) تنظیم لینوکس برای OpenSearch (فقط استک کامل)

اگر بعداً استک کامل را بالا می‌آورید:

```bash
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-soorin.conf
sudo sysctl --system
```

### ۴) Node.js 20 و pnpm

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

sudo corepack enable
sudo corepack prepare pnpm@8.15.1 --activate

node -v    # باید v20.x باشد
pnpm -v    # باید 8.x باشد
```

### ۵) کلون کردن پروژه

```bash
git clone https://github.com/SoorinSecurity/Agentic_SOC.git
cd Agentic_SOC
```

اگر همین پوشه را از قبل روی سرور کپی کرده‌اید، دوباره کلون نکنید؛ فقط وارد همان پوشه شوید.

### ۶) فایل محیط

```bash
cp .env.example .env
nano .env
```

برای دموی ساده، پیش‌فرض‌ها معمولاً کافی است. برای تحقیق واقعی با LLM حداقل یکی را بگذارید:

```env
OPENAI_API_KEY=sk-...
# یا
ANTHROPIC_API_KEY=sk-ant-...
```

کلید vault کانکتورها (اگر می‌خواهید کانکتور واقعی وصل کنید):

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

خروجی را در `AISOC_CREDENTIAL_KEY` داخل `.env` بگذارید. اگر `cryptography` نصب نبود:

```bash
pip3 install cryptography
```

متغیرهای داخلی با پیشوند `AISOC_*` هستند؛ این عمدی است و نباید عوض شوند.

### ۷) نصب وابستگی‌های Node

```bash
pnpm install
```

---

## اجرا

### حالت A — دموی سریع (پیشنهادی برای بار اول)

اولین بیلد از سورس حدود ۱۰ تا ۱۵ دقیقه طول می‌کشد. استک سبک می‌آید: Postgres، Redis، Kafka، API، agents، realtime، web.

```bash
pnpm aisoc:demo
```

معادل:

```bash
pnpm soorin:demo
```

بعد از بالا آمدن:

| مورد | آدرس / مقدار |
|------|----------------|
| کنسول | http://localhost:5000 |
| کیس نمونه | http://localhost:5000/cases/INC-RT-001?tab=ledger |
| ورود دمو | معمولاً auto-login با `demo@tryaisoc.com` |
| API docs | http://localhost:8888/docs |

دستورهای مفید:

```bash
pnpm aisoc:doctor        # سلامت سرویس‌ها
pnpm aisoc:demo:logs     # لاگ‌ها
pnpm aisoc:demo:down     # خاموش کردن و پاک کردن volume دمو
```

### حالت B — استک کامل توسعه

فقط وقتی می‌خواهید روی خود کد کار کنید یا همه سرویس‌ها (ClickHouse، OpenSearch، Neo4j و غیره) را داشته باشید.

```bash
pnpm install
cp .env.example .env     # اگر هنوز نکرده‌اید
docker compose up -d
docker compose ps
```

مهاجرت دیتابیس:

```bash
docker compose exec api alembic upgrade head
docker compose exec ueba alembic upgrade head
docker compose exec honeytokens alembic upgrade head
docker compose exec purple-team alembic upgrade head
```

داده نمونه:

```bash
pnpm seed:demo
pnpm aisoc:doctor
```

ورود استک کامل بعد از seed:

- UI: http://localhost:5000
- کاربر: `admin@aisoc.local`
- رمز: `changeme`

کانکتورها، osquery و Slack پشت profile هستند:

```bash
COMPOSE_PROFILES=connectors,osquery,slack docker compose up -d
```

---

## اگر SSH زدید و مرورگر روی خود سرور نیست

از لپ‌تاپ تونل بزنید:

```bash
ssh -L 5000:localhost:5000 -L 8888:localhost:8888 USER@IP-اوبونتو
```

بعد روی لپ‌تاپ: http://localhost:5000

از ماشین دیگر در همان شبکه (نه از خود VM) آدرس `http://IP:5000` را باز کنید.
پورت وب باید روی `0.0.0.0` باشد نه فقط `127.0.0.1`. بعد از کشیدن این تغییر:

```bash
cd /home/api/Agentic_SOC
export AISOC_BIND_ADDR=0.0.0.0
export AISOC_CORS_ORIGINS="http://localhost:5000,http://127.0.0.1:5000,http://192.168.0.55:5000"
docker compose -f infra/compose/docker-compose.demo.yml up -d --force-recreate web api agents realtime
```

اگر فایروال روشن است: `sudo ufw allow 5000/tcp && sudo ufw reload`

روی خود VM برای تست: `curl -I http://127.0.0.1:5000` باید ۲۰۰ بدهد. `docker ps` باید نشان بدهد `0.0.0.0:5000->3000/tcp` نه `127.0.0.1:5000`.

---

## پورت‌های اشغال‌شده

اگر پورت گرفته شده بود:

```bash
sudo ss -lptn 'sport = :5000'
```

یا در `.env` پورت را عوض کنید، مثلاً `AISOC_WEB_PORT=5001`.

| پورت | سرویس | متغیر جایگزین |
|------|--------|----------------|
| `5000` | وب‌کنسول | `AISOC_WEB_PORT` |
| `8888` | API | `AISOC_API_PORT` |
| `8887` | Agents | `AISOC_AGENTS_PORT` |
| `5432` | Postgres | `AISOC_POSTGRES_PORT` |
| `6379` | Redis | `AISOC_REDIS_PORT` |
| `9092` | Kafka | `AISOC_KAFKA_PORT` |

---

## خاموش کردن

دمو:

```bash
pnpm aisoc:demo:down
```

استک کامل:

```bash
docker compose down          # داده باقی می‌ماند
docker compose down -v       # همه volumeها پاک می‌شود
```

---

## مشکلات رایج روی اوبونتو

1. **`permission denied` برای Docker**  
   `sudo usermod -aG docker $USER` سپس logout/login. در همان سشن می‌توانید بزنید:  
   `sg docker -c "pnpm aisoc:demo"`

2. **OpenSearch بالا نمی‌آید**  
   همان `vm.max_map_count=262144` در بخش ۳.

3. **اولین بوت طول می‌کشد**  
   طبیعی است؛ بیلد از سورس ۱۰–۱۵ دقیقه است. اگر شبکه به `ghcr.io` محدود است، همین مسیر `--rebuild` درست است.

4. **RAM کم**  
   کمتر از ۴ گیگ آزاد ممکن است Postgres را OOM کند. فقط حالت دمو را اجرا کنید، نه استک کامل.

5. **گروه docker در همان سشن اعمال نشده**  
   `newgrp docker` یا logout/login.

---

## لینک‌های مرتبط

- نصب یک‌کلیکی (همه پلتفرم‌ها): [`QUICK_INSTALL.md`](QUICK_INSTALL.md)
- توسعه لوکال سرویس‌به‌سرویس: [`runbooks/LOCAL_DEVELOPMENT.md`](runbooks/LOCAL_DEVELOPMENT.md)
- متغیرهای محیط: [`../apps/docs/docs/deployment/env-vars.md`](../apps/docs/docs/deployment/env-vars.md)
- وب‌سایت: [soorinsec.ir](https://soorinsec.ir)
- گیت‌هاب: [SoorinSecurity/Agentic_SOC](https://github.com/SoorinSecurity/Agentic_SOC)
