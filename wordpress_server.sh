#!/bin/bash
# ==============================================================================
# WordPress Web Server — Setup Complet
# Componente: Apache2, PHP, MariaDB, Fail2Ban, UFW, Webmin, Hardening
# Compatibil: Ubuntu Server 22.04 / 24.04 LTS
# Rulare: sudo bash wordpress_server.sh
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Log ────────────────────────────────────────────────────────────────────────
LOG="/var/log/wp_server_setup.log"
exec > >(tee -a "$LOG") 2>&1

# ── Culori ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[✔]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✘] EROARE:${NC} $*"; exit 1; }
section() { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}"; }

# ── Verificare root ────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && error "Rulează cu: sudo bash $0"

# ── Verificare Ubuntu ──────────────────────────────────────────────────────────
if ! grep -qi "ubuntu" /etc/os-release; then
    warn "Scriptul este optimizat pentru Ubuntu. Continuare pe propriul risc."
fi

UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
info "Sistem detectat: Ubuntu $UBUNTU_VERSION"

# ── Funcție citire parolă cu confirmare ───────────────────────────────────────
read_password() {
    local prompt="$1" varname="$2" pass1 pass2
    while true; do
        read -s -p "  → $prompt: " pass1; echo
        [[ ${#pass1} -lt 8 ]] && { warn "Parola trebuie să aibă minim 8 caractere."; continue; }
        read -s -p "  → Confirmă parola: " pass2; echo
        [[ "$pass1" == "$pass2" ]] && { printf -v "$varname" '%s' "$pass1"; break; }
        warn "Parolele nu coincid. Încearcă din nou."
    done
}

# ── Colectare credențiale ──────────────────────────────────────────────────────
clear
echo -e "${BOLD}"
cat << 'BANNER'
  ╔══════════════════════════════════════════════════════╗
  ║       WordPress Server — Setup Automat               ║
  ║       Apache · PHP · MariaDB · Fail2Ban · Webmin     ║
  ╚══════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

section "Configurare credențiale"
echo -e "  Completează cu atenție. Parolele nu vor fi afișate.\n"

read -p "  → Username admin MySQL: " MYSQL_ADMIN_USER
[[ -z "$MYSQL_ADMIN_USER" || "$MYSQL_ADMIN_USER" == "root" ]] && \
    error "Alege un username diferit de 'root' și nevid."

read_password "Parolă admin MySQL ($MYSQL_ADMIN_USER)" MYSQL_ADMIN_PASS
read_password "Parolă root MySQL (internă/backup)" MYSQL_ROOT_PASS

echo
read -p "  → Hostname server (ex: server.domeniu.ro) [apasă Enter pentru IP]: " SERVER_HOSTNAME
SERVER_HOSTNAME="${SERVER_HOSTNAME:-$(hostname -I | awk '{print $1}')}"

echo
info "Credențiale colectate. Se începe instalarea..."
sleep 2

# ══════════════════════════════════════════════════════════════════════════════
section "1 / 9 — Actualizare sistem"
# ══════════════════════════════════════════════════════════════════════════════

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg2 \
    curl \
    wget \
    unzip \
    lsb-release \
    net-tools \
    htop \
    vim \
    git \
    cron \
    logrotate

info "Sistem actualizat."

# ══════════════════════════════════════════════════════════════════════════════
section "2 / 9 — Apache2"
# ══════════════════════════════════════════════════════════════════════════════

DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 apache2-utils
systemctl enable --now apache2

# Module necesare WordPress
a2enmod rewrite headers ssl expires deflate filter setenvif

# Dezactivare site default și listare directoare
a2dissite 000-default.conf 2>/dev/null || true
sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' \
    /etc/apache2/apache2.conf 2>/dev/null || true

# Hardening Apache global
cat > /etc/apache2/conf-available/hardening.conf << 'EOF'
# Ascunde versiunea Apache
ServerTokens Prod
ServerSignature Off

# Dezactivare metode periculoase
TraceEnable Off

# Security Headers
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
Header always unset X-Powered-By

# Previne accesul la fișiere sensibile
<FilesMatch "(\.htaccess|\.htpasswd|\.git|\.env|wp-config\.php|xmlrpc\.php)">
    Require all denied
</FilesMatch>

# Compresie Gzip pentru performanță
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml
    AddOutputFilterByType DEFLATE text/css text/javascript
    AddOutputFilterByType DEFLATE application/javascript application/json
    AddOutputFilterByType DEFLATE application/x-font-ttf font/opentype
    AddOutputFilterByType DEFLATE image/svg+xml
</IfModule>

# Cache static assets
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/webp "access plus 1 year"
    ExpiresByType image/svg+xml "access plus 1 month"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType application/x-font-woff "access plus 1 year"
</IfModule>
EOF

a2enconf hardening

# Virtual Host template WordPress (va fi clonat per site)
cat > /etc/apache2/sites-available/wordpress-template.conf << 'EOF'
# ── Template VirtualHost WordPress ──────────────────────────────
# Copiază și adaptează pentru fiecare site:
# cp /etc/apache2/sites-available/wordpress-template.conf \
#    /etc/apache2/sites-available/domeniu.conf
# Înlocuiește DOMENIU_TBD și DBNAME_TBD, apoi: a2ensite domeniu.conf

<VirtualHost *:80>
    ServerName DOMENIU_TBD
    ServerAlias www.DOMENIU_TBD
    DocumentRoot /var/www/DOMENIU_TBD

    <Directory /var/www/DOMENIU_TBD>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # WordPress xmlrpc — dezactivat (protecție brute-force)
    <Files xmlrpc.php>
        Require all denied
    </Files>

    # Blochează wp-config.php
    <Files wp-config.php>
        Require all denied
    </Files>

    ErrorLog  ${APACHE_LOG_DIR}/DOMENIU_TBD-error.log
    CustomLog ${APACHE_LOG_DIR}/DOMENIU_TBD-access.log combined

    # Redirect HTTP → HTTPS (decomentează după SSL)
    # RewriteEngine On
    # RewriteCond %{HTTPS} off
    # RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>

# <VirtualHost *:443>
#     ServerName DOMENIU_TBD
#     DocumentRoot /var/www/DOMENIU_TBD
#     SSLEngine on
#     SSLCertificateFile    /etc/letsencrypt/live/DOMENIU_TBD/fullchain.pem
#     SSLCertificateKeyFile /etc/letsencrypt/live/DOMENIU_TBD/privkey.pem
#     Include               /etc/letsencrypt/options-ssl-apache.conf
#     Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
#
#     <Directory /var/www/DOMENIU_TBD>
#         Options -Indexes +FollowSymLinks
#         AllowOverride All
#         Require all granted
#     </Directory>
#     ErrorLog  ${APACHE_LOG_DIR}/DOMENIU_TBD-ssl-error.log
#     CustomLog ${APACHE_LOG_DIR}/DOMENIU_TBD-ssl-access.log combined
# </VirtualHost>
EOF

systemctl reload apache2
info "Apache2 instalat și hardened."

# ══════════════════════════════════════════════════════════════════════════════
section "3 / 9 — PHP (WordPress dependencies)"
# ══════════════════════════════════════════════════════════════════════════════

# Detectare versiune PHP disponibilă
DEBIAN_FRONTEND=noninteractive apt-get install -y php libapache2-mod-php
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
info "PHP $PHP_VER detectat."

# Toate extensiile necesare WordPress (+ recomandate de wordpress.org)
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    "php${PHP_VER}-mysql" \
    "php${PHP_VER}-curl" \
    "php${PHP_VER}-xml" \
    "php${PHP_VER}-mbstring" \
    "php${PHP_VER}-zip" \
    "php${PHP_VER}-gd" \
    "php${PHP_VER}-imagick" \
    "php${PHP_VER}-intl" \
    "php${PHP_VER}-bcmath" \
    "php${PHP_VER}-soap" \
    "php${PHP_VER}-cli" \
    "php${PHP_VER}-fpm" \
    "php${PHP_VER}-opcache" 2>/dev/null || \
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    php-mysql php-curl php-xml php-mbstring php-zip php-gd \
    php-intl php-bcmath php-soap php-cli php-fpm

# Hardening php.ini pentru Apache
PHP_INI_APACHE="/etc/php/${PHP_VER}/apache2/php.ini"
PHP_INI_CLI="/etc/php/${PHP_VER}/cli/php.ini"

harden_php() {
    local ini_file="$1"
    [[ ! -f "$ini_file" ]] && return
    cp "$ini_file" "${ini_file}.bak"
    sed -i \
        -e 's/^expose_php.*/expose_php = Off/' \
        -e 's/^display_errors.*/display_errors = Off/' \
        -e 's/^display_startup_errors.*/display_startup_errors = Off/' \
        -e 's/^log_errors.*/log_errors = On/' \
        -e 's/^error_reporting.*/error_reporting = E_ALL \& ~E_DEPRECATED \& ~E_STRICT/' \
        -e 's/^upload_max_filesize.*/upload_max_filesize = 64M/' \
        -e 's/^post_max_size.*/post_max_size = 64M/' \
        -e 's/^max_execution_time.*/max_execution_time = 120/' \
        -e 's/^max_input_time.*/max_input_time = 120/' \
        -e 's/^memory_limit.*/memory_limit = 256M/' \
        -e 's/^allow_url_fopen.*/allow_url_fopen = Off/' \
        -e 's/^session.cookie_httponly.*/session.cookie_httponly = 1/' \
        -e 's/^session.cookie_secure.*/session.cookie_secure = 1/' \
        -e 's/^session.use_strict_mode.*/session.use_strict_mode = 1/' \
        "$ini_file"
    # Opcache settings (append dacă nu există)
    grep -q "opcache.enable" "$ini_file" || cat >> "$ini_file" << 'OPCACHE'

; OPcache WordPress optimizat
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=4000
opcache.revalidate_freq=2
opcache.fast_shutdown=1
OPCACHE
}

harden_php "$PHP_INI_APACHE"
harden_php "$PHP_INI_CLI"

systemctl restart apache2
info "PHP $PHP_VER instalat cu toate extensiile WordPress."

# ══════════════════════════════════════════════════════════════════════════════
section "4 / 9 — MariaDB"
# ══════════════════════════════════════════════════════════════════════════════

DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client
systemctl enable --now mariadb

# Setare parolă root MariaDB
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';" 2>/dev/null || \
    warn "Root MariaDB are deja o parolă (ignorat)."

# Securizare completă
mysql -u root --password="${MYSQL_ROOT_PASS}" << MYSQL_EOF
-- Ștergere utilizatori anonimi
DELETE FROM mysql.user WHERE User='';
-- Ștergere baza de date test
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
-- Root doar local
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
-- Creare utilizator admin dedicat
CREATE USER IF NOT EXISTS '${MYSQL_ADMIN_USER}'@'localhost' IDENTIFIED BY '${MYSQL_ADMIN_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_ADMIN_USER}'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
MYSQL_EOF

# Hardening my.cnf
cat > /etc/mysql/conf.d/hardening.cnf << 'EOF'
[mysqld]
# Dezactivare conectare remote
bind-address            = 127.0.0.1
skip-networking         = 0
local-infile            = 0

# Performanță WordPress
innodb_buffer_pool_size = 256M
innodb_log_file_size    = 64M
innodb_flush_method     = O_DIRECT
query_cache_type        = 1
query_cache_size        = 32M
max_connections         = 150
wait_timeout            = 300
interactive_timeout     = 300

# Logging
slow_query_log          = 1
slow_query_log_file     = /var/log/mysql/slow.log
long_query_time         = 2
EOF

systemctl restart mariadb
info "MariaDB instalat și hardened. Admin: ${MYSQL_ADMIN_USER}@localhost"

# ══════════════════════════════════════════════════════════════════════════════
section "5 / 9 — Fail2Ban"
# ══════════════════════════════════════════════════════════════════════════════

DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
systemctl enable --now fail2ban

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime         = 86400
findtime        = 600
maxretry        = 3
ignoreip        = 127.0.0.1/8 ::1
banaction       = ufw
banaction_allports = ufw

[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log
maxretry = 3

[apache-auth]
enabled  = true
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache2/error.log
maxretry = 3

[apache-badbots]
enabled  = true
port     = http,https
filter   = apache-badbots
logpath  = /var/log/apache2/access.log
maxretry = 1
bantime  = 604800

[apache-noscript]
enabled  = true
port     = http,https
filter   = apache-noscript
logpath  = /var/log/apache2/error.log

[apache-overflows]
enabled  = true
port     = http,https
filter   = apache-overflows
logpath  = /var/log/apache2/error.log
maxretry = 2

[apache-shellshock]
enabled  = true
port     = http,https
filter   = apache-shellshock
logpath  = /var/log/apache2/error.log
maxretry = 1
bantime  = 604800

[wordpress-xmlrpc]
enabled  = true
port     = http,https
filter   = wordpress-xmlrpc
logpath  = /var/log/apache2/*access.log
maxretry = 2
bantime  = 604800

[wordpress-login]
enabled  = true
port     = http,https
filter   = wordpress-login
logpath  = /var/log/apache2/*access.log
maxretry = 5
findtime = 300
bantime  = 86400
EOF

# Filtru WordPress xmlrpc
cat > /etc/fail2ban/filter.d/wordpress-xmlrpc.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "POST .*xmlrpc\.php
ignoreregex =
EOF

# Filtru WordPress login
cat > /etc/fail2ban/filter.d/wordpress-login.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "POST .*wp-login\.php
ignoreregex =
EOF

# Filtru Apache shellshock
cat > /etc/fail2ban/filter.d/apache-shellshock.conf << 'EOF'
[Definition]
failregex = ^<HOST> .*\(\) \{
ignoreregex =
EOF

systemctl restart fail2ban
info "Fail2Ban configurat cu reguli WordPress."

# ══════════════════════════════════════════════════════════════════════════════
section "6 / 9 — UFW Firewall"
# ══════════════════════════════════════════════════════════════════════════════

DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Porturi necesare
ufw allow OpenSSH          comment 'SSH'
ufw allow 80/tcp           comment 'HTTP'
ufw allow 443/tcp          comment 'HTTPS'
ufw allow 10000/tcp        comment 'Webmin'

# Rate limiting SSH (anti brute-force)
ufw limit ssh comment 'SSH rate limit'

ufw --force enable
info "UFW activat: SSH, HTTP, HTTPS, Webmin permise."

# ══════════════════════════════════════════════════════════════════════════════
section "7 / 9 — Webmin"
# ══════════════════════════════════════════════════════════════════════════════

curl -fsSL https://download.webmin.com/jcameron-key.asc \
    | gpg --dearmor -o /usr/share/keyrings/webmin-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/webmin-keyring.gpg] https://download.webmin.com/download/repository sarge contrib" \
    > /etc/apt/sources.list.d/webmin.list

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y webmin
systemctl enable --now webmin
info "Webmin instalat."

# ══════════════════════════════════════════════════════════════════════════════
section "8 / 9 — Actualizări automate & Hardening OS"
# ══════════════════════════════════════════════════════════════════════════════

# Unattended upgrades (doar security)
DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades apt-listchanges
dpkg-reconfigure -f noninteractive unattended-upgrades

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Autoremove "1";
EOF

# Hardening SSH
SSH_CFG="/etc/ssh/sshd_config"
cp "$SSH_CFG" "${SSH_CFG}.bak"
sed -i \
    -e 's/^#\?PermitRootLogin.*/PermitRootLogin no/' \
    -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' \
    -e 's/^#\?X11Forwarding.*/X11Forwarding no/' \
    -e 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' \
    -e 's/^#\?LoginGraceTime.*/LoginGraceTime 30/' \
    -e 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' \
    -e 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' \
    "$SSH_CFG"

# Banner SSH
echo "Unauthorized access is prohibited. All sessions are logged." \
    > /etc/issue.net
grep -q "^Banner" "$SSH_CFG" || echo "Banner /etc/issue.net" >> "$SSH_CFG"

systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

# Hardening kernel (sysctl)
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# Protecție IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Dezactivare ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Dezactivare source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log pachete suspecte
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Dezactivare IPv6 dacă nu e folosit
# net.ipv6.conf.all.disable_ipv6 = 1

# Protecție core dump
fs.suid_dumpable = 0

# Shared memory protection
kernel.randomize_va_space = 2
EOF

sysctl -p /etc/sysctl.d/99-hardening.conf > /dev/null 2>&1
info "Hardening OS aplicat (SSH, kernel, sysctl)."

# ══════════════════════════════════════════════════════════════════════════════
section "9 / 9 — Instrucțiuni adăugare site WordPress"
# ══════════════════════════════════════════════════════════════════════════════

# Script helper: adaugă site WordPress nou
cat > /usr/local/bin/add-wp-site << 'WPSCRIPT'
#!/bin/bash
# Utilizare: sudo add-wp-site domeniu.ro db_name db_user db_pass

set -euo pipefail

DOMAIN="${1:?Lipsește domeniu. Ex: add-wp-site domeniu.ro db_name db_user db_pass}"
DB_NAME="${2:?Lipsește numele bazei de date.}"
DB_USER="${3:?Lipsește userul bazei de date.}"
DB_PASS="${4:?Lipsește parola bazei de date.}"
WEB_ROOT="/var/www/${DOMAIN}"

echo "[+] Creare director web: $WEB_ROOT"
mkdir -p "$WEB_ROOT"

echo "[+] Descarcare WordPress..."
curl -sL https://wordpress.org/latest.tar.gz | tar -xz -C /tmp
cp -r /tmp/wordpress/. "$WEB_ROOT/"
chown -R www-data:www-data "$WEB_ROOT"
find "$WEB_ROOT" -type d -exec chmod 755 {} \;
find "$WEB_ROOT" -type f -exec chmod 644 {} \;

echo "[+] Creare bază de date MySQL..."
# Citire parolă admin MySQL
read -s -p "Parolă MySQL admin: " MYSQL_ADMIN_PASS; echo
read -p "Username MySQL admin: " MYSQL_ADMIN_USER

mysql -u "$MYSQL_ADMIN_USER" --password="$MYSQL_ADMIN_PASS" << SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

echo "[+] Configurare wp-config.php..."
cp "$WEB_ROOT/wp-config-sample.php" "$WEB_ROOT/wp-config.php"
sed -i \
    -e "s/database_name_here/${DB_NAME}/" \
    -e "s/username_here/${DB_USER}/" \
    -e "s/password_here/${DB_PASS}/" \
    "$WEB_ROOT/wp-config.php"

# Generare WordPress secret keys
KEYS=$(curl -sL https://api.wordpress.org/secret-key/1.1/salt/)
# Înlocuire bloc de chei placeholder
python3 - "$WEB_ROOT/wp-config.php" "$KEYS" << 'PY'
import sys, re
cfg_path = sys.argv[1]
keys = sys.argv[2]
with open(cfg_path, 'r') as f:
    content = f.read()
pattern = r"define\( 'AUTH_KEY'.*?define\( 'NONCE_SALT'.*?\);"
content = re.sub(pattern, keys.strip(), content, flags=re.DOTALL)
with open(cfg_path, 'w') as f:
    f.write(content)
PY

chmod 640 "$WEB_ROOT/wp-config.php"
chown www-data:www-data "$WEB_ROOT/wp-config.php"

echo "[+] Creare VirtualHost Apache..."
VHOST="/etc/apache2/sites-available/${DOMAIN}.conf"
cat > "$VHOST" << VHEOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ServerAlias www.${DOMAIN}
    DocumentRoot ${WEB_ROOT}

    <Directory ${WEB_ROOT}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <Files xmlrpc.php>
        Require all denied
    </Files>
    <Files wp-config.php>
        Require all denied
    </Files>

    ErrorLog  \${APACHE_LOG_DIR}/${DOMAIN}-error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}-access.log combined
</VirtualHost>
VHEOF

a2ensite "${DOMAIN}.conf"
systemctl reload apache2

echo ""
echo "══════════════════════════════════════════════════════"
echo "  ✅ Site adăugat cu succes!"
echo "  🌐 URL:      http://${DOMAIN}"
echo "  📁 Web root: ${WEB_ROOT}"
echo "  🗄️  DB:       ${DB_NAME} / user: ${DB_USER}"
echo ""
echo "  Pasul următor — SSL gratuit cu Let's Encrypt:"
echo "  sudo certbot --apache -d ${DOMAIN} -d www.${DOMAIN}"
echo "══════════════════════════════════════════════════════"
WPSCRIPT

chmod +x /usr/local/bin/add-wp-site
info "Script helper 'add-wp-site' instalat în /usr/local/bin/"

# ══════════════════════════════════════════════════════════════════════════════
# Cleanup
# ══════════════════════════════════════════════════════════════════════════════

apt-get autoremove -y -qq
apt-get autoclean -qq

# Pagină Apache default
echo "<html><body><h1>Server activ</h1></body></html>" \
    > /var/www/html/index.html
chown www-data:www-data /var/www/html/index.html

# ══════════════════════════════════════════════════════════════════════════════
# Sumar final
# ══════════════════════════════════════════════════════════════════════════════

SERVER_IP=$(hostname -I | awk '{print $1}')
INSTALLED_PHP=$(php -r 'echo PHP_VERSION;')

echo
echo -e "${BOLD}${GREEN}"
cat << 'DONE'
  ╔══════════════════════════════════════════════════════════════╗
  ║                ✅ INSTALARE FINALIZATĂ                       ║
  ╚══════════════════════════════════════════════════════════════╝
DONE
echo -e "${NC}"
echo -e "  ${CYAN}Server IP:${NC}     $SERVER_IP"
echo -e "  ${CYAN}PHP:${NC}           $INSTALLED_PHP"
echo -e "  ${CYAN}Apache:${NC}        http://${SERVER_IP}"
echo -e "  ${CYAN}Webmin:${NC}        https://${SERVER_IP}:10000"
echo -e "  ${CYAN}MySQL admin:${NC}   ${MYSQL_ADMIN_USER}@localhost"
echo
echo -e "  ${YELLOW}━━━ PAȘI URMĂTORI ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}1. Adaugă un site WordPress:${NC}"
echo -e "     sudo add-wp-site domeniu.ro db_name db_user db_pass"
echo
echo -e "  ${BOLD}2. Instalează SSL gratuit (Certbot):${NC}"
echo -e "     sudo apt install certbot python3-certbot-apache -y"
echo -e "     sudo certbot --apache -d domeniu.ro -d www.domeniu.ro"
echo
echo -e "  ${BOLD}3. Verificare Fail2Ban:${NC}"
echo -e "     sudo fail2ban-client status"
echo
echo -e "  ${BOLD}4. Verificare UFW:${NC}"
echo -e "     sudo ufw status verbose"
echo
echo -e "  ${CYAN}Log instalare:${NC} $LOG"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo