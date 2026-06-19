#!/bin/bash
# ==============================================================================
# WordPress Web Server - Setup complet pentru Ubuntu Server clean install
# ------------------------------------------------------------------------------
# Apache + ModSecurity(WAF) + mod_evasive
# PHP + toate dependintele WordPress
# MariaDB  -> root FARA parola, accesibil DOAR prin `sudo mariadb` (unix_socket)
# Fail2Ban (jail-uri extinse) + UFW (hardened, admin LAN-only)
# Webmin (instalat din pachet .deb descarcat manual)
# Hardening OS: auditd, AppArmor, pwquality, faillock, sysctl, SSH
#
# Compatibil: Ubuntu Server 22.04 / 24.04 LTS
# Rulare:     sudo bash setup_wordpress_server.sh
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

LOG="/var/log/wp_server_setup.log"
exec > >(tee -a "$LOG") 2>&1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[X] EROARE:${NC} $*"; exit 1; }
section() { echo -e "\n${BOLD}${BLUE}===================================================${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}===================================================${NC}"; }

# ── Preflight ───────────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && error "Ruleaza cu: sudo bash $0"

if ! grep -qi "ubuntu" /etc/os-release; then
    warn "Optimizat pentru Ubuntu. Continui pe propriul risc."
fi
UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)

# Utilizatorul real (cel care a dat sudo) - pentru acces MariaDB prin socket
ADMIN_OS_USER="${SUDO_USER:-root}"

clear
cat << 'BANNER'
  ==============================================================
            WordPress Server - Setup automat (clean)
     Apache+WAF . PHP . MariaDB . Fail2Ban . UFW . Webmin
  ==============================================================
BANNER

info "Ubuntu $UBUNTU_VERSION | Utilizator admin OS: $ADMIN_OS_USER"

# ── Detectare retea locala (pentru acces admin LAN-only) ───────────────────────
section "Detectare retea locala (LAN)"
LAN_IFACE=$(ip route | awk '/^default/ {print $5; exit}')
DETECTED_SUBNET=$(ip route | awk '/proto kernel scope link/ {print $1; exit}')
SERVER_IP=$(hostname -I | awk '{print $1}')

echo "  Interfata principala: ${LAN_IFACE:-?}"
echo "  IP server:            ${SERVER_IP:-?}"
echo "  Subretea detectata:   ${DETECTED_SUBNET:-?}"
echo
echo "  Acces admin (SSH + Webmin) va fi permis DOAR din aceasta subretea."
read -p "  -> Confirma subreteaua LAN (Enter = ${DETECTED_SUBNET}): " LAN_SUBNET
LAN_SUBNET="${LAN_SUBNET:-$DETECTED_SUBNET}"
[[ -z "$LAN_SUBNET" ]] && error "Subretea LAN nedeterminata. Introdu manual (ex: 192.168.1.0/24)."
info "Admin restrictionat la: $LAN_SUBNET"

echo
info "Incepe instalarea..."
sleep 2

# ══════════════════════════════════════════════════════════════════════════════
section "1/11 - Actualizare sistem + unelte securitate"
# ══════════════════════════════════════════════════════════════════════════════
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    software-properties-common apt-transport-https ca-certificates gnupg2 \
    curl wget unzip lsb-release net-tools htop vim git cron logrotate \
    auditd audispd-plugins apparmor apparmor-utils libpam-pwquality \
    libpam-tmpdir acct rkhunter unattended-upgrades apt-listchanges
info "Sistem actualizat + unelte de securitate instalate."

# ══════════════════════════════════════════════════════════════════════════════
section "2/11 - Apache2 + ModSecurity (WAF) + mod_evasive"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2 apache2-utils libapache2-mod-security2 libapache2-mod-evasive
systemctl enable --now apache2

a2enmod rewrite headers ssl expires deflate filter setenvif security2
a2dissite 000-default.conf 2>/dev/null || true
sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' \
    /etc/apache2/apache2.conf 2>/dev/null || true

cat > /etc/apache2/conf-available/hardening.conf << 'EOF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None

# Anti slowloris
Timeout 30
KeepAliveTimeout 5
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500

# Limite request
LimitRequestBody 67108864
LimitRequestFields 100
LimitRequestFieldSize 8190
LimitRequestLine 8190

# Security headers (X-XSS-Protection eliminat - depreciat)
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
Header always set Content-Security-Policy "upgrade-insecure-requests"
Header always unset X-Powered-By
Header always unset Server
Header unset ETag

# Fisiere sensibile blocate
<FilesMatch "(^\.ht|\.git|\.env|\.bak|\.sql|\.log|\.ini|wp-config\.php|readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
<DirectoryMatch "^/.*/(\.git|\.svn|node_modules)/">
    Require all denied
</DirectoryMatch>

<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css
    AddOutputFilterByType DEFLATE application/javascript application/json
    AddOutputFilterByType DEFLATE image/svg+xml
</IfModule>
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/webp "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>
EOF
a2enconf hardening
a2dismod -f status 2>/dev/null || true
a2dismod -f info 2>/dev/null || true

# ModSecurity in mod blocare + OWASP CRS
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
sed -i 's/^SecResponseBodyAccess .*/SecResponseBodyAccess Off/' /etc/modsecurity/modsecurity.conf
DEBIAN_FRONTEND=noninteractive apt-get install -y modsecurity-crs 2>/dev/null || \
    warn "modsecurity-crs indisponibil; CRS poate necesita configurare manuala."
if [[ -d /usr/share/modsecurity-crs ]]; then
    # IMPORTANT: includem DOAR fisierul *.load (owasp-crs.load), care la randul lui
    # incarca crs-setup.conf + rules/*.conf. NU includem si rules/*.conf separat,
    # altfel regulile se incarca de doua ori -> "another rule with the same id".
    cat > /etc/apache2/mods-available/security2.conf << 'EOF'
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>
EOF
    info "OWASP CRS legat la ModSecurity (incarcare unica)."
fi

# mod_evasive (anti DoS)
cat > /etc/apache2/mods-available/evasive.conf << 'EOF'
<IfModule mod_evasive20.c>
    DOSHashTableSize    3097
    DOSPageCount        5
    DOSSiteCount        100
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   60
    DOSLogDir           "/var/log/mod_evasive"
</IfModule>
EOF
mkdir -p /var/log/mod_evasive
chown www-data:www-data /var/log/mod_evasive
a2enmod evasive

cat > /etc/apache2/sites-available/wordpress-template.conf << 'EOF'
# Foloseste comanda 'add-wp-site' pentru a crea site-uri noi
<VirtualHost *:80>
    ServerName DOMENIU_TBD
    ServerAlias www.DOMENIU_TBD
    DocumentRoot /var/www/DOMENIU_TBD
    <Directory /var/www/DOMENIU_TBD>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    <Files xmlrpc.php>
        Require all denied
    </Files>
    ErrorLog  ${APACHE_LOG_DIR}/DOMENIU_TBD-error.log
    CustomLog ${APACHE_LOG_DIR}/DOMENIU_TBD-access.log combined
</VirtualHost>
EOF

apache2ctl configtest && systemctl restart apache2
info "Apache + ModSecurity(blocare) + mod_evasive activ."

# ══════════════════════════════════════════════════════════════════════════════
section "3/11 - PHP + dependinte WordPress"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y php libapache2-mod-php
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
info "PHP $PHP_VER detectat."

# Extensii cerute / recomandate de WordPress
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    "php${PHP_VER}-mysql" "php${PHP_VER}-curl" "php${PHP_VER}-xml" \
    "php${PHP_VER}-mbstring" "php${PHP_VER}-zip" "php${PHP_VER}-gd" \
    "php${PHP_VER}-imagick" "php${PHP_VER}-intl" "php${PHP_VER}-bcmath" \
    "php${PHP_VER}-soap" "php${PHP_VER}-cli" "php${PHP_VER}-opcache" 2>/dev/null || \
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    php-mysql php-curl php-xml php-mbstring php-zip php-gd \
    php-intl php-bcmath php-soap php-cli

harden_php() {
    local ini_file="$1"
    [[ ! -f "$ini_file" ]] && return
    cp "$ini_file" "${ini_file}.bak"
    sed -i \
        -e 's/^expose_php.*/expose_php = Off/' \
        -e 's/^display_errors.*/display_errors = Off/' \
        -e 's/^display_startup_errors.*/display_startup_errors = Off/' \
        -e 's/^log_errors.*/log_errors = On/' \
        -e 's/^upload_max_filesize.*/upload_max_filesize = 64M/' \
        -e 's/^post_max_size.*/post_max_size = 64M/' \
        -e 's/^max_execution_time.*/max_execution_time = 120/' \
        -e 's/^max_input_time.*/max_input_time = 120/' \
        -e 's/^memory_limit.*/memory_limit = 256M/' \
        -e 's/^allow_url_fopen.*/allow_url_fopen = Off/' \
        -e 's/^allow_url_include.*/allow_url_include = Off/' \
        -e 's/^;\?cgi.fix_pathinfo.*/cgi.fix_pathinfo = 0/' \
        -e 's/^;\?session.cookie_httponly.*/session.cookie_httponly = 1/' \
        -e 's/^;\?session.cookie_secure.*/session.cookie_secure = 1/' \
        -e 's/^;\?session.use_strict_mode.*/session.use_strict_mode = 1/' \
        -e 's/^;\?session.cookie_samesite.*/session.cookie_samesite = "Strict"/' \
        "$ini_file"
    grep -q "^disable_functions" "$ini_file" && \
        sed -i 's/^disable_functions.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source,proc_get_status,pcntl_exec/' "$ini_file" || \
        echo 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source,proc_get_status,pcntl_exec' >> "$ini_file"
    grep -q "opcache.enable=1" "$ini_file" || cat >> "$ini_file" << 'OPCACHE'

; OPcache WordPress
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=4000
opcache.revalidate_freq=2
opcache.fast_shutdown=1
OPCACHE
}
harden_php "/etc/php/${PHP_VER}/apache2/php.ini"
harden_php "/etc/php/${PHP_VER}/cli/php.ini"

systemctl restart apache2
info "PHP $PHP_VER instalat + hardened."

# ══════════════════════════════════════════════════════════════════════════════
section "4/11 - MariaDB (root DOAR prin sudo, fara parola)"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client
systemctl enable --now mariadb

# Pe Ubuntu, root@localhost foloseste implicit pluginul unix_socket:
#   -> singura cale de acces este `sudo mariadb` / `sudo mysql` (ca root de sistem)
#   -> nu exista parola root, deci nu poate fi atacat prin brute-force
# Aici doar intarim acest comportament si curatam instalarea.
mariadb << MYSQL_EOF
-- Curatare utilizatori anonimi (compatibil cu toate versiunile)
DROP USER IF EXISTS ''@'localhost';
DROP USER IF EXISTS ''@'$(hostname)';

-- Stergere baza de date de test
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db LIKE 'test\\_%';

-- Asigura ca root e DOAR pe localhost + unix_socket, fara parola
ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket;
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');

FLUSH PRIVILEGES;
MYSQL_EOF

# Cont admin mapat pe utilizatorul tau de sistem (acces via socket, fara parola).
# Astfel poti rula 'mariadb' direct cand esti logat ca '$ADMIN_OS_USER',
# pe langa 'sudo mariadb' (ca root). Sarit daca ai rulat scriptul direct ca root.
if [[ "$ADMIN_OS_USER" != "root" ]]; then
    mariadb << MYSQL_ADMIN_EOF
CREATE USER IF NOT EXISTS '${ADMIN_OS_USER}'@'localhost' IDENTIFIED VIA unix_socket;
GRANT ALL PRIVILEGES ON *.* TO '${ADMIN_OS_USER}'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
MYSQL_ADMIN_EOF
    info "Cont admin MariaDB '$ADMIN_OS_USER' creat (acces via socket)."
fi

# query_cache eliminat (depreciat in MariaDB 10.3+)
cat > /etc/mysql/conf.d/hardening.cnf << 'EOF'
[mysqld]
bind-address            = 127.0.0.1
skip-name-resolve       = 1
local-infile            = 0
skip-symbolic-links     = 1
secure_file_priv        = /var/lib/mysql-files

innodb_buffer_pool_size = 256M
innodb_flush_method     = O_DIRECT
max_connections         = 150
wait_timeout            = 300
interactive_timeout     = 300

slow_query_log          = 1
slow_query_log_file     = /var/log/mysql/slow.log
long_query_time         = 2
EOF
mkdir -p /var/lib/mysql-files && chown mysql:mysql /var/lib/mysql-files

systemctl restart mariadb
info "MariaDB: root accesibil DOAR prin 'sudo mariadb'. Admin socket: $ADMIN_OS_USER"

# ══════════════════════════════════════════════════════════════════════════════
section "5/11 - Fail2Ban"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
systemctl enable --now fail2ban

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime         = 86400
findtime        = 600
maxretry        = 3
# ignoreip include DOAR localhost - NU toata subreteaua LAN
# (un dispozitiv compromis din LAN nu trebuie sa fie imun la ban)
ignoreip        = 127.0.0.1/8 ::1
banaction       = ufw
banaction_allports = ufw

# ── SSH ──────────────────────────────────────────────────────────────────────
[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 86400

# ── Apache - autentificare ────────────────────────────────────────────────────
[apache-auth]
enabled  = true
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache2/error.log
maxretry = 3

# ── Apache - boti rau intentionati ───────────────────────────────────────────
[apache-badbots]
enabled  = true
port     = http,https
filter   = apache-badbots
logpath  = /var/log/apache2/access.log
maxretry = 1
bantime  = 604800

# ── Apache - cereri fara script (scanere) ─────────────────────────────────────
[apache-noscript]
enabled  = true
port     = http,https
filter   = apache-noscript
logpath  = /var/log/apache2/error.log
maxretry = 3

# ── Apache - overflow/buffer attacks ──────────────────────────────────────────
[apache-overflows]
enabled  = true
port     = http,https
filter   = apache-overflows
logpath  = /var/log/apache2/error.log
maxretry = 2
bantime  = 604800

# ── Apache - Shellshock (CVE-2014-6271) ───────────────────────────────────────
[apache-shellshock]
enabled  = true
port     = http,https
filter   = apache-shellshock
logpath  = /var/log/apache2/error.log
maxretry = 1
bantime  = 604800

# ── ModSecurity WAF ───────────────────────────────────────────────────────────
[apache-modsecurity]
enabled  = true
port     = http,https
filter   = apache-modsecurity
logpath  = /var/log/apache2/error.log
maxretry = 3
bantime  = 604800

# ── WordPress - atac xmlrpc (DDoS amplification + brute-force) ───────────────
[wordpress-xmlrpc]
enabled  = true
port     = http,https
filter   = wordpress-xmlrpc
logpath  = /var/log/apache2/*access.log
maxretry = 1
bantime  = 604800

# ── WordPress - brute-force pe pagina de login ────────────────────────────────
[wordpress-login]
enabled  = true
port     = http,https
filter   = wordpress-login
logpath  = /var/log/apache2/*access.log
maxretry = 5
findtime = 300
bantime  = 86400

# ── Scanere de vulnerabilitati (WPScan, Nikto, etc.) ─────────────────────────
[wordpress-scanner]
enabled  = true
port     = http,https
filter   = wordpress-scanner
logpath  = /var/log/apache2/*access.log
maxretry = 10
findtime = 60
bantime  = 604800

# ── Cereri catre fisiere sensibile (.env, .git, wp-config, etc.) ─────────────
[apache-sensitive-files]
enabled  = true
port     = http,https
filter   = apache-sensitive-files
logpath  = /var/log/apache2/*access.log
maxretry = 2
bantime  = 604800

# ── Recidivisti (banati de 3 ori in 24h -> 14 zile) ──────────────────────────
[recidive]
enabled   = true
logpath   = /var/log/fail2ban.log
banaction = ufw
bantime   = 1209600
findtime  = 86400
maxretry  = 3
EOF

# ── Filtre personalizate ───────────────────────────────────────────────────────

cat > /etc/fail2ban/filter.d/wordpress-xmlrpc.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "POST .*xmlrpc\.php
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/wordpress-login.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "POST .*wp-login\.php
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/apache-shellshock.conf << 'EOF'
[Definition]
failregex = ^<HOST> .*\(\) \{
ignoreregex =
EOF

# Fix: regex pe o singura linie per varianta, prefix 'failregex +=' pentru a doua
cat > /etc/fail2ban/filter.d/apache-modsecurity.conf << 'EOF'
[Definition]
failregex = \[client <HOST>\] ModSecurity: Access denied
ignoreregex =
EOF

# Scanere - User-Agent cunoscute + pattern-uri de scan masiv
cat > /etc/fail2ban/filter.d/wordpress-scanner.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) .*(wp-content/plugins/|wp-includes/|\.php\?).* HTTP.*" (404|403|400) .*$
            ^<HOST> .*"(GET|POST) /(\?|index\.php\?|xmlrpc\.php|wp-json/).* HTTP.*" 4[0-9][0-9] .*$
ignoreregex = ^<HOST> .* "GET /wp-content/uploads/
              ^<HOST> .* "GET /wp-content/themes/
EOF

# Cereri catre fisiere sensibile
cat > /etc/fail2ban/filter.d/apache-sensitive-files.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST) .*(/\.env|/\.git|/wp-config\.php|/wp-config\.bak|/etc/passwd|/etc/shadow|/\.htaccess|/xmlrpc\.php|/readme\.html|/license\.txt|/web\.config|/\.svn|/backup|/dump\.sql)
ignoreregex =
EOF

systemctl restart fail2ban
info "Fail2Ban activ (SSH, Apache, ModSecurity, WordPress, scanere, fisiere sensibile, recidive)."

# ══════════════════════════════════════════════════════════════════════════════
section "6/11 - UFW Firewall (hardened, admin LAN-only)"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
ufw --force reset
ufw default deny incoming
ufw default deny outgoing

# Outgoing strict (doar ce e necesar)
ufw allow out 53                comment 'DNS'
ufw allow out 80/tcp            comment 'HTTP out (update-uri)'
ufw allow out 443/tcp           comment 'HTTPS out (update-uri)'
ufw allow out 123/udp           comment 'NTP'
ufw allow out 25/tcp            comment 'SMTP'
ufw allow out 587/tcp           comment 'SMTP submission'
ufw allow out 465/tcp           comment 'SMTPS'

# Web public
ufw allow 80/tcp                comment 'HTTP public'
ufw allow 443/tcp               comment 'HTTPS public'

# Admin DOAR din LAN
# NOTA: pentru SSH folosim DOAR 'limit' (max 6 conexiuni/30s) - nu si 'allow' separat
# (daca ambele exista, se anuleaza reciproc; 'limit' include si permisiunea de acces)
ufw limit from "$LAN_SUBNET" to any port 22    proto tcp comment 'SSH LAN - rate limited'
ufw allow from "$LAN_SUBNET" to any port 10000 proto tcp comment 'Webmin LAN'

ufw --force enable
info "UFW: web public (80/443); SSH+Webmin doar din $LAN_SUBNET."

# ══════════════════════════════════════════════════════════════════════════════
section "7/11 - Webmin (.deb manual, acces LAN-only)"
# ══════════════════════════════════════════════════════════════════════════════
wget https://www.webmin.com/download/deb/webmin-current.deb -O /tmp/webmin.deb
DEBIAN_FRONTEND=noninteractive apt install -y /tmp/webmin.deb
rm -f /tmp/webmin.deb

if [[ -f /etc/webmin/miniserv.conf ]]; then
    grep -q "^allow=" /etc/webmin/miniserv.conf || \
        echo "allow=${LAN_SUBNET} 127.0.0.1 localhost" >> /etc/webmin/miniserv.conf
    sed -i 's/^ssl=.*/ssl=1/' /etc/webmin/miniserv.conf 2>/dev/null || echo "ssl=1" >> /etc/webmin/miniserv.conf
    grep -q "^ssl_cipher_list=" /etc/webmin/miniserv.conf || \
        echo "ssl_cipher_list=ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS" >> /etc/webmin/miniserv.conf
    systemctl restart webmin
fi
systemctl enable --now webmin
info "Webmin instalat, acces restrictionat la $LAN_SUBNET."

# ══════════════════════════════════════════════════════════════════════════════
section "8/11 - Hardening SSH"
# ══════════════════════════════════════════════════════════════════════════════
echo "ACCES INTERZIS persoanelor neautorizate. Sesiunile sunt monitorizate." > /etc/issue.net
cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes

X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

LogLevel VERBOSE
Banner /etc/issue.net
EOF
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || \
    systemctl restart ssh 2>/dev/null || true
info "SSH hardened. Parola ramane activa (pune chei SSH si dezactiveaz-o ulterior)."

# ══════════════════════════════════════════════════════════════════════════════
section "9/11 - Hardening kernel, login, fisiere"
# ══════════════════════════════════════════════════════════════════════════════
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl --system > /dev/null 2>&1 || true

# Core dumps off
grep -q '^\* hard core 0' /etc/security/limits.conf || echo '* hard core 0' >> /etc/security/limits.conf

# Politica parole
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
difok = 5
maxrepeat = 3
gecoscheck = 1
enforcing = 1
EOF

# Lockout cont
if [[ -f /etc/security/faillock.conf ]]; then
    sed -i \
        -e 's/^# *deny =.*/deny = 5/' \
        -e 's/^# *unlock_time =.*/unlock_time = 900/' \
        -e 's/^# *fail_interval =.*/fail_interval = 900/' \
        /etc/security/faillock.conf
fi

# UMASK + expirare parole
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs 2>/dev/null || true
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs 2>/dev/null || true

# Blacklist module/protocoale neuzuale
cat > /etc/modprobe.d/blacklist-hardening.conf << 'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
# install usb-storage /bin/true   # decomenteaza daca nu folosesti USB pe server
EOF

# Shared memory securizat
grep -q "/run/shm" /etc/fstab || \
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab

# Cron restrictionat
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny 2>/dev/null || true

# Permisiuni fisiere
chmod 600 /etc/ssh/sshd_config
chmod 640 /etc/shadow 2>/dev/null || true

# auditd + accounting + AppArmor
systemctl enable --now auditd 2>/dev/null || true
systemctl enable --now acct 2>/dev/null || systemctl enable --now psacct 2>/dev/null || true
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /var/www -p wa -k web_content
-w /etc/apache2 -p wa -k apache_config
EOF
augenrules --load 2>/dev/null || true
info "Hardening kernel/login/fisiere aplicat."

# ══════════════════════════════════════════════════════════════════════════════
section "10/11 - Actualizari automate de securitate"
# ══════════════════════════════════════════════════════════════════════════════
dpkg-reconfigure -f noninteractive unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Autoremove "1";
EOF
cat > /etc/apt/apt.conf.d/51unattended-reboot << 'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
info "Actualizari automate activate (+reboot la 04:00 daca e nevoie)."

# ══════════════════════════════════════════════════════════════════════════════
section "11/11 - Helper add-wp-site"
# ══════════════════════════════════════════════════════════════════════════════
cat > /usr/local/bin/add-wp-site << 'WPSCRIPT'
#!/bin/bash
# Creeaza un site WordPress nou.
# Utilizare: sudo add-wp-site domeniu.ro db_name db_user db_pass
# Acceseaza MariaDB prin socket (sudo) - nu cere parola de admin.
set -euo pipefail
[[ "$EUID" -ne 0 ]] && { echo "Ruleaza cu sudo."; exit 1; }

DOMAIN="${1:?Lipseste domeniu. Ex: add-wp-site domeniu.ro db_name db_user db_pass}"
DB_NAME="${2:?Lipseste numele bazei de date.}"
DB_USER="${3:?Lipseste userul bazei de date.}"
DB_PASS="${4:?Lipseste parola bazei de date.}"
WEB_ROOT="/var/www/${DOMAIN}"

echo "[+] Director web: $WEB_ROOT"
mkdir -p "$WEB_ROOT"

echo "[+] Descarcare WordPress..."
curl -sL https://wordpress.org/latest.tar.gz | tar -xz -C /tmp
cp -r /tmp/wordpress/. "$WEB_ROOT/"
rm -rf /tmp/wordpress
chown -R www-data:www-data "$WEB_ROOT"
find "$WEB_ROOT" -type d -exec chmod 755 {} \;
find "$WEB_ROOT" -type f -exec chmod 644 {} \;

echo "[+] Creare baza de date (via sudo/socket)..."
mariadb << SQL
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

KEYS=$(curl -sL https://api.wordpress.org/secret-key/1.1/salt/)
python3 - "$WEB_ROOT/wp-config.php" "$KEYS" << 'PY'
import sys, re
cfg, keys = sys.argv[1], sys.argv[2]
c = open(cfg).read()
c = re.sub(r"define\( 'AUTH_KEY'.*?define\( 'NONCE_SALT'.*?\);", keys.strip(), c, flags=re.DOTALL)
if "FS_METHOD" not in c:
    c = c.replace("/* That's all, stop editing!",
                  "define('FS_METHOD','direct');\ndefine('DISALLOW_FILE_EDIT',true);\n\n/* That's all, stop editing!")
open(cfg,'w').write(c)
PY
chmod 640 "$WEB_ROOT/wp-config.php"
chown www-data:www-data "$WEB_ROOT/wp-config.php"

echo "[+] VirtualHost Apache..."
cat > "/etc/apache2/sites-available/${DOMAIN}.conf" << VHEOF
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
    ErrorLog  \${APACHE_LOG_DIR}/${DOMAIN}-error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}-access.log combined
</VirtualHost>
VHEOF
a2ensite "${DOMAIN}.conf"
systemctl reload apache2

echo ""
echo "=================================================="
echo "  Site adaugat: http://${DOMAIN}"
echo "  Web root:     ${WEB_ROOT}"
echo "  DB:           ${DB_NAME} / user: ${DB_USER}"
echo ""
echo "  SSL gratuit (dupa ce domeniul pointeaza la server):"
echo "  sudo apt install certbot python3-certbot-apache -y"
echo "  sudo certbot --apache -d ${DOMAIN} -d www.${DOMAIN}"
echo "=================================================="
WPSCRIPT
chmod +x /usr/local/bin/add-wp-site
info "Helper 'add-wp-site' instalat in /usr/local/bin/."

# ── Cleanup ──────────────────────────────────────────────────────────────────
apt-get autoremove -y -qq
apt-get autoclean -qq
echo "<html><body><h1>Server activ</h1></body></html>" > /var/www/html/index.html
chown www-data:www-data /var/www/html/index.html

# ── Sumar final ──────────────────────────────────────────────────────────────
SERVER_IP=$(hostname -I | awk '{print $1}')
INSTALLED_PHP=$(php -r 'echo PHP_VERSION;')

echo
cat << 'DONE'
  ==================================================================
                    INSTALARE FINALIZATA
  ==================================================================
DONE
echo "  Server IP:    $SERVER_IP"
echo "  PHP:          $INSTALLED_PHP"
echo "  Apache+WAF:   http://${SERVER_IP}   (public)"
echo "  Webmin:       https://${SERVER_IP}:10000   (doar LAN: $LAN_SUBNET)"
echo
echo "  MariaDB: administrare DOAR prin -> sudo mariadb"
echo "           (root fara parola, accesibil exclusiv ca root de sistem)"
echo
echo "  === PASI URMATORI ==="
echo "  1. Adauga un site:   sudo add-wp-site domeniu.ro nume_db user_db parola_db"
echo "  2. SSL:              sudo apt install certbot python3-certbot-apache -y"
echo "                       sudo certbot --apache -d domeniu.ro"
echo "  3. Verificari:       sudo fail2ban-client status ; sudo ufw status verbose"
echo "  4. (Recomandat) Pune chei SSH, apoi dezactiveaza parola:"
echo "       sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/99-hardening.conf"
echo "       sudo systemctl restart ssh"
echo
echo "  ATENTIE: ModSecurity ruleaza in mod BLOCARE. Daca un plugin da 403:"
echo "    sudo sed -i 's/SecRuleEngine On/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf"
echo "    sudo systemctl reload apache2"
echo
echo "  RECOMANDARE: ruleaza 'sudo reboot' pentru a aplica complet hardening-ul."
echo "  Log instalare: $LOG"
echo "  =================================================================="
