#!/bin/bash
# ==============================================================================
# WordPress Web Server — HARDENED MAXIM (LAN-only admin)
# Apache + ModSecurity(WAF) + PHP + MariaDB + Fail2Ban + UFW + Webmin
# Hardening: CIS-aligned · auditd · AppArmor · pwquality · faillock · sysctl
# Compatibil: Ubuntu Server 22.04 / 24.04 LTS
# Rulare: sudo bash wordpress_server_hardened.sh
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
section() { echo -e "\n${BOLD}${BLUE}==============================================${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}==============================================${NC}"; }

[[ "$EUID" -ne 0 ]] && error "Ruleaza cu: sudo bash $0"

if ! grep -qi "ubuntu" /etc/os-release; then
    warn "Optimizat pentru Ubuntu. Continui pe propriul risc."
fi
UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
info "Ubuntu $UBUNTU_VERSION detectat."

read_password() {
    local prompt="$1" varname="$2" pass1 pass2
    while true; do
        read -s -p "  -> $prompt: " pass1; echo
        [[ ${#pass1} -lt 12 ]] && { warn "Minim 12 caractere pentru hardening maxim."; continue; }
        read -s -p "  -> Confirma parola: " pass2; echo
        [[ "$pass1" == "$pass2" ]] && { printf -v "$varname" '%s' "$pass1"; break; }
        warn "Parolele nu coincid."
    done
}

clear
cat << 'BANNER'
  ==========================================================
        WordPress Server - HARDENING MAXIM (LAN-only)
     Apache+WAF . PHP . MariaDB . Fail2Ban . Webmin
  ==========================================================
BANNER

# ── Detectare subretea LAN ─────────────────────────────────────────────────────
section "Detectare retea locala (LAN)"

LAN_IFACE=$(ip route | awk '/^default/ {print $5; exit}')
DETECTED_SUBNET=$(ip route | awk '/proto kernel scope link/ {print $1; exit}')
SERVER_IP=$(hostname -I | awk '{print $1}')

echo "  Interfata principala: ${LAN_IFACE:-necunoscuta}"
echo "  IP server:            ${SERVER_IP:-necunoscut}"
echo "  Subretea detectata:   ${DETECTED_SUBNET:-necunoscuta}"
echo
read -p "  -> Subreteaua LAN pentru acces admin (Enter = ${DETECTED_SUBNET}): " LAN_SUBNET
LAN_SUBNET="${LAN_SUBNET:-$DETECTED_SUBNET}"
[[ -z "$LAN_SUBNET" ]] && error "Nu am putut determina subreteaua LAN. Reintrodu manual (ex: 192.168.1.0/24)."
info "Acces admin (SSH + Webmin) restrictionat la: $LAN_SUBNET"

# ── Credentiale ─────────────────────────────────────────────────────────────────
section "Configurare credentiale"
read -p "  -> Username admin MySQL: " MYSQL_ADMIN_USER
[[ -z "$MYSQL_ADMIN_USER" || "$MYSQL_ADMIN_USER" == "root" ]] && \
    error "Alege un username diferit de 'root' si nevid."
read_password "Parola admin MySQL ($MYSQL_ADMIN_USER)" MYSQL_ADMIN_PASS
read_password "Parola root MySQL (interna/backup)" MYSQL_ROOT_PASS

echo
info "Date colectate. Incepe instalarea blindata..."
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
info "Sistem actualizat si unelte de securitate instalate."

# ══════════════════════════════════════════════════════════════════════════════
section "2/11 - Apache2 + ModSecurity (WAF) + mod_evasive"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2 apache2-utils \
    libapache2-mod-security2 \
    libapache2-mod-evasive
systemctl enable --now apache2

a2enmod rewrite headers ssl expires deflate filter setenvif security2

a2dissite 000-default.conf 2>/dev/null || true

# Dezactivare semnatura + indexare globala
sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' \
    /etc/apache2/apache2.conf 2>/dev/null || true

# Hardening global Apache
cat > /etc/apache2/conf-available/hardening.conf << 'EOF'
# Ascunde versiunea
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None

# Timeout-uri reduse (anti slowloris)
Timeout 30
KeepAliveTimeout 5
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500

# Limite request (anti abuz)
LimitRequestBody 67108864
LimitRequestFields 100
LimitRequestFieldSize 8190
LimitRequestLine 8190

# Security headers (X-XSS-Protection eliminat - depreciat/periculos)
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), interest-cohort=()"
Header always set Content-Security-Policy "upgrade-insecure-requests"
Header always unset X-Powered-By
Header always unset Server
Header unset ETag

# Blocheaza fisiere sensibile
<FilesMatch "(^\.ht|\.git|\.env|\.bak|\.sql|\.log|\.ini|wp-config\.php|readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>

# Dezactiveaza acces la directoare de sistem WordPress sensibile
<DirectoryMatch "^/.*/(\.git|\.svn|node_modules)/">
    Require all denied
</DirectoryMatch>

# Compresie
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css
    AddOutputFilterByType DEFLATE application/javascript application/json
    AddOutputFilterByType DEFLATE image/svg+xml
</IfModule>

# Cache static
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

# Dezactiveaza server-status / server-info expuse
a2dismod -f status 2>/dev/null || true
a2dismod -f info 2>/dev/null || true

# ── ModSecurity: activare in mod BLOCARE + OWASP CRS ──────────────────────────
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
sed -i 's/^SecResponseBodyAccess .*/SecResponseBodyAccess Off/' /etc/modsecurity/modsecurity.conf
# Limita upload pentru WAF aliniata cu PHP
sed -i 's/^SecRequestBodyLimit .*/SecRequestBodyLimit 67108864/' /etc/modsecurity/modsecurity.conf 2>/dev/null || true

# OWASP Core Rule Set
DEBIAN_FRONTEND=noninteractive apt-get install -y modsecurity-crs 2>/dev/null || \
    warn "Pachet modsecurity-crs indisponibil; CRS poate necesita instalare manuala."

# Leaga CRS daca exista
if [[ -d /usr/share/modsecurity-crs ]]; then
    cat > /etc/apache2/mods-available/security2.conf << 'EOF'
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /usr/share/modsecurity-crs/*.load
    IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
</IfModule>
EOF
    info "OWASP CRS legat la ModSecurity."
fi

# ── mod_evasive (anti DoS/flood) ──────────────────────────────────────────────
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

# Template VirtualHost
cat > /etc/apache2/sites-available/wordpress-template.conf << 'EOF'
# Copiaza pentru fiecare site: foloseste comanda 'add-wp-site'
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
info "Apache + ModSecurity(WAF, blocare) + mod_evasive activ."

# ══════════════════════════════════════════════════════════════════════════════
section "3/11 - PHP (dependinte WordPress + hardening)"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y php libapache2-mod-php
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
info "PHP $PHP_VER detectat."

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
        -e 's/^;\?error_log =.*/error_log = \/var\/log\/php_errors.log/' \
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
    # Functii periculoase dezactivate
    grep -q "^disable_functions" "$ini_file" && \
        sed -i 's/^disable_functions.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source,proc_get_status,pcntl_exec/' "$ini_file" || \
        echo 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source,proc_get_status,pcntl_exec' >> "$ini_file"
    # OPcache
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
touch /var/log/php_errors.log && chown www-data:www-data /var/log/php_errors.log

systemctl restart apache2
info "PHP $PHP_VER instalat si hardened (disable_functions, allow_url_*, cookies)."

# ══════════════════════════════════════════════════════════════════════════════
section "4/11 - MariaDB (hardened)"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client
systemctl enable --now mariadb

mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';" 2>/dev/null || \
    warn "Root MariaDB are deja parola (ignorat)."

mysql -u root --password="${MYSQL_ROOT_PASS}" << MYSQL_EOF
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
CREATE USER IF NOT EXISTS '${MYSQL_ADMIN_USER}'@'localhost' IDENTIFIED BY '${MYSQL_ADMIN_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_ADMIN_USER}'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
MYSQL_EOF

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
info "MariaDB hardened (bind localhost, local-infile off, secure_file_priv)."

# ══════════════════════════════════════════════════════════════════════════════
section "5/11 - Fail2Ban (jail-uri extinse)"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
systemctl enable --now fail2ban

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime         = 86400
findtime        = 600
maxretry        = 3
ignoreip        = 127.0.0.1/8 ::1 ${LAN_SUBNET}
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

[apache-modsecurity]
enabled  = true
port     = http,https
filter   = apache-modsecurity
logpath  = /var/log/apache2/error.log
maxretry = 3
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

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = ufw
bantime  = 1209600
findtime = 86400
maxretry = 3
EOF

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
cat > /etc/fail2ban/filter.d/apache-modsecurity.conf << 'EOF'
[Definition]
failregex = \[client <HOST>\] ModSecurity: Access denied
            ModSecurity:.*\[client <HOST>\]
ignoreregex =
EOF

systemctl restart fail2ban
info "Fail2Ban: SSH, Apache, ModSecurity, WordPress, recidive."

# ══════════════════════════════════════════════════════════════════════════════
section "6/11 - UFW Firewall (admin LAN-only)"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
ufw --force reset
ufw default deny incoming
ufw default deny outgoing   # strict: doar porturile de mai jos sunt permise spre exterior

# Outgoing strict necesar (DNS, HTTP/S pentru update-uri, NTP, mail)
ufw allow out 53        comment 'DNS'
ufw allow out 80/tcp    comment 'HTTP out'
ufw allow out 443/tcp   comment 'HTTPS out'
ufw allow out 123/udp   comment 'NTP'
ufw allow out 25/tcp    comment 'SMTP'
ufw allow out 587/tcp   comment 'SMTP submission'
ufw allow out 465/tcp   comment 'SMTPS'

# Web public - deschis catre toti
ufw allow 80/tcp        comment 'HTTP public'
ufw allow 443/tcp       comment 'HTTPS public'

# Admin - DOAR din LAN
ufw allow from "$LAN_SUBNET" to any port 22    proto tcp comment 'SSH LAN'
ufw allow from "$LAN_SUBNET" to any port 10000 proto tcp comment 'Webmin LAN'

# Rate limit SSH chiar si din LAN
ufw limit from "$LAN_SUBNET" to any port 22 proto tcp comment 'SSH rate limit'

ufw --force enable
info "UFW: web public (80/443); SSH+Webmin doar din $LAN_SUBNET."

# ══════════════════════════════════════════════════════════════════════════════
section "7/11 - Webmin (bind LAN, .deb)"
# ══════════════════════════════════════════════════════════════════════════════
wget https://www.webmin.com/download/deb/webmin-current.deb -O /tmp/webmin.deb
DEBIAN_FRONTEND=noninteractive apt install -y /tmp/webmin.deb
rm -f /tmp/webmin.deb

# Bind Webmin doar pe IP-ul LAN + restrictie acces la subreteaua LAN
if [[ -f /etc/webmin/miniserv.conf ]]; then
    # Permite doar LAN
    if ! grep -q "^allow=" /etc/webmin/miniserv.conf; then
        echo "allow=${LAN_SUBNET} 127.0.0.1 localhost" >> /etc/webmin/miniserv.conf
    fi
    # Forteaza SSL + protocoale moderne
    sed -i 's/^ssl=.*/ssl=1/' /etc/webmin/miniserv.conf 2>/dev/null || echo "ssl=1" >> /etc/webmin/miniserv.conf
    grep -q "^ssl_version=" /etc/webmin/miniserv.conf || echo "ssl_version=10" >> /etc/webmin/miniserv.conf
    # Dezactiveaza ciphers slabi
    grep -q "^ssl_cipher_list=" /etc/webmin/miniserv.conf || \
        echo "ssl_cipher_list=ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS" >> /etc/webmin/miniserv.conf
    systemctl restart webmin
fi
systemctl enable --now webmin
info "Webmin instalat, acces restrictionat la $LAN_SUBNET, SSL fortat."

# ══════════════════════════════════════════════════════════════════════════════
section "8/11 - Hardening SSH"
# ══════════════════════════════════════════════════════════════════════════════
SSH_CFG="/etc/ssh/sshd_config"
cp "$SSH_CFG" "${SSH_CFG}.bak"

# IMPORTANT: PasswordAuthentication ramane 'yes' pana configurezi cheile SSH.
# Dupa ce ai pus cheia, schimba in 'no' si: systemctl restart ssh
cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# === SSH HARDENING ===
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes

X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no

MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Cripto moderna (CIS)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

Protocol 2
LogLevel VERBOSE
Banner /etc/issue.net
EOF

echo "ACCES INTERZIS persoanelor neautorizate. Toate sesiunile sunt monitorizate si inregistrate." \
    > /etc/issue.net

systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || \
    systemctl restart ssh 2>/dev/null || true
info "SSH hardened (root off, cripto moderna). Parola ramane activa pana pui cheile."

# ══════════════════════════════════════════════════════════════════════════════
section "9/11 - Hardening kernel, login, fisiere"
# ══════════════════════════════════════════════════════════════════════════════

# --- sysctl ---
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# ICMP redirects off
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
# Source routing off
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
# SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
# Ignora ping broadcast + bogus
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Log martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# RA off (IPv6)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
# Protectii memorie / kernel
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

# --- Dezactivare core dumps ---
echo '* hard core 0' >> /etc/security/limits.conf
echo 'ProcessSizeMax=0' >> /etc/systemd/coredump.conf 2>/dev/null || true
echo 'Storage=none' >> /etc/systemd/coredump.conf 2>/dev/null || true

# --- Politica parole (pwquality) ---
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

# --- Lockout cont la esecuri (faillock) ---
if [[ -f /etc/security/faillock.conf ]]; then
    sed -i \
        -e 's/^# *deny =.*/deny = 5/' \
        -e 's/^# *unlock_time =.*/unlock_time = 900/' \
        -e 's/^# *fail_interval =.*/fail_interval = 900/' \
        /etc/security/faillock.conf
fi

# --- UMASK strict ---
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs 2>/dev/null || true
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs 2>/dev/null || true

# --- Blacklist module/protocoale neutilizate ---
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
# install usb-storage /bin/true   # decomenteaza daca nu folosesti USB stick pe server
EOF

# --- Securizare shared memory ---
grep -q "/run/shm" /etc/fstab || \
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab

# --- Restrictioneaza cron/at la root + useri permisi ---
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny 2>/dev/null || true

# --- Permisiuni fisiere sensibile ---
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/passwd
chmod 640 /etc/shadow 2>/dev/null || true
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

# --- Process accounting + AppArmor enforce ---
systemctl enable --now auditd 2>/dev/null || true
systemctl enable --now acct 2>/dev/null || systemctl enable --now psacct 2>/dev/null || true
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# --- Reguli auditd de baza ---
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
section "10/11 - Actualizari automate (cu reboot securitate)"
# ══════════════════════════════════════════════════════════════════════════════
dpkg-reconfigure -f noninteractive unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Autoremove "1";
EOF
# Reboot automat la 4 dimineata daca e necesar (kernel updates)
cat > /etc/apt/apt.conf.d/51unattended-reboot << 'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
info "Actualizari automate de securitate activate (+reboot la 04:00 daca e nevoie)."

# ══════════════════════════════════════════════════════════════════════════════
section "11/11 - Helper add-wp-site"
# ══════════════════════════════════════════════════════════════════════════════
cat > /usr/local/bin/add-wp-site << 'WPSCRIPT'
#!/bin/bash
# Utilizare: sudo add-wp-site domeniu.ro db_name db_user db_pass
set -euo pipefail
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

read -p "Username MySQL admin: " MYSQL_ADMIN_USER
read -s -p "Parola MySQL admin: " MYSQL_ADMIN_PASS; echo
mysql -u "$MYSQL_ADMIN_USER" --password="$MYSQL_ADMIN_PASS" << SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

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
# Forteaza accesul direct la filesystem (fara FTP) + dezactiveaza editorul de fisiere
if "FS_METHOD" not in c:
    c = c.replace("/* That's all, stop editing!", "define('FS_METHOD','direct');\ndefine('DISALLOW_FILE_EDIT',true);\ndefine('DISALLOW_FILE_MODS',false);\n\n/* That's all, stop editing!")
open(cfg,'w').write(c)
PY
chmod 640 "$WEB_ROOT/wp-config.php"
chown www-data:www-data "$WEB_ROOT/wp-config.php"

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
info "Helper 'add-wp-site' instalat."

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
                  INSTALARE FINALIZATA - BLINDAT
  ==================================================================
DONE
echo "  Server IP:    $SERVER_IP"
echo "  PHP:          $INSTALLED_PHP"
echo "  Apache+WAF:   http://${SERVER_IP}  (public)"
echo "  Webmin:       https://${SERVER_IP}:10000  (doar LAN: $LAN_SUBNET)"
echo "  MySQL admin:  ${MYSQL_ADMIN_USER}@localhost"
echo
echo "  === IMPORTANT - PASI URMATORI ==="
echo "  1. Configureaza cheia SSH, apoi dezactiveaza parola:"
echo "     ssh-copy-id user@${SERVER_IP}   (de pe masina ta)"
echo "     sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/99-hardening.conf"
echo "     sudo systemctl restart ssh"
echo
echo "  2. Adauga un site:    sudo add-wp-site domeniu.ro db db_user db_pass"
echo "  3. SSL:               sudo certbot --apache -d domeniu.ro"
echo "  4. Verificari:        sudo fail2ban-client status ; sudo ufw status verbose"
echo "  5. Scan rootkit:      sudo rkhunter --check"
echo
echo "  ATENTIE: ModSecurity ruleaza in mod BLOCARE. Daca un plugin"
echo "  WordPress da erori 403, treci temporar in DetectionOnly:"
echo "    sudo sed -i 's/SecRuleEngine On/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf"
echo "    sudo systemctl reload apache2"
echo
echo "  Log instalare: $LOG"
echo "  ==================================================================
"
echo "  RECOMANDARE: reporneste serverul acum (sudo reboot) pentru a aplica"
echo "  toate modulele kernel blacklisted si montarile fstab."
echo "  =================================================================="