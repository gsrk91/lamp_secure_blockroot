#!/bin/bash
# ==============================================================================
# LAMP Stack Setup — Ubuntu/Debian
# Componente: Apache2, MariaDB, PHP, Fail2Ban, Webmin, Hardening
# Versiune: 3.0 — fără phpMyAdmin
# Rulare: sudo bash lamp_secure_v3.sh
# ==============================================================================

set -euo pipefail

LOG_FILE="/var/log/lamp_setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# ── Culori pentru output ───────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo "=================================================================="
echo "   Instalare LAMP + Fail2Ban + Webmin + Hardening Securitate"
echo "=================================================================="

# ── Verificare root ────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && error "Rulează scriptul ca root sau cu sudo."

# ── Funcție citire parolă cu confirmare ───────────────────────────────────────
read_password() {
    local prompt="$1"
    local var_name="$2"
    local pass1 pass2
    while true; do
        read -s -p "$prompt: " pass1; echo
        read -s -p "Confirmă parola: " pass2; echo
        if [[ "$pass1" == "$pass2" ]]; then
            # Export dinamic în variabila cerută
            printf -v "$var_name" '%s' "$pass1"
            break
        else
            warn "Parolele nu coincid. Încearcă din nou."
        fi
    done
}

# ── Colectare date utilizator ──────────────────────────────────────────────────
echo
info "=== Configurare credențiale ==="

read -p "Nume utilizator MySQL admin (va înlocui root): " MYSQL_ADMIN_USER
[[ -z "$MYSQL_ADMIN_USER" ]] && error "Numele utilizatorului nu poate fi gol."

read_password "Parolă pentru utilizatorul MySQL '$MYSQL_ADMIN_USER'" MYSQL_ADMIN_PASS
read_password "Parolă pentru MariaDB root (internă, de backup)" MYSQL_ROOT_PASS

echo
info "Toate datele au fost colectate. Se începe instalarea..."
echo

# ── Update sistem ──────────────────────────────────────────────────────────────
info "Actualizare pachete sistem..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq

# ── Instalare pachete ──────────────────────────────────────────────────────────
info "Instalare Apache2, MariaDB, PHP și utilitare..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2 \
    mariadb-server \
    php \
    libapache2-mod-php \
    php-mysql \
    php-cli \
    php-curl \
    php-xml \
    php-mbstring \
    php-opcache \
    php-zip \
    php-gd \
    unzip \
    curl \
    wget \
    gnupg2 \
    apache2-utils \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    ufw

# ── Activare servicii ──────────────────────────────────────────────────────────
info "Activare servicii..."
systemctl enable --now apache2 mariadb fail2ban

# ── Hardening MariaDB ──────────────────────────────────────────────────────────
info "Configurare și securizare MariaDB..."

# Setare parolă root mai întâi, separat
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';" 2>/dev/null || \
mysql -u root --password="${MYSQL_ROOT_PASS}" -e "SELECT 1;" > /dev/null 2>&1 || \
warn "Root MariaDB deja are parolă configurată sau altă metodă de autentificare."

# Curățare și creare user admin — într-o singură sesiune autentificată
mysql -u root --password="${MYSQL_ROOT_PASS}" <<MYSQL_SCRIPT
-- Curățare utilizatori anonimi și baze de test
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Restricționare root doar la localhost (fără a-l șterge)
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Creare utilizator admin dedicat
CREATE USER IF NOT EXISTS '${MYSQL_ADMIN_USER}'@'localhost' IDENTIFIED BY '${MYSQL_ADMIN_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_ADMIN_USER}'@'localhost' WITH GRANT OPTION;

FLUSH PRIVILEGES;
MYSQL_SCRIPT

info "MariaDB configurat. User admin: ${MYSQL_ADMIN_USER}@localhost"

# ── Configurare PHP ────────────────────────────────────────────────────────────
info "Hardening configurație PHP..."

PHP_INI=$(php --ini | grep "Loaded Configuration" | awk '{print $NF}')

if [[ -f "$PHP_INI" ]]; then
    # Backup
    cp "$PHP_INI" "${PHP_INI}.bak"

    sed -i \
        -e 's/^expose_php.*/expose_php = Off/' \
        -e 's/^display_errors.*/display_errors = Off/' \
        -e 's/^log_errors.*/log_errors = On/' \
        -e 's/^upload_max_filesize.*/upload_max_filesize = 32M/' \
        -e 's/^post_max_size.*/post_max_size = 32M/' \
        -e 's/^max_execution_time.*/max_execution_time = 60/' \
        -e 's/^memory_limit.*/memory_limit = 256M/' \
        "$PHP_INI"

    info "PHP.ini hardened: $PHP_INI"
else
    warn "Nu s-a găsit php.ini. Hardening PHP sărit."
fi

# ── Activare module Apache ─────────────────────────────────────────────────────
info "Activare module Apache..."
a2enmod rewrite headers ssl

# ── Security headers Apache ────────────────────────────────────────────────────
info "Configurare security headers Apache..."
cat > /etc/apache2/conf-available/security-hardening.conf <<'EOL'
# Ascunde versiunea Apache
ServerSignature Off
ServerTokens Prod

# Security Headers
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# HSTS — activează doar dacă ai SSL configurat
# Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Dezactivare metode HTTP periculoase
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
EOL

a2enconf security-hardening

# ── Permisiuni web root ────────────────────────────────────────────────────────
info "Setare permisiuni /var/www/html..."
chown -R www-data:www-data /var/www/html
find /var/www/html -type d -exec chmod 755 {} \;
find /var/www/html -type f -exec chmod 644 {} \;

# Creare pagină index curată (înlocuiește default Apache)
cat > /var/www/html/index.html <<'EOL'
<!DOCTYPE html>
<html lang="ro">
<head><meta charset="UTF-8"><title>Server activ</title></head>
<body><h1>Server LAMP funcțional</h1></body>
</html>
EOL

systemctl restart apache2
info "Apache2 repornit cu succes."

# ── Fail2Ban ───────────────────────────────────────────────────────────────────
info "Configurare Fail2Ban..."
cat > /etc/fail2ban/jail.local <<'EOL'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3

[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log

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
maxretry = 2

[apache-noscript]
enabled  = true
port     = http,https
filter   = apache-noscript
logpath  = /var/log/apache2/error.log
EOL

systemctl restart fail2ban
info "Fail2Ban configurat și repornit."

# ── Actualizări automate ───────────────────────────────────────────────────────
info "Activare actualizări automate de securitate..."
dpkg-reconfigure -f noninteractive unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOL'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Autoremove "1";
EOL

# ── Instalare Webmin ───────────────────────────────────────────────────────────
info "Instalare Webmin..."

# Adăugare repo oficial Webmin cu verificare GPG
curl -fsSL https://download.webmin.com/jcameron-key.asc | \
    gpg --dearmor -o /usr/share/keyrings/webmin-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/webmin-keyring.gpg] https://download.webmin.com/download/repository sarge contrib" \
    > /etc/apt/sources.list.d/webmin.list

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y webmin

info "Webmin instalat."

# ── Firewall UFW ───────────────────────────────────────────────────────────────
info "Configurare firewall UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 'Apache Full'
ufw allow 10000/tcp comment 'Webmin'
ufw --force enable

info "Firewall UFW activat."

# ── Cleanup ────────────────────────────────────────────────────────────────────
info "Curățare pachete neutilizate..."
apt-get autoremove -y -qq
apt-get autoclean -qq

# ── Sumar final ────────────────────────────────────────────────────────────────
SERVER_IP=$(hostname -I | awk '{print $1}')

echo
echo "=================================================================="
echo -e "${GREEN}   ✅ Instalare finalizată cu succes!${NC}"
echo "=================================================================="
echo
echo "  🌐 Apache:    http://${SERVER_IP}"
echo "  🔒 Webmin:    https://${SERVER_IP}:10000"
echo "  🗄️  MySQL:     User '${MYSQL_ADMIN_USER}' (LOCAL only)"
echo
echo "  📋 Log complet: ${LOG_FILE}"
echo
echo "  ⚠️  IMPORTANT:"
echo "     - Activează HSTS în security-hardening.conf după ce configurezi SSL"
echo "     - Configurează SSL cu: certbot --apache (instalează certbot separat)"
echo "     - Verifică Fail2Ban: fail2ban-client status"
echo "     - Verifică UFW: ufw status verbose"
echo "=================================================================="