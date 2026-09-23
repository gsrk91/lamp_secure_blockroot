#!/bin/bash
# ==============================================================================
#  Nginx Reverse Proxy Server - VARIANTA FINALA (consolidata)
#  "Final boss" pentru reverse proxy - pregatire completa Ubuntu Server clean install
# ------------------------------------------------------------------------------
#  STACK:
#    - Nginx (reverse proxy) hardened: TLS modern, rate-limiting, headers de
#      securitate implicite, restaurare IP real din spatele Cloudflare
#    - Webmin (.deb oficial) - administrare vizuala, acces DOAR din LAN
#    - Fail2Ban: sshd (port custom), nginx-http-auth, nginx-limit-req,
#      nginx-botsearch, jail-uri proprii (badbots, fisiere sensibile), webmin,
#      recidive
#    - UFW: deny in/out, web public (80/443), SSH+Webmin DOAR din LAN pe
#      porturi custom + protectie anti auto-lockout
#    - acme.sh + Cloudflare DNS-01: certificat Let's Encrypt DOAR pentru vhost-ul
#      de webmail al mail serverului (mail clientii au nevoie de cert public-trusted,
#      Origin Certificate NU e de incredere in afara Cloudflare)
#    - Helper 'add-reverse-proxy-site': genereaza vhost-uri noi dupa acelasi
#      tipar folosit deja (Origin Certificate Cloudflare, incarcat manual de tine
#      in /etc/nginx/ssl/, la fel ca site-urile existente - NU automatizat aici,
#      pentru ca asa ai cerut sa ramana fluxul pentru site-urile obisnuite)
#
#  SECURITATE (gandita ca un cybersecurity manager):
#    - SSH pe PORT CUSTOM, hardening complet (cripto moderna, root off, faillock)
#    - Hardening OS: auditd, AppArmor enforce, pwquality, sysctl kernel,
#      blacklist module, actualizari automate de securitate
#    - Secrete (Cloudflare API Token) introduse interactiv, NU hardcodate
#
#  Compatibil: Ubuntu Server 22.04 / 24.04 LTS
#  Rulare:     sudo bash nginx_proxy_final_boss.sh
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

LOG="/var/log/nginx_proxy_setup.log"
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
ADMIN_OS_USER="${SUDO_USER:-root}"

clear
cat << 'BANNER'
  ==============================================================
         Nginx Reverse Proxy - Setup automat (clean)
     Nginx . Webmin . Fail2Ban . UFW . SSH hardening . acme.sh
  ==============================================================
BANNER
info "Ubuntu $UBUNTU_VERSION | Utilizator admin OS: $ADMIN_OS_USER"

# ══════════════════════════════════════════════════════════════════════════════
section "0/12 - Date necesare (le introduci o singura data, acum)"
# ══════════════════════════════════════════════════════════════════════════════
echo "  ── Reteaua locala (LAN) pentru acces admin (SSH + Webmin) ─────────────"
LAN_IFACE=$(ip route | awk '/^default/ {print $5; exit}')
DETECTED_SUBNET=$(ip route | awk '/proto kernel scope link/ {print $1; exit}')
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "  Interfata: ${LAN_IFACE:-?}   IP server: ${SERVER_IP:-?}   Subretea detectata: ${DETECTED_SUBNET:-?}"
read -r -p "  -> Confirma subreteaua LAN pentru SSH+Webmin (Enter = ${DETECTED_SUBNET}): " LAN_SUBNET
LAN_SUBNET="${LAN_SUBNET:-$DETECTED_SUBNET}"
[[ -z "$LAN_SUBNET" ]] && error "Subretea LAN nedeterminata. Introdu manual (ex: 192.168.1.0/24)."
info "Admin restrictionat la: $LAN_SUBNET"

echo
echo "  Port custom SSH - elimina 99% din traficul de boti automate."
while true; do
    read -r -p "  -> Port custom SSH (1024-65535, Enter = 22 standard): " SSH_PORT
    SSH_PORT="${SSH_PORT:-22}"
    if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && { (( SSH_PORT >= 1024 && SSH_PORT <= 65535 )) || [[ "$SSH_PORT" == "22" ]]; }; then
        break
    fi
    warn "Port invalid. Introdu un numar intre 1024 si 65535 (sau Enter pentru 22)."
done
[[ "$SSH_PORT" == "22" ]] && warn "Ai ales portul standard 22. Recomandam un port custom."

echo
echo "  Webmin (panou de administrare vizual) va fi instalat automat, accesibil"
echo "  DOAR din subreteaua LAN de mai sus."
read -r -p "  -> Port Webmin (Enter = 10000 standard): " WEBMIN_PORT
WEBMIN_PORT="${WEBMIN_PORT:-10000}"
while ! [[ "$WEBMIN_PORT" =~ ^[0-9]+$ ]] || (( WEBMIN_PORT < 1 || WEBMIN_PORT > 65535 )); do
    warn "Port invalid."
    read -r -p "  -> Port Webmin (Enter = 10000 standard): " WEBMIN_PORT
    WEBMIN_PORT="${WEBMIN_PORT:-10000}"
done
info "Webmin va asculta pe portul ${WEBMIN_PORT}, doar din $LAN_SUBNET."

echo
echo "  ── Reverse proxy pentru webmail-ul mail serverului (optional) ─────────"
echo "  Site-urile tale obisnuite raman pe Origin Certificate Cloudflare (manual,"
echo "  ca pana acum). DAR clientii de mail (Outlook/Thunderbird/telefon) au nevoie"
echo "  de un certificat PUBLIC-TRUSTED (Let's Encrypt) pentru portul 993/465/587"
echo "  de pe mail server - Origin Certificate NU e de incredere in afara Cloudflare."
echo "  Acest script poate configura acum vhost-ul de webmail + certificatul, prin"
echo "  acme.sh + Cloudflare DNS-01 (nu are nevoie de portul 80 deschis catre nimeni)."
read -r -p "  -> Configuram acum reverse proxy + certificat pentru webmail? (da/nu): " SETUP_MAIL_PROXY
SETUP_MAIL_PROXY="${SETUP_MAIL_PROXY,,}"

if [[ "$SETUP_MAIL_PROXY" == "da" ]]; then
    read -r -p "  -> FQDN mail server (ex: mail.exemplu.ro): " MAIL_FQDN
    while [[ -z "${MAIL_FQDN:-}" ]] || [[ "$MAIL_FQDN" != *"."* ]]; do
        warn "Introdu un FQDN valid."
        read -r -p "  -> FQDN mail server: " MAIL_FQDN
    done
    read -r -p "  -> IP intern al mail serverului in LAN (ex: 192.168.1.50): " MAIL_BACKEND_IP
    while [[ -z "${MAIL_BACKEND_IP:-}" ]]; do
        warn "IP-ul nu poate fi gol."
        read -r -p "  -> IP intern al mail serverului: " MAIL_BACKEND_IP
    done
    read -r -p "  -> E-mail admin (pentru contul acme.sh, Enter = admin@${MAIL_FQDN#*.}): " ADMIN_EMAIL
    ADMIN_EMAIL="${ADMIN_EMAIL:-admin@${MAIL_FQDN#*.}}"

    echo
    echo "  Creeaza un API Token Cloudflare (NU Global API Key):"
    echo "    dash.cloudflare.com -> My Profile -> API Tokens -> Create Token"
    echo "    Permisiuni: Zone / DNS / Edit  +  Zone / Zone / Read"
    echo "    Resurse: doar zona domeniului tau de mail."
    echo
    echo "  Token-ul SE VEDE pe masura ce il tastezi (e lung, ca sa-l poti verifica)."
    echo "  Nu ajunge in ${LOG}: ecoul caracterelor tastate il face terminalul,"
    echo "  nu stdout-ul scriptului, deci 'tee' nu il captureaza."
    echo "  Ramane insa in scrollback-ul terminalului - da 'clear' dupa instalare"
    echo "  daca lucrezi pe un ecran la care au acces si altii."
    echo
    while true; do
        read -r -p "  -> Cloudflare API Token: " CF_TOKEN || true
        # Taie spatii/tab-uri/newline lipite la copy-paste
        CF_TOKEN="${CF_TOKEN//[[:space:]]/}"

        if [[ -z "${CF_TOKEN:-}" ]]; then
            warn "Token-ul nu poate fi gol."
            continue
        fi

        # Confirmarea mascata merge DOAR pe terminal, ca sa nu ajunga in log.
        if [[ -w /dev/tty ]]; then
            printf '     ai introdus %d caractere: %s...%s\n' \
                "${#CF_TOKEN}" "${CF_TOKEN:0:4}" "${CF_TOKEN: -4}" > /dev/tty 2>/dev/null || true
        fi

        # Validare la Cloudflare INAINTE de instalare. Fara asta, o greseala de
        # tastare se descopera abia la pasul 7/12, dupa ~10 minute de instalare,
        # iar acme.sh esueaza cu un mesaj greu de interpretat.
        # curl se instaleaza abia la 1/12; pe o imagine minimala poate lipsi aici.
        if ! command -v curl >/dev/null 2>&1; then
            warn "curl nu e instalat inca - sar peste verificarea token-ului."
            warn "Daca token-ul e gresit, vei vedea eroarea la pasul 7/12."
            break
        fi

        echo "     Verific token-ul la Cloudflare..."
        CF_CHECK="$(curl -fsS -m 20 \
            -H "Authorization: Bearer ${CF_TOKEN}" \
            -H "Content-Type: application/json" \
            "https://api.cloudflare.com/client/v4/user/tokens/verify" 2>/dev/null || true)"

        # Compactam raspunsul: API-ul poate returna '"success": true' cu spatiu.
        CF_CHECK_COMPACT="${CF_CHECK//[[:space:]]/}"
        if [[ "$CF_CHECK_COMPACT" == *'"success":true'* ]]; then
            info "Token valid si activ la Cloudflare."
            break
        fi

        warn "Cloudflare NU a acceptat token-ul (sau serverul nu are internet)."
        if [[ -n "$CF_CHECK" ]]; then
            echo "     Raspuns API: $CF_CHECK"
        else
            echo "     Niciun raspuns de la api.cloudflare.com."
        fi
        _cf_retry=""
        read -r -p "  Reintroduci token-ul? (da = reincerc / nu = continui oricum): " _cf_retry || true
        [[ "${_cf_retry,,}" == "da" ]] || { warn "Continui cu token-ul neverificat."; break; }
    done
else
    info "Sar peste configurarea webmail-ului acum. Poti rula sectiunea manual mai tarziu."
fi

echo
info "Toate datele au fost colectate. Incepe instalarea..."
sleep 2

# ══════════════════════════════════════════════════════════════════════════════
section "1/12 - Actualizare sistem + unelte de baza"
# ══════════════════════════════════════════════════════════════════════════════
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    software-properties-common apt-transport-https ca-certificates gnupg2 \
    curl wget unzip lsb-release net-tools htop vim git cron logrotate dialog \
    auditd audispd-plugins apparmor apparmor-utils libpam-pwquality \
    libpam-tmpdir acct unattended-upgrades apt-listchanges dnsutils openssl
info "Sistem actualizat + unelte de baza instalate."

# ══════════════════════════════════════════════════════════════════════════════
section "2/12 - Hardening SSH (facut ACUM, inainte de UFW)"
# ══════════════════════════════════════════════════════════════════════════════
echo "ACCES INTERZIS persoanelor neautorizate. Sesiunile sunt monitorizate." > /etc/issue.net

cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
Port ${SSH_PORT}
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
# Ubuntu 24.04: SSH foloseste socket activation (ssh.socket); dezactivam si
# fortam ssh.service clasic, altfel portul custom nu se aplica niciodata.
if systemctl list-unit-files | grep -q '^ssh.socket'; then
    systemctl disable --now ssh.socket 2>/dev/null || true
    rm -f /etc/systemd/system/ssh.socket.d/*.conf 2>/dev/null || true
fi
systemctl daemon-reload
systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

sleep 1
if ss -tlnp 2>/dev/null | grep -q ":${SSH_PORT} "; then
    info "SSH confirmat pe portul ${SSH_PORT}."
else
    warn "ATENTIE: nu am putut confirma ca SSH asculta pe ${SSH_PORT}. NU inchide sesiunea curenta!"
fi

# ══════════════════════════════════════════════════════════════════════════════
section "3/12 - Nginx (reverse proxy) + hardening global"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
systemctl enable --now nginx

mkdir -p /etc/nginx/ssl

# ── Evitarea erorii "directive is duplicate" ──────────────────────────────────
# Ubuntu livreaza /etc/nginx/nginx.conf cu o parte din aceste directive deja
# setate in blocul http{} (server_tokens, ssl_protocols,
# ssl_prefer_server_ciphers, keepalive_timeout). Linia
#     include /etc/nginx/conf.d/*.conf;
# se afla in ACELASI bloc http{}, deci redeclararea lor in 00-hardening.conf
# opreste nginx cu:
#     nginx: [emerg] "server_tokens" directive is duplicate in
#            /etc/nginx/conf.d/00-hardening.conf:1
#
# Solutia: comentam variantele din nginx.conf si lasam 00-hardening.conf singura
# sursa de adevar. NU invers - default-ul Ubuntu are 'ssl_protocols TLSv1
# TLSv1.1 TLSv1.2', adica exact protocoalele pe care vrem sa le eliminam.
# Operatia e idempotenta: la a doua rulare nu mai gaseste nimic necomentat.
NGINX_MAIN="/etc/nginx/nginx.conf"
NGINX_MANAGED=(
    server_tokens
    ssl_protocols
    ssl_prefer_server_ciphers
    ssl_ciphers
    ssl_session_cache
    ssl_session_timeout
    ssl_session_tickets
    keepalive_timeout
    client_max_body_size
    client_body_timeout
    client_header_timeout
    send_timeout
)

if [[ -f "$NGINX_MAIN" ]]; then
    [[ -f "${NGINX_MAIN}.orig-prehardening" ]] || \
        cp -a "$NGINX_MAIN" "${NGINX_MAIN}.orig-prehardening"

    for _d in "${NGINX_MANAGED[@]}"; do
        if grep -Eq "^[[:space:]]*${_d}[[:space:]]" "$NGINX_MAIN"; then
            sed -i -E "s|^([[:space:]]*)(${_d}[[:space:]].*)$|\1# \2   # mutat in conf.d/00-hardening.conf|" "$NGINX_MAIN"
            info "nginx.conf: comentat '${_d}' (gestionat acum in 00-hardening.conf)"
        fi
    done
    info "Backup nginx.conf original: ${NGINX_MAIN}.orig-prehardening"
fi

# Hardening global (TLS modern, rate-limiting, ascunde versiunea) - aplicat la
# nivel de http{}, site-urile individuale isi pot suprascrie propriile valori
# (ca in configul tau existent) fara conflict.
cat > /etc/nginx/conf.d/00-hardening.conf << 'EOF'
server_tokens off;

ssl_protocols       TLSv1.2 TLSv1.3;
ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_session_cache   shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

client_max_body_size 64m;
client_body_timeout  15s;
client_header_timeout 15s;
keepalive_timeout    30s;
send_timeout         15s;

# Rate limiting global - folosit optional in vhost-uri cu 'limit_req zone=general_limit ...'
limit_req_zone  $binary_remote_addr zone=general_limit:10m rate=15r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Blocheaza User-Agent-uri de scanere/exploatare cunoscute, la nivel global
map $http_user_agent $is_badbot {
    default 0;
    "~*(nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wfuzz|hydra|acunetix|nessus|openvas)" 1;
}
EOF

# Restaurare IP real pentru site-urile proxy-uite prin Cloudflare (orange cloud).
# Fara asta, $remote_addr in access.log/fail2ban arata IP-ul Cloudflare, nu
# vizitatorul real - fail2ban ar bana gresit (sau deloc).
info "Descarc listele de IP-uri Cloudflare pentru restaurarea IP-ului real..."
{
    echo "# Generat automat - IP-urile Cloudflare (pentru real_ip cand site-urile"
    echo "# sunt proxy-uite prin Cloudflare, nor portocaliu). Sigur de pastrat si"
    echo "# daca nu folosesti Cloudflare proxy pe toate site-urile."
    for ip in $(curl -fsSL https://www.cloudflare.com/ips-v4 2>/dev/null); do
        echo "set_real_ip_from ${ip};"
    done
    for ip in $(curl -fsSL https://www.cloudflare.com/ips-v6 2>/dev/null); do
        echo "set_real_ip_from ${ip};"
    done
    echo "real_ip_header CF-Connecting-IP;"
    echo "real_ip_recursive on;"
} > /etc/nginx/conf.d/01-cloudflare-realip.conf

if [[ ! -s /etc/nginx/conf.d/01-cloudflare-realip.conf ]] || ! grep -q set_real_ip_from /etc/nginx/conf.d/01-cloudflare-realip.conf; then
    warn "Nu am putut descarca listele Cloudflare (verifica internet). Sterg fisierul gol."
    rm -f /etc/nginx/conf.d/01-cloudflare-realip.conf
else
    info "Restaurare IP real Cloudflare configurata ($(grep -c set_real_ip_from /etc/nginx/conf.d/01-cloudflare-realip.conf) subretele)."
fi

# Snippet reutilizabil de blocare fisiere sensibile + badbots - il poti include
# in orice vhost nou cu 'include /etc/nginx/snippets/hardening-locations.conf;'
mkdir -p /etc/nginx/snippets
# ATENTIE: aceste blocuri NU au 'access_log off'. Intentionat.
# Daca stingi access log-ul pe exact caile pe care le blochezi (.env, .git,
# xmlrpc.php...), atunci jail-ul fail2ban 'nginx-sensitive-files' nu mai are ce
# citi si nu banneaza niciodata - blochezi cererea, dar atacatorul poate incerca
# la nesfarsit, gratis. Pastram 'log_not_found off' (aia doar taie zgomotul de
# 404 pentru fisiere inexistente), dar logam refuzurile.
cat > /etc/nginx/snippets/hardening-locations.conf << 'EOF'
if ($is_badbot) {
    return 403;
}
if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS)$) {
    return 405;
}
location ~ /\. {
    deny all;
    log_not_found off;
}
location ~* \.(bak|sql|tar|gz|zip|log|conf|ini|sh|py|rb|env)$ {
    deny all;
    log_not_found off;
}
location = /xmlrpc.php {
    deny all;
    log_not_found off;
}
location = /wp-config.php {
    deny all;
}
EOF

if nginx -t; then
    systemctl reload nginx
    info "Nginx instalat si hardened."
else
    nginx -t || true
    error "Configuratia nginx este invalida. Corecteaza inainte de a continua."
fi

# ══════════════════════════════════════════════════════════════════════════════
section "4/12 - Webmin (.deb oficial, acces LAN-only)"
# ══════════════════════════════════════════════════════════════════════════════
wget -q https://www.webmin.com/download/deb/webmin-current.deb -O /tmp/webmin.deb
DEBIAN_FRONTEND=noninteractive apt install -y /tmp/webmin.deb
rm -f /tmp/webmin.deb

if [[ -f /etc/webmin/miniserv.conf ]]; then
    sed -i '/^allow=/d' /etc/webmin/miniserv.conf
    echo "allow=${LAN_SUBNET} 127.0.0.1 localhost" >> /etc/webmin/miniserv.conf
    sed -i "s/^port=.*/port=${WEBMIN_PORT}/" /etc/webmin/miniserv.conf 2>/dev/null || \
        echo "port=${WEBMIN_PORT}" >> /etc/webmin/miniserv.conf
    sed -i 's/^ssl=.*/ssl=1/' /etc/webmin/miniserv.conf 2>/dev/null || echo "ssl=1" >> /etc/webmin/miniserv.conf
    grep -q "^ssl_cipher_list=" /etc/webmin/miniserv.conf || \
        echo "ssl_cipher_list=ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS" >> /etc/webmin/miniserv.conf
    # Esecurile de login trebuie sa ajunga in syslog (/var/log/auth.log) - acolo
    # citeste filtrul fail2ban 'webmin-auth'. miniserv.log NU contine aceste mesaje.
    sed -i '/^syslog=/d' /etc/webmin/miniserv.conf
    echo "syslog=1" >> /etc/webmin/miniserv.conf
    systemctl restart webmin
fi
systemctl enable --now webmin
info "Webmin instalat pe portul ${WEBMIN_PORT}, acces restrictionat la $LAN_SUBNET."

# ══════════════════════════════════════════════════════════════════════════════
section "5/12 - UFW Firewall (web public, admin LAN-only, anti auto-lockout)"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y ufw

ufw --force reset
ufw default deny incoming
ufw default deny outgoing

ufw allow out 53                comment 'DNS'
ufw allow out 80/tcp            comment 'HTTP out (update-uri, upstream backend)'
ufw allow out 443/tcp           comment 'HTTPS out (update-uri, API Cloudflare, backend)'
ufw allow out 123/udp           comment 'NTP'

ufw allow 80/tcp                comment 'HTTP public (redirect + ACME daca e nevoie)'
ufw allow 443/tcp               comment 'HTTPS public'

ufw limit from "$LAN_SUBNET" to any port "$SSH_PORT" proto tcp comment "SSH LAN port ${SSH_PORT} - rate limited"
ufw allow from "$LAN_SUBNET" to any port "$WEBMIN_PORT" proto tcp comment "Webmin LAN port ${WEBMIN_PORT}"

if [[ -n "${SSH_CLIENT:-}" ]] || [[ -n "${SSH_TTY:-}" ]]; then
    echo
    warn "Scriptul ruleaza printr-o sesiune SSH activa."
    warn "UFW va fi activat cu regula SSH pe portul ${SSH_PORT} din ${LAN_SUBNET}."
    read -r -p "  Continua cu activarea UFW? (da/nu): " UFW_CONFIRM
    [[ "${UFW_CONFIRM,,}" != "da" ]] && error "UFW anulat de utilizator. Ruleaza manual dupa verificare."
fi

ufw --force enable
info "UFW activat: web public (80/443), SSH+Webmin doar din $LAN_SUBNET."

# ══════════════════════════════════════════════════════════════════════════════
section "6/12 - Fail2Ban (sshd, nginx, webmin, recidive)"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
systemctl enable --now fail2ban

# ATENTIE (capcana clasica): NU pune 'backend = systemd' in [DEFAULT].
# fail2ban ignora COMPLET 'logpath' cand backend-ul e systemd - in jailreader.py:
#     if opt == "logpath":
#         if backend.startswith("systemd"): continue
# Adica toate jail-urile pe fisier (nginx, webmin, recidive) ar porni "verzi" in
# 'fail2ban-client status', dar ar asculta pe journald, unde logurile nginx NU
# ajung niciodata => zero banari, fals sentiment de siguranta.
# Solutia: backend implicit 'auto' (inotify pe fisiere), systemd DOAR pe sshd.
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime         = 86400
findtime        = 600
maxretry        = 3
ignoreip        = 127.0.0.1/8 ::1
banaction       = ufw
banaction_allports = ufw

[sshd]
enabled   = true
port      = ${SSH_PORT}
backend   = systemd
maxretry  = 3
bantime   = 86400

[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
backend  = auto
logpath  = /var/log/nginx/*error.log
maxretry = 3

[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
backend  = auto
logpath  = /var/log/nginx/*error.log
maxretry = 10
findtime = 120
bantime  = 604800

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
backend  = auto
logpath  = /var/log/nginx/*error.log
maxretry = 5
bantime  = 604800

[nginx-badbots]
enabled  = true
port     = http,https
filter   = nginx-badbots
backend  = auto
logpath  = /var/log/nginx/*access.log
maxretry = 1
bantime  = 604800

[nginx-sensitive-files]
enabled  = true
port     = http,https
filter   = nginx-sensitive-files
backend  = auto
logpath  = /var/log/nginx/*access.log
maxretry = 2
bantime  = 604800

# Webmin scrie esecurile de login in SYSLOG, NU in /var/webmin/miniserv.log
# (acela e access log in format Apache). Filtrul oficial 'webmin-auth' asteapta
# exact formatul syslog:
#   Dec 13 08:15:18 host webmin[25875]: Invalid login as root from 1.2.3.4
# Folosim backend systemd (fara logpath) pentru ca e singura varianta care merge
# si pe Ubuntu fara rsyslog instalat (24.04 nu-l mai are garantat) - journald
# capteaza oricum orice mesaj syslog.
[webmin-auth]
enabled  = true
port     = ${WEBMIN_PORT}
filter   = webmin-auth
backend  = systemd
maxretry = 3
findtime = 600
bantime  = 86400

[recidive]
enabled   = true
backend   = auto
logpath   = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime   = 1209600
findtime  = 86400
maxretry  = 3
EOF

# Filtre proprii - user-agent-uri de scanere si cereri catre fisiere sensibile,
# pe langa filtrul deja aplicat direct in nginx (map $is_badbot).
# NOTA regex: scanerele se prezinta ca "Mozilla/5.00 (Nikto/2.1.5)" - cu N mare.
# fail2ban compileaza regex-urile CASE-SENSITIVE, deci un '(nikto|...)' simplu ar
# rata exact traficul pe care vrea sa-l prinda. Folosim grup cu flag local
# '(?i:...)' (valid oriunde in regex-ul Python, spre deosebire de '(?i)' global,
# care in Python 3.11+ e acceptat doar la inceputul expresiei compilate).
# Campurile sunt delimitate strict cu [^"]* ca sa nu depindem de backtracking.
cat > /etc/fail2ban/filter.d/nginx-badbots.conf << 'EOF'
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "[A-Z]+[^"]*" \d+ \S+ "[^"]*" "[^"]*\b(?i:nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wfuzz|hydra|acunetix|nessus|openvas)\b[^"]*"
ignoreregex =
EOF

# '/backup' generic a fost scos intentionat: ar fi banat si un /backups/ legitim
# al unui site din spate, iar cu maxretry=2 si ban de 7 zile un fals pozitiv e scump.
cat > /etc/fail2ban/filter.d/nginx-sensitive-files.conf << 'EOF'
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*(?i:/\.env|/\.git|/\.svn|/\.htaccess|/wp-config\.php|/xmlrpc\.php|/etc/passwd|/etc/shadow|/dump\.sql|/backup\.(?:sql|zip|tar|gz)|/config\.php\.bak)[^"]*"
ignoreregex =
EOF

touch /var/log/nginx/access.log /var/log/nginx/error.log 2>/dev/null || true

if systemctl restart fail2ban; then
    sleep 1
    info "Fail2Ban activ. Jail-uri incarcate:"
    fail2ban-client status 2>/dev/null | grep "Jail list" || true
else
    warn "Fail2Ban a intampinat o problema la pornire. Verifica: sudo fail2ban-client status"
fi

# ══════════════════════════════════════════════════════════════════════════════
section "7/12 - Certificat webmail (acme.sh + Cloudflare DNS-01)"
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SETUP_MAIL_PROXY" == "da" ]]; then
    ACME_HOME="/root/.acme.sh"
    ACME_BIN="${ACME_HOME}/acme.sh"

    if [[ ! -x "$ACME_BIN" ]]; then
        info "Instalez acme.sh..."
        git clone --depth 1 https://github.com/acmesh-official/acme.sh.git /usr/local/src/acme.sh
        (cd /usr/local/src/acme.sh && ./acme.sh --install --home "$ACME_HOME" \
            --accountemail "$ADMIN_EMAIL" > /dev/null)
    fi

    if [[ -x "$ACME_BIN" ]]; then
        "$ACME_BIN" --set-default-ca --server letsencrypt --home "$ACME_HOME" > /dev/null 2>&1 || true
        export CF_Token="$CF_TOKEN"
        mkdir -p /etc/nginx/ssl

        info "Cer certificatul Let's Encrypt pentru ${MAIL_FQDN} (validare DNS-01 prin Cloudflare)..."
        if "$ACME_BIN" --home "$ACME_HOME" --issue --dns dns_cf -d "$MAIL_FQDN" --keylength 2048; then
            "$ACME_BIN" --home "$ACME_HOME" --install-cert -d "$MAIL_FQDN" \
                --key-file       "/etc/nginx/ssl/${MAIL_FQDN}.key" \
                --fullchain-file "/etc/nginx/ssl/${MAIL_FQDN}.pem" \
                --reloadcmd      "systemctl reload nginx"
            chmod 640 "/etc/nginx/ssl/${MAIL_FQDN}.key"
            MAIL_CERT_OK=1
            info "Certificat Let's Encrypt instalat pentru vhost-ul de webmail."
            info "Reinnoire automata: acme.sh (cron/systemd-timer, verificare 2x/zi)."
        else
            warn "Emiterea certificatului a esuat. Verifica token-ul Cloudflare si zona."
            warn "Reincearca manual: export CF_Token='...'; ${ACME_BIN} --issue --dns dns_cf -d ${MAIL_FQDN}"
            MAIL_CERT_OK=0
        fi
        unset CF_TOKEN CF_Token
    else
        warn "Instalarea acme.sh a esuat."
        MAIL_CERT_OK=0
    fi
else
    info "Sarit (nu ai cerut configurarea webmail-ului la pasul 0)."
    MAIL_CERT_OK=0
fi

# ══════════════════════════════════════════════════════════════════════════════
section "8/12 - Vhost reverse proxy pentru webmail"
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$SETUP_MAIL_PROXY" == "da" ]] && [[ "$MAIL_CERT_OK" == "1" ]]; then
    cat > "/etc/nginx/sites-available/${MAIL_FQDN}.conf" << EOF
server {
    listen 80;
    server_name ${MAIL_FQDN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${MAIL_FQDN};

    ssl_certificate     /etc/nginx/ssl/${MAIL_FQDN}.pem;
    ssl_certificate_key /etc/nginx/ssl/${MAIL_FQDN}.key;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    access_log /var/log/nginx/${MAIL_FQDN}.access.log combined;
    error_log  /var/log/nginx/${MAIL_FQDN}.error.log warn;

    include /etc/nginx/snippets/hardening-locations.conf;

    location / {
        limit_req zone=general_limit burst=40 nodelay;

        proxy_pass https://${MAIL_BACKEND_IP};
        # proxy_ssl_verify are nevoie OBLIGATORIU de un CA bundle explicit - nginx
        # NU cade automat pe magazia de certificate a sistemului. Fara linia
        # 'proxy_ssl_trusted_certificate' rezultatul ar fi 502 Bad Gateway cu
        # "upstream SSL certificate verify error". Iar SNI nu se trimite implicit
        # (proxy_ssl_server_name e 'off' din fabrica), deci backend-ul nu ar sti
        # ce certificat sa serveasca.
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 2;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_ssl_server_name on;
        proxy_ssl_name ${MAIL_FQDN};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout    120s;
        proxy_read_timeout    120s;
        client_max_body_size  100m;
    }
}
EOF
    ln -sf "/etc/nginx/sites-available/${MAIL_FQDN}.conf" "/etc/nginx/sites-enabled/${MAIL_FQDN}.conf"
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        info "Vhost webmail creat si activ: https://${MAIL_FQDN} -> ${MAIL_BACKEND_IP}"
    else
        warn "Configtest nginx a esuat pentru vhost-ul webmail. Verifica manual: nginx -t"
    fi
    warn "IMPORTANT - pe MAIL SERVER trebuie configurat 'trusted_proxies' / real IP pentru"
    warn "nginx-ul LOCAL de acolo (cel al iRedMail), altfel fail2ban-ul de pe mail server"
    warn "vede IP-ul ACESTUI reverse-proxy in loc de IP-ul real al atacatorilor."
else
    info "Vhost webmail nu a fost creat (certificat lipsa sau pas sarit la 0/12)."
fi

# ══════════════════════════════════════════════════════════════════════════════
section "9/12 - Helper add-reverse-proxy-site (Origin Certificate Cloudflare, manual)"
# ══════════════════════════════════════════════════════════════════════════════
cat > /usr/local/bin/add-reverse-proxy-site << 'RPSCRIPT'
#!/bin/bash
# Creeaza un vhost reverse-proxy nou, dupa tiparul deja folosit (Origin
# Certificate Cloudflare incarcat manual de tine in /etc/nginx/ssl/).
# Utilizare: sudo add-reverse-proxy-site domeniu.ro backend_ip [backend_port]
set -euo pipefail
[[ "$EUID" -ne 0 ]] && { echo "Ruleaza cu sudo."; exit 1; }

DOMAIN="${1:?Lipseste domeniu. Ex: add-reverse-proxy-site domeniu.ro 192.168.1.101}"
BACKEND_IP="${2:?Lipseste IP-ul backend-ului. Ex: add-reverse-proxy-site domeniu.ro 192.168.1.101 443}"
BACKEND_PORT="${3:-443}"
CERT="/etc/nginx/ssl/${DOMAIN}.pem"
KEY="/etc/nginx/ssl/${DOMAIN}.key"

if [[ ! -f "$CERT" ]] || [[ ! -f "$KEY" ]]; then
    echo "[!] Lipseste certificatul Origin Cloudflare pentru ${DOMAIN}."
    echo "    Genereaza-l in Cloudflare (SSL/TLS -> Origin Server -> Create Certificate)"
    echo "    si salveaza-l manual la:"
    echo "      ${CERT}"
    echo "      ${KEY}"
    exit 1
fi

BACKEND_SCHEME="https"
[[ "$BACKEND_PORT" == "80" ]] && BACKEND_SCHEME="http"

cat > "/etc/nginx/sites-available/${DOMAIN}.conf" << VHEOF
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    return 301 https://${DOMAIN}\$request_uri;
}

server {
    listen 443 ssl;
    server_name www.${DOMAIN};

    ssl_certificate     ${CERT};
    ssl_certificate_key ${KEY};

    return 301 https://${DOMAIN}\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     ${CERT};
    ssl_certificate_key ${KEY};

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()" always;

    access_log /var/log/nginx/${DOMAIN}.access.log combined;
    error_log  /var/log/nginx/${DOMAIN}.error.log warn;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_types text/plain text/css application/javascript application/json image/svg+xml font/ttf font/otf application/font-woff2;

    include /etc/nginx/snippets/hardening-locations.conf;

    location ~* \.(jpg|jpeg|png|gif|ico|svg|webp|avif|woff|woff2|ttf|otf|eot|css|js|mp4|mp3|ogg|pdf)\$ {
        proxy_pass ${BACKEND_SCHEME}://${BACKEND_IP}:${BACKEND_PORT};
        include proxy_params;
        proxy_ssl_verify off;
        expires 30d;
        add_header Cache-Control "public, immutable";
        add_header Vary "Accept-Encoding";
        access_log off;
    }

    location / {
        limit_req zone=general_limit burst=40 nodelay;

        proxy_pass ${BACKEND_SCHEME}://${BACKEND_IP}:${BACKEND_PORT}/;
        include proxy_params;
        proxy_ssl_verify off;
        proxy_connect_timeout  10s;
        proxy_send_timeout     60s;
        proxy_read_timeout     60s;
        proxy_buffering          on;
        proxy_buffer_size        8k;
        proxy_buffers            8 16k;
        proxy_busy_buffers_size  32k;
        proxy_hide_header X-Powered-By;
        proxy_hide_header X-Generator;
        proxy_intercept_errors on;
        error_page 502 503 504 /50x.html;
    }

    location = /50x.html {
        root /var/www/html;
        internal;
    }
}
VHEOF

ln -sf "/etc/nginx/sites-available/${DOMAIN}.conf" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
nginx -t
systemctl reload nginx

echo ""
echo "=================================================="
echo "  Vhost adaugat: https://${DOMAIN}"
echo "  Backend:       ${BACKEND_SCHEME}://${BACKEND_IP}:${BACKEND_PORT}"
echo "  Certificat:    ${CERT} (Origin Certificate Cloudflare)"
echo "=================================================="
RPSCRIPT
chmod +x /usr/local/bin/add-reverse-proxy-site
info "Helper 'add-reverse-proxy-site' instalat in /usr/local/bin/."

# ══════════════════════════════════════════════════════════════════════════════
section "10/12 - Hardening kernel, login, fisiere"
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

grep -q '^\* hard core 0' /etc/security/limits.conf || echo '* hard core 0' >> /etc/security/limits.conf

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

if [[ -f /etc/security/faillock.conf ]]; then
    sed -i \
        -e 's/^# *deny =.*/deny = 5/' \
        -e 's/^# *unlock_time =.*/unlock_time = 900/' \
        -e 's/^# *fail_interval =.*/fail_interval = 900/' \
        /etc/security/faillock.conf
fi

sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs 2>/dev/null || true
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs 2>/dev/null || true

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
EOF

# Memoria partajata: pe Ubuntu modern mountpoint-ul real e /dev/shm (/run/shm a
# disparut prin 14.04). Montarea lui /run/shm nu ar hardeni nimic si ar lasa in
# urma o unitate systemd esuata la boot.
grep -q "[[:space:]]/dev/shm[[:space:]]" /etc/fstab || \
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab

echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny 2>/dev/null || true

chmod 600 /etc/ssh/sshd_config
chmod 640 /etc/shadow 2>/dev/null || true

systemctl enable --now auditd 2>/dev/null || true
systemctl enable --now acct 2>/dev/null || systemctl enable --now psacct 2>/dev/null || true
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/nginx -p wa -k nginx_config
EOF
augenrules --load 2>/dev/null || true
info "Hardening kernel/login/fisiere aplicat."

# ══════════════════════════════════════════════════════════════════════════════
section "11/12 - Actualizari automate de securitate"
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
section "12/12 - Sumar final"
# ══════════════════════════════════════════════════════════════════════════════
apt-get autoremove -y -qq
apt-get autoclean -qq
echo "<html><body><h1>Reverse proxy activ</h1></body></html>" > /var/www/html/index.nginx-debian.html 2>/dev/null || true

echo
cat << 'DONE'
  ==================================================================
                    INSTALARE FINALIZATA
  ==================================================================
DONE
echo "  Server IP:      $SERVER_IP"
echo "  Nginx:          activ, hardened, real-IP Cloudflare configurat"
echo "  Webmin:         https://${SERVER_IP}:${WEBMIN_PORT}   (doar LAN: $LAN_SUBNET)"
if [[ "$SETUP_MAIL_PROXY" == "da" ]] && [[ "$MAIL_CERT_OK" == "1" ]]; then
    echo "  Webmail proxy:  https://${MAIL_FQDN} -> ${MAIL_BACKEND_IP} (cert Let's Encrypt)"
fi
echo
echo "  === CONECTARE SSH DE ACUM INAINTE ==="
echo "    ssh -p ${SSH_PORT} ${ADMIN_OS_USER}@${SERVER_IP}"
echo "    (recomandat) pune chei SSH, apoi dezactiveaza parola:"
echo "      ssh-copy-id -p ${SSH_PORT} ${ADMIN_OS_USER}@${SERVER_IP}"
echo "      sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/99-hardening.conf"
echo "      sudo systemctl restart ssh"
echo
echo "  === SITE-URI NOI (Origin Certificate Cloudflare, ca pana acum) ==="
echo "    1. genereaza certificatul Origin in Cloudflare -> SSL/TLS -> Origin Server"
echo "    2. salveaza-l la /etc/nginx/ssl/domeniu.ro.pem si /etc/nginx/ssl/domeniu.ro.key"
echo "    3. sudo add-reverse-proxy-site domeniu.ro 192.168.1.XXX [port]"
echo
if [[ "$SETUP_MAIL_PROXY" == "da" ]]; then
    echo "  === URMATORUL PAS - PE MAIL SERVER ==="
    echo "  Configureaza 'real IP' pe nginx-ul LOCAL al iRedMail de pe mail server,"
    echo "  ca sa vada IP-ul real al vizitatorilor webmail (nu IP-ul acestui proxy):"
    echo "    echo 'set_real_ip_from ${SERVER_IP};'      >> /etc/nginx/conf.d/proxy-realip.conf"
    echo "    echo 'real_ip_header X-Forwarded-For;'      >> /etc/nginx/conf.d/proxy-realip.conf"
    echo "    echo 'real_ip_recursive on;'                >> /etc/nginx/conf.d/proxy-realip.conf"
    echo "    systemctl reload nginx   (pe mail server)"
    echo
fi
echo "  === VERIFICARI ==="
echo "    sudo fail2ban-client status"
echo "    sudo ufw status verbose"
echo "    sudo nginx -t"
echo
echo "  Log instalare:   $LOG"
echo "  =================================================================="
