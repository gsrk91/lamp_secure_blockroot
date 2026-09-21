#!/bin/bash
# ==============================================================================
#  Mail Server (iRedMail + Mailjet relay) - VARIANTA FINALA (consolidata)
#  "Final boss" pentru e-mail - pregatire completa pe Ubuntu Server clean install
# ------------------------------------------------------------------------------
#  STACK:
#    - iRedMail (Postfix + Dovecot + MariaDB + Roundcube/SOGo + Amavis +
#      SpamAssassin + ClamAV + OpenDKIM) - instalatorul oficial, rulat controlat
#    - Postfix configurat ca RELAY CLIENT prin Mailjet (in-v3.mailjet.com:587,
#      auth SASL cu API Key + Secret Key introduse la rulare)
#    - Webmin (.deb oficial, instalat automat) - administrare vizuala a
#      serverului, acces restrictionat DOAR din LAN, pe HTTPS
#    - Fail2Ban: jail-urile oficiale iRedMail (postfix, dovecot, postfix-pregreet,
#      roundcube/sogo) + jail-uri proprii (sshd port custom, webmin, recidive)
#    - UFW: deny in/out, mail public (25/587/465/993), web public (80/443),
#      SSH + Webmin DOAR din LAN pe porturi custom + protectie anti auto-lockout
#
#  SECURITATE (gandita ca un cybersecurity manager):
#    - SSH pe PORT CUSTOM, hardening complet (cripto moderna, root off, faillock)
#    - Hardening OS: auditd, AppArmor enforce, pwquality, sysctl kernel,
#      blacklist module, actualizari automate de securitate
#    - Secrete (Mailjet API/Secret Key) introduse interactiv, NU hardcodate,
#      salvate doar in sasl_passwd cu permisiuni 600
#
#  IMPORTANT - SINGURA PARTE INTERACTIVA A SCRIPTULUI:
#    Instalatorul oficial iRedMail.sh foloseste ecrane whiptail/dialog (domeniu,
#    parola admin, backend DB, componente). NU exista o metoda sigura si stabila
#    (independenta de versiune) de a completa automat acele ecrane fara riscul
#    de a genera o instalare corupta - de aceea acest script te ghideaza exact
#    ce sa raspunzi, apoi preia controlul inapoi pentru tot restul (Mailjet,
#    firewall, fail2ban, hardening).
#
#  Compatibil: Ubuntu Server 22.04 / 24.04 LTS, minim 2 vCPU / 4GB RAM / 20GB disk
#  Rulare:     sudo bash mail_server_final_boss.sh
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

LOG="/var/log/mail_server_setup.log"
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

RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if (( RAM_MB < 3500 )); then
    warn "RAM detectata: ${RAM_MB}MB. iRedMail (ClamAV+SpamAssassin+Amavis) recomanda minim 4GB."
    read -r -p "  -> Continui oricum? (da/nu): " RAM_CONFIRM
    [[ "${RAM_CONFIRM,,}" != "da" ]] && error "Instalare anulata. Mareste RAM-ul si reia."
fi

clear
cat << 'BANNER'
  ==============================================================
       Mail Server - iRedMail + Mailjet relay - Setup automat
   Postfix+Dovecot . Webmin . Fail2Ban . UFW . SSH hardening . TLS
  ==============================================================
BANNER
info "Ubuntu $UBUNTU_VERSION | RAM ${RAM_MB}MB | Utilizator admin OS: $ADMIN_OS_USER"

# ══════════════════════════════════════════════════════════════════════════════
section "0/11 - Date necesare (le introduci o singura data, acum)"
# ══════════════════════════════════════════════════════════════════════════════
echo "  Ai nevoie, inainte sa incepi:"
echo "   - un domeniu propriu cu acces la zona DNS (MX/SPF/DKIM/DMARC)"
echo "   - un subdomeniu dedicat serverului de mail (ex: mail.domeniul-tau.ro)"
echo "   - un cont Mailjet cu API Key + Secret Key (mailjet.com -> Account -> SMTP and SEND API Settings)"
echo

read -r -p "  -> Hostname FQDN al serverului (ex: mail.exemplu.ro): " MAIL_FQDN
while [[ -z "${MAIL_FQDN:-}" ]] || [[ "$MAIL_FQDN" != *"."* ]]; do
    warn "Introdu un FQDN valid (trebuie sa contina cel putin un punct), ex: mail.exemplu.ro"
    read -r -p "  -> Hostname FQDN al serverului: " MAIL_FQDN
done

DEFAULT_DOMAIN="${MAIL_FQDN#*.}"
read -r -p "  -> Domeniul principal de mail (Enter = ${DEFAULT_DOMAIN}): " PRIMARY_DOMAIN
PRIMARY_DOMAIN="${PRIMARY_DOMAIN:-$DEFAULT_DOMAIN}"
[[ -z "$PRIMARY_DOMAIN" ]] && error "Domeniu principal nedeterminat."
info "Domeniu: $PRIMARY_DOMAIN | Hostname server: $MAIL_FQDN"

read -r -p "  -> E-mail admin (postmaster / notificari certbot, Enter = postmaster@${PRIMARY_DOMAIN}): " ADMIN_EMAIL
ADMIN_EMAIL="${ADMIN_EMAIL:-postmaster@${PRIMARY_DOMAIN}}"

echo
echo "  ── Reteaua locala (LAN) pentru acces admin (SSH) ──────────────────────"
LAN_IFACE=$(ip route | awk '/^default/ {print $5; exit}')
DETECTED_SUBNET=$(ip route | awk '/proto kernel scope link/ {print $1; exit}')
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "  Interfata: ${LAN_IFACE:-?}   IP server: ${SERVER_IP:-?}   Subretea detectata: ${DETECTED_SUBNET:-?}"
read -r -p "  -> Confirma subreteaua LAN pentru SSH (Enter = ${DETECTED_SUBNET}, sau 0.0.0.0/0 daca administrezi de oriunde): " LAN_SUBNET
LAN_SUBNET="${LAN_SUBNET:-$DETECTED_SUBNET}"
[[ -z "$LAN_SUBNET" ]] && error "Subretea LAN nedeterminata. Introdu manual (ex: 192.168.1.0/24)."
info "SSH admin restrictionat la: $LAN_SUBNET"

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
echo "  Webmin (panou de administrare vizual) va fi instalat automat la final,"
echo "  accesibil DOAR din subreteaua LAN de mai sus, pe HTTPS."
read -r -p "  -> Port Webmin (Enter = 10000 standard): " WEBMIN_PORT
WEBMIN_PORT="${WEBMIN_PORT:-10000}"
while ! [[ "$WEBMIN_PORT" =~ ^[0-9]+$ ]] || (( WEBMIN_PORT < 1 || WEBMIN_PORT > 65535 )); do
    warn "Port invalid."
    read -r -p "  -> Port Webmin (Enter = 10000 standard): " WEBMIN_PORT
    WEBMIN_PORT="${WEBMIN_PORT:-10000}"
done
info "Webmin va asculta pe portul ${WEBMIN_PORT}, doar din $LAN_SUBNET."

echo
echo "  ── Mailjet (relay SMTP de iesire) ─────────────────────────────────────"
echo "  Gaseste-le in Mailjet: Account Settings -> SMTP and SEND API Settings."
echo "  Secret Key se afiseaza o SINGURA data la generare - ai-o pregatita."
read -r -p "  -> Mailjet API Key: " MAILJET_API_KEY
while [[ -z "${MAILJET_API_KEY:-}" ]]; do
    warn "API Key nu poate fi gol."
    read -r -p "  -> Mailjet API Key: " MAILJET_API_KEY
done
read -rs -p "  -> Mailjet Secret Key (nu se afiseaza pe ecran): " MAILJET_SECRET_KEY
echo
while [[ -z "${MAILJET_SECRET_KEY:-}" ]]; do
    warn "Secret Key nu poate fi gol."
    read -rs -p "  -> Mailjet Secret Key: " MAILJET_SECRET_KEY
    echo
done
info "Credentiale Mailjet primite (nu vor fi afisate in log)."

echo
echo "  ── Cloudflare (certificat TLS automat, validare DNS-01) ───────────────"
echo "  Necesar pentru reinnoire automata a certificatului Let's Encrypt pentru"
echo "  ${MAIL_FQDN}, FARA sa depinda de portul 80/443 sau de reverse proxy-ul nginx."
echo "  Creeaza un API Token (NU Global API Key) in Cloudflare:"
echo "    dash.cloudflare.com -> My Profile -> API Tokens -> Create Token"
echo "    Permisiuni: Zone / DNS / Edit  +  Zone / Zone / Read"
echo "    Resurse: doar zona ${PRIMARY_DOMAIN} (nu toate zonele din cont)."
read -rs -p "  -> Cloudflare API Token: " CF_TOKEN
echo
while [[ -z "${CF_TOKEN:-}" ]]; do
    warn "Token-ul nu poate fi gol."
    read -rs -p "  -> Cloudflare API Token: " CF_TOKEN
    echo
done
info "Token Cloudflare primit (nu va fi afisat in log)."
warn "IMPORTANT: verifica in Cloudflare ca inregistrarea DNS pentru ${MAIL_FQDN}"
warn "este 'DNS only' (nor gri), NU 'Proxied' (nor portocaliu) - altfel clientii"
warn "de mail (SMTP/IMAP) nu se vor putea conecta (Cloudflare nu proxy-eaza mail)."

echo
info "Toate datele au fost colectate. Incepe instalarea..."
sleep 2

# ══════════════════════════════════════════════════════════════════════════════
section "1/11 - Actualizare sistem, hostname/FQDN, unelte de baza"
# ══════════════════════════════════════════════════════════════════════════════
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    software-properties-common apt-transport-https ca-certificates gnupg2 \
    curl wget unzip lsb-release net-tools htop vim git cron logrotate dialog \
    auditd audispd-plugins apparmor apparmor-utils libpam-pwquality \
    libpam-tmpdir acct unattended-upgrades apt-listchanges dnsutils swaks

hostnamectl set-hostname "$MAIL_FQDN"
MAIL_SHORT_NAME="${MAIL_FQDN%%.*}"
if ! grep -q "$MAIL_FQDN" /etc/hosts; then
    echo "${SERVER_IP} ${MAIL_FQDN} ${MAIL_SHORT_NAME}" >> /etc/hosts
fi
if [[ "$(hostname -f)" != "$MAIL_FQDN" ]]; then
    warn "hostname -f = $(hostname -f), diferit de $MAIL_FQDN. Verifica /etc/hosts."
else
    info "FQDN confirmat: $(hostname -f)"
fi
info "Sistem actualizat + unelte de baza instalate."

# ══════════════════════════════════════════════════════════════════════════════
section "2/11 - Hardening SSH (facut ACUM, inainte de iRedMail si UFW)"
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
section "3/11 - UFW Firewall (mail public, admin LAN-only, anti auto-lockout)"
# ══════════════════════════════════════════════════════════════════════════════
DEBIAN_FRONTEND=noninteractive apt-get install -y ufw

ufw --force reset
ufw default deny incoming
ufw default deny outgoing

# Outgoing - strict, doar ce e necesar unui mail server
ufw allow out 53                comment 'DNS'
ufw allow out 80/tcp            comment 'HTTP out (update-uri, ACME)'
ufw allow out 443/tcp           comment 'HTTPS out (update-uri, ACME, API Mailjet)'
ufw allow out 123/udp           comment 'NTP'
ufw allow out 25/tcp            comment 'SMTP out (livrare/relay)'
ufw allow out 587/tcp           comment 'SMTP submission out (relay Mailjet)'
ufw allow out 465/tcp           comment 'SMTPS out'

# Incoming - servicii de mail publice (trebuie accesibile din tot internetul)
ufw allow 25/tcp                comment 'SMTP in (primire mail)'
ufw allow 587/tcp               comment 'SMTP submission (clienti mail)'
ufw allow 465/tcp               comment 'SMTPS (clienti mail)'
ufw allow 993/tcp               comment 'IMAPS (clienti mail)'
ufw allow 995/tcp               comment 'POP3S (clienti mail, optional)'
ufw allow 80/tcp                comment 'HTTP public (webmail + ACME challenge)'
ufw allow 443/tcp               comment 'HTTPS public (webmail/SOGo/iRedAdmin)'

# Admin DOAR din LAN - SSH cu rate limiting (max 6 incercari/30s) + Webmin
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
info "UFW activat: mail public (25/587/465/993/995), web public (80/443), SSH+Webmin doar din $LAN_SUBNET."
warn "IMPORTANT: cand instalatorul iRedMail te va intreba daca vrea sa configureze"
warn "propriul firewall (iptables), raspunde NU - UFW deja acopera tot."

# ══════════════════════════════════════════════════════════════════════════════
section "4/11 - Instalare iRedMail (PARTEA INTERACTIVA)"
# ══════════════════════════════════════════════════════════════════════════════
cd /usr/local/src
IRM_VERSION=$(curl -fsSL https://api.github.com/repos/iredmail/iRedMail/releases/latest | \
    grep -oP '"tag_name":\s*"\K[^"]+' || true)
IRM_VERSION="${IRM_VERSION:-1.7.4}"
IRM_TARBALL="iRedMail-${IRM_VERSION}.tar.bz2"

if [[ ! -f "$IRM_TARBALL" ]]; then
    info "Descarc iRedMail ${IRM_VERSION}..."
    wget -q "https://github.com/iredmail/iRedMail/archive/refs/tags/${IRM_VERSION}.tar.gz" \
        -O "$IRM_TARBALL" || error "Nu am putut descarca iRedMail. Verifica versiunea/link-ul manual pe https://www.iredmail.org/download.html"
fi
rm -rf "iRedMail-${IRM_VERSION}"
mkdir -p "iRedMail-${IRM_VERSION}"
tar -xzf "$IRM_TARBALL" -C "iRedMail-${IRM_VERSION}" --strip-components=1
cd "iRedMail-${IRM_VERSION}"

cat << EOF

${BOLD}${YELLOW}=====================================================================
  URMEAZA WIZARD-UL OFICIAL iRedMail. Raspunde cu urmatoarele valori:
=====================================================================${NC}
  - Mail storage path:      lasa default (/var/vmail) daca ai destul spatiu
  - First domain:           ${PRIMARY_DOMAIN}
  - Domain admin password:  o parola PUTERNICA - noteaz-o intr-un manager de parole
  - Backend:                MySQL/MariaDB (recomandat, mai simplu de intretinut)
  - Componente:             lasa selectate implicit (Roundcube, SOGo, Fail2Ban = DA)
  - Firewall propriu iptables al iRedMail:  raspunde NU (UFW e deja configurat)
  - La final, ALEGE "y" pentru a incepe instalarea propriu-zisa.
${BOLD}${YELLOW}=====================================================================${NC}

EOF
read -r -p "  Apasa ENTER cand esti gata sa pornesti wizard-ul iRedMail..." _

# Rulam DIRECT pe /dev/tty pentru ca whiptail/dialog au nevoie de un terminal
# real - nu prin pipe-ul de logging (tee) folosit de restul scriptului.
bash iRedMail.sh < /dev/tty > /dev/tty 2>&1 || \
    error "Instalarea iRedMail a esuat sau a fost intrerupta. Verifica /var/log/iRedMail.log"

info "iRedMail instalat. Log complet: /var/log/iRedMail.log"

# ══════════════════════════════════════════════════════════════════════════════
section "5/11 - Postfix ca relay client prin Mailjet"
# ══════════════════════════════════════════════════════════════════════════════
MAILJET_HOST="in-v3.mailjet.com"
MAILJET_PORT="587"

echo "${MAILJET_HOST}:${MAILJET_PORT}    ${MAILJET_API_KEY}:${MAILJET_SECRET_KEY}" > /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd.db

# postconf -e este idempotent - sigur de rulat de mai multe ori (nu dubleaza linii)
postconf -e "relayhost = [${MAILJET_HOST}]:${MAILJET_PORT}"
postconf -e "smtp_sasl_auth_enable = yes"
postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
postconf -e "smtp_sasl_security_options = noanonymous"
postconf -e "smtp_sasl_tls_security_options = noanonymous"
postconf -e "smtp_tls_security_level = encrypt"
postconf -e "smtp_tls_wrappermode = no"
postconf -e "smtp_tls_note_starttls_offer = yes"
postconf -e "header_size_limit = 4096000"
# Header-ul asta ajuta fail2ban/postfix.iredmail sa vada IP-ul real al clientilor
# care s-au autentificat SASL local (login/webmail), nu afecteaza relay-ul catre Mailjet.
postconf -e "smtpd_sasl_authenticated_header = yes"

systemctl restart postfix
info "Postfix configurat sa foloseasca Mailjet (${MAILJET_HOST}:${MAILJET_PORT}) ca relay de iesire."

echo
info "Trimit un e-mail de test catre ${ADMIN_EMAIL} prin Mailjet (verificare credentiale)..."
if swaks --to "$ADMIN_EMAIL" --from "postmaster@${PRIMARY_DOMAIN}" \
        --server "$MAILJET_HOST" --port "$MAILJET_PORT" \
        --auth LOGIN --auth-user "$MAILJET_API_KEY" --auth-password "$MAILJET_SECRET_KEY" \
        --tls \
        --header "Subject: Test relay Mailjet - $(date '+%Y-%m-%d %H:%M')" \
        --body "Daca primesti acest e-mail, relay-ul Postfix -> Mailjet functioneaza corect." \
        > /tmp/swaks_test.log 2>&1; then
    info "Test SMTP catre Mailjet: SUCCES. Verifica inbox-ul ${ADMIN_EMAIL}."
else
    warn "Test SMTP catre Mailjet a esuat. Detalii in /tmp/swaks_test.log."
    warn "Verifica: API Key/Secret corecte, domeniul expeditor verificat in Mailjet,"
    warn "si ca DNS-ul (SPF/DKIM) e configurat asa cum e afisat la finalul scriptului."
fi

# ══════════════════════════════════════════════════════════════════════════════
section "6/11 - Webmin (.deb oficial, acces LAN-only)"
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
    # Webmin trimite esecurile de autentificare in syslog (-> /var/log/auth.log),
    # exact formatul pe care il asteapta filtrul oficial fail2ban 'webmin-auth':
    #   Dec 13 08:15:18 host webmin[25875]: Invalid login as root from 1.2.3.4
    # ATENTIE: /var/webmin/miniserv.log NU e bun pentru fail2ban - e un access log
    # in format Apache si nu contine deloc mesajele de autentificare esuata.
    sed -i '/^syslog=/d' /etc/webmin/miniserv.conf
    echo "syslog=1" >> /etc/webmin/miniserv.conf
    systemctl restart webmin
fi
systemctl enable --now webmin
info "Webmin instalat pe portul ${WEBMIN_PORT}, acces restrictionat la $LAN_SUBNET."

# ══════════════════════════════════════════════════════════════════════════════
section "7/11 - Fail2Ban (jail-urile iRedMail + jail-uri proprii)"
# ══════════════════════════════════════════════════════════════════════════════
systemctl enable --now fail2ban 2>/dev/null || true

# iRedMail scrie propriile jail-uri in /etc/fail2ban/jail.d/ (postfix, dovecot,
# postfix-pregreet, roundcube/sogo, sshd) DOAR daca ai raspuns "da" la Fail2Ban
# in wizard. Verificam si avertizam daca lipsesc.
for j in postfix dovecot postfix-pregreet; do
    if [[ ! -f "/etc/fail2ban/jail.d/${j}.local" ]]; then
        warn "Jail '${j}' nu a fost gasit - probabil ai raspuns NU la Fail2Ban in wizard iRedMail."
    fi
done

# Suprascriem jail-ul sshd al iRedMail cu portul nostru custom (iRedMail il
# auto-detecteaza la instalare, dar il fortam explicit ca sa fie garantat corect).
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/zz-custom-sshd.local << EOF
[sshd]
enabled  = true
port     = ${SSH_PORT}
backend  = systemd
maxretry = 3
bantime  = 86400
findtime = 600
EOF

# Webmin - filtrul oficial 'webmin-auth' citeste din SYSLOG, nu din miniserv.log
# (acela e access log Apache-like si nu contine mesajele de login esuat). De aceea
# am pus 'syslog=1' in miniserv.conf mai sus. Folosim backend systemd (fara logpath)
# ca sa mearga si pe Ubuntu fara rsyslog - journald capteaza orice mesaj syslog.
cat > /etc/fail2ban/jail.d/zz-custom-webmin.local << EOF
[webmin-auth]
enabled  = true
port     = ${WEBMIN_PORT}
filter   = webmin-auth
backend  = systemd
maxretry = 3
findtime = 600
bantime  = 86400
EOF

# iRedMail seteaza 'logtarget = SYSLOG' in /etc/fail2ban/fail2ban.local, deci
# /var/log/fail2ban.log ramane GOL -> jail-ul 'recidive' (care citeste exact acel
# fisier) nu s-ar declansa niciodata. Il readucem pe fisier printr-un override
# in fail2ban.d/*.local, care are precedenta peste fail2ban.local.
mkdir -p /etc/fail2ban/fail2ban.d
cat > /etc/fail2ban/fail2ban.d/zz-custom-logtarget.local << 'EOF'
[Definition]
logtarget = /var/log/fail2ban.log
EOF

# Recidivisti - oricine e banat de 3 ori in 24h ia 14 zile ban, indiferent
# de serviciul care l-a declansat (ssh, postfix, dovecot, roundcube, webmin...).
cat > /etc/fail2ban/jail.d/zz-custom-recidive.local << 'EOF'
[recidive]
enabled   = true
backend   = auto
logpath   = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime   = 1209600
findtime  = 86400
maxretry  = 3
EOF

# ignoreip DOAR localhost - un dispozitiv compromis din LAN nu trebuie sa fie imun.
# ATENTIE: iRedMail scrie in jail.local un ignoreip care albeste TOT spatiul privat
# (10/8, 172.16/12, 192.168/16). Il suprascriem din jail.d/*.local, care se citeste
# ULTIMUL (ordinea reala: jail.conf -> jail.d/*.conf -> jail.local -> jail.d/*.local).
cat > /etc/fail2ban/jail.d/zz-custom-00-default.local << 'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
EOF

if systemctl restart fail2ban; then
    sleep 1
    info "Fail2Ban activ. Jail-uri incarcate:"
    fail2ban-client status 2>/dev/null | grep "Jail list" || true
else
    warn "Fail2Ban a intampinat o problema la pornire. Verifica: sudo fail2ban-client status"
fi

# ══════════════════════════════════════════════════════════════════════════════
section "8/11 - Hardening kernel, login, fisiere"
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
-w /etc/postfix -p wa -k postfix_config
-w /etc/dovecot -p wa -k dovecot_config
EOF
augenrules --load 2>/dev/null || true
info "Hardening kernel/login/fisiere aplicat."

# ══════════════════════════════════════════════════════════════════════════════
section "9/11 - Actualizari automate de securitate"
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
section "10/11 - Certificat TLS automat (Let's Encrypt via acme.sh + Cloudflare DNS-01)"
# ══════════════════════════════════════════════════════════════════════════════
# DNS-01 nu are nevoie de portul 80/443 accesibil din exterior si nu depinde de
# reverse proxy-ul nginx din fata serverului - acme.sh cere singur, prin API-ul
# Cloudflare, o inregistrare TXT temporara si o sterge dupa validare.

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
    mkdir -p /etc/ssl/certs /etc/ssl/private
    [[ -f /etc/ssl/certs/iRedMail.crt ]] && cp -a /etc/ssl/certs/iRedMail.crt /etc/ssl/certs/iRedMail.crt.bak
    [[ -f /etc/ssl/private/iRedMail.key ]] && cp -a /etc/ssl/private/iRedMail.key /etc/ssl/private/iRedMail.key.bak

    info "Cer certificatul Let's Encrypt pentru ${MAIL_FQDN} (validare DNS-01 prin Cloudflare)..."
    if "$ACME_BIN" --home "$ACME_HOME" --issue --dns dns_cf -d "$MAIL_FQDN" --keylength 2048; then
        "$ACME_BIN" --home "$ACME_HOME" --install-cert -d "$MAIL_FQDN" \
            --key-file       /etc/ssl/private/iRedMail.key \
            --fullchain-file /etc/ssl/certs/iRedMail.crt \
            --reloadcmd      "systemctl restart postfix dovecot; systemctl restart nginx 2>/dev/null || systemctl restart apache2 2>/dev/null || true"
        chmod 640 /etc/ssl/private/iRedMail.key
        chown root:root /etc/ssl/private/iRedMail.key
        info "Certificat Let's Encrypt instalat pentru Postfix/Dovecot/webmail local."
        info "Reinnoire automata: acme.sh instaleaza singur un cron/systemd-timer (verificare de 2x/zi,"
        info "reinnoieste cu ~30 zile inainte de expirare, ruleaza reloadcmd automat)."
        unset CF_TOKEN CF_Token
    else
        warn "Emiterea certificatului a esuat. Cauze frecvente:"
        warn "  - token Cloudflare fara permisiuni Zone:DNS:Edit pe zona ${PRIMARY_DOMAIN}"
        warn "  - domeniul ${PRIMARY_DOMAIN} nu e (inca) gestionat de acel cont Cloudflare"
        warn "Certificatul auto-semnat de iRedMail ramane activ pana rezolvi si rulezi manual:"
        warn "  export CF_Token='...'; ${ACME_BIN} --issue --dns dns_cf -d ${MAIL_FQDN}"
        unset CF_TOKEN CF_Token
    fi
else
    warn "Instalarea acme.sh a esuat. Vezi manual: https://github.com/acmesh-official/acme.sh"
fi

echo
warn "IMPORTANT - partea din nginx (alta masina, reverse proxy-ul din LAN):"
warn "  Certificatul de mai sus e valabil DOAR pe acest server (Postfix/Dovecot +"
warn "  webmail-ul local). Pe masina cu nginx reverse proxy, instaleaza SEPARAT"
warn "  acme.sh cu ACELASI token Cloudflare si cere ACELASI certificat pentru"
warn "  ${MAIL_FQDN}, ca sa inlocuiesti Origin Certificate-ul (care nu e de incredere"
warn "  pentru clientii de mail oricum, doar pentru conexiunea Cloudflare<->nginx)."

# ══════════════════════════════════════════════════════════════════════════════
section "11/11 - Sumar final + inregistrari DNS necesare"
# ══════════════════════════════════════════════════════════════════════════════
apt-get autoremove -y -qq
apt-get autoclean -qq

DKIM_RECORD=""
if command -v amavisd-new >/dev/null 2>&1 && [[ -f /var/lib/dkim/${PRIMARY_DOMAIN}.dns ]]; then
    DKIM_RECORD=$(cat "/var/lib/dkim/${PRIMARY_DOMAIN}.dns")
fi

echo
cat << 'DONE'
  ==================================================================
                    INSTALARE FINALIZATA
  ==================================================================
DONE
echo "  Server IP:      $SERVER_IP"
echo "  Hostname:       $MAIL_FQDN"
echo "  Domeniu mail:   $PRIMARY_DOMAIN"
echo "  Webmail:        https://${MAIL_FQDN}/mail/  (Roundcube/SOGo, dupa instalare iRedMail)"
echo "  Admin panel:    https://${MAIL_FQDN}/iredadmin/"
echo "  Webmin:         https://${SERVER_IP}:${WEBMIN_PORT}   (doar LAN: $LAN_SUBNET)"
echo "  Relay iesire:   Postfix -> Mailjet (${MAILJET_HOST}:${MAILJET_PORT})"
echo
echo "  === CONECTARE SSH DE ACUM INAINTE ==="
echo "    ssh -p ${SSH_PORT} ${ADMIN_OS_USER}@${SERVER_IP}"
echo "    (recomandat) pune chei SSH, apoi dezactiveaza parola:"
echo "      ssh-copy-id -p ${SSH_PORT} ${ADMIN_OS_USER}@${SERVER_IP}"
echo "      sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/99-hardening.conf"
echo "      sudo systemctl restart ssh"
echo
echo "  === INREGISTRARI DNS OBLIGATORII (zona ${PRIMARY_DOMAIN}) ==="
echo "  MX     ${PRIMARY_DOMAIN}.        ->  10 ${MAIL_FQDN}."
echo "  A      ${MAIL_FQDN}.  ->  ${SERVER_IP}   (in Cloudflare: 'DNS only' / nor GRI, NU Proxied!)"
echo "  PTR (rDNS, la providerul de hosting/cloud):  ${SERVER_IP} -> ${MAIL_FQDN}"
echo "  SPF (TXT pe @):"
echo "     \"v=spf1 mx include:spf.mailjet.com ~all\""
echo "  DMARC (TXT pe _dmarc):"
echo "     \"v=DMARC1; p=quarantine; rua=mailto:${ADMIN_EMAIL}\""
if [[ -n "$DKIM_RECORD" ]]; then
    echo "  DKIM (TXT, generat de iRedMail/OpenDKIM):"
    echo "     $DKIM_RECORD"
else
    echo "  DKIM (OpenDKIM, generat de iRedMail): vezi 'sudo amavisd-new showkeys'"
    echo "     sau /var/lib/dkim/${PRIMARY_DOMAIN}.dns"
fi
echo "  DKIM Mailjet (separat, pentru mail-ul trimis PRIN Mailjet ca relay):"
echo "     adauga in Mailjet -> Account -> DNS/Domains domeniul ${PRIMARY_DOMAIN},"
echo "     apoi copiaza inregistrarile TXT afisate acolo (mailjet._domainkey + verificare domeniu)."
echo
echo "  === VERIFICARI ==="
echo "    sudo fail2ban-client status"
echo "    sudo ufw status verbose"
echo "    sudo swaks --to test@extern.ro --from postmaster@${PRIMARY_DOMAIN} --server localhost"
echo "    cat /tmp/swaks_test.log   (rezultatul testului Mailjet de mai devreme)"
echo "    sudo ${ACME_BIN} --list                       (starea certificatului Let's Encrypt)"
echo "    echo | openssl s_client -connect ${MAIL_FQDN}:993 2>/dev/null | openssl x509 -noout -dates"
echo
echo "  === NGINX REVERSE PROXY (alta masina) ==="
echo "  Certificatul emis aici e valabil DOAR pe acest server. Repeta emiterea"
echo "  (acme.sh + acelasi token Cloudflare, DNS-01) SEPARAT pe masina cu nginx,"
echo "  ca sa inlocuiesti Origin Certificate-ul folosit acum pentru ${MAIL_FQDN}."
echo
echo "  NOTA: relayhost e setat GLOBAL - TOT mail-ul de iesire trece prin Mailjet."
echo "  Portul 25 de intrare ramane deschis pentru a PRIMI mail (nu e afectat de relay)."
echo
echo "  Log instalare:      $LOG"
echo "  Log iRedMail:       /var/log/iRedMail.log"
echo "  =================================================================="
