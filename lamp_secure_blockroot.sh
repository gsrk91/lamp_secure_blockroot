
#!/bin/bash

# Logare instalare
exec > >(tee /var/log/lamp_setup.log) 2>&1

echo "=== Instalare LAMP + phpMyAdmin + Fail2Ban + Webmin + Hardening Securitate ==="

# Verificare privilegiu sudo
if [ "$EUID" -ne 0 ]; then
  echo "🔒 Te rog rulează scriptul ca root sau cu sudo."
  exit 1
fi

# Citire parolă MariaDB root
read -p "Introduceți un nume de utilizator MySQL (cu drepturi de root): " MYSQL_ADMIN_USER
read -s -p "Introduceți parola pentru utilizatorul $MYSQL_ADMIN_USER: " MYSQL_ADMIN_PASS
echo
read -s -p "Introduceți parola pentru MariaDB root: " MYSQL_ROOT_PASS
echo
read -p "Introduceți username pentru protecția HTTP Basic (phpMyAdmin): " HTTP_USER
read -s -p "Introduceți parola pentru acest user: " HTTP_PASS
echo

# Update și upgrade
apt update && apt upgrade -y

# Instalare pachete esențiale
apt install -y apache2 mariadb-server php libapache2-mod-php php-mysql php-cli php-curl php-xml php-mbstring php-opcache unzip curl apache2-utils fail2ban unattended-upgrades apt-listchanges wget gnupg2

# Activare servicii
systemctl enable --now apache2 mariadb fail2ban


mysql -u root <<MYSQL_SCRIPT
-- Securizare root
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
DELETE FROM mysql.user WHERE User='root' AND Host!='localhost';

-- Creare utilizator personalizat cu privilegii root
CREATE USER '${MYSQL_ADMIN_USER}'@'localhost' IDENTIFIED BY '${MYSQL_ADMIN_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_ADMIN_USER}'@'localhost' WITH GRANT OPTION;

-- Dezactivare completă user root
RENAME USER 'root'@'localhost' TO 'disabled_root'@'localhost';

FLUSH PRIVILEGES;
MYSQL_SCRIPT

mysql -u root <<MYSQL_SCRIPT
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
DELETE FROM mysql.user WHERE User='root' AND Host!='localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

# Fișier test PHP
echo "<?php phpinfo(); ?>" > /var/www/html/info.php

# Instalare phpMyAdmin
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
echo "phpmyadmin phpmyadmin/app-password-confirm password $MYSQL_ROOT_PASS" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/admin-pass password $MYSQL_ROOT_PASS" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/app-pass password $MYSQL_ROOT_PASS" | debconf-set-selections
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections
apt install -y phpmyadmin

# Activare module Apache
a2enmod rewrite headers ssl

# Protecție HTTP Basic
htpasswd -cb /etc/apache2/.htpasswd "$HTTP_USER" "$HTTP_PASS"

# Config Apache phpMyAdmin
mv /etc/apache2/conf-available/phpmyadmin.conf /etc/apache2/conf-available/phpmyadmin.conf.bak 2>/dev/null
cat <<EOL > /etc/apache2/conf-available/phpmyadmin.conf
Alias /phpmyadmin /usr/share/phpmyadmin

<Directory /usr/share/phpmyadmin>
    Options -Indexes +FollowSymLinks
    DirectoryIndex index.php
    AllowOverride All

    <IfModule mod_php.c>
        php_admin_value upload_max_filesize 64M
        php_admin_value post_max_size 64M
    </IfModule>

    <IfModule mod_php.c>
        php_admin_value open_basedir none
    </IfModule>

    <IfModule mod_php.c>
        php_admin_value disable_functions none
    </IfModule>

    <FilesMatch "\\.(htaccess|htpasswd|ini|log|conf)\$">
        Require all denied
    </FilesMatch>

    AuthType Basic
    AuthName "phpMyAdmin Secure"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>
EOL

a2enconf phpmyadmin
systemctl restart apache2

# Permisiuni fișiere web
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

# Fail2Ban configurare
cat <<EOL > /etc/fail2ban/jail.local
[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log
maxretry = 3
findtime = 600
bantime = 3600

[apache-auth]
enabled = true
port    = http,https
filter  = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3
findtime = 600
bantime = 3600

[phpmyadmin]
enabled = true
port     = http,https
filter   = phpmyadmin
logpath  = /var/log/apache2/error.log
maxretry = 3
findtime = 600
bantime = 3600
EOL

cat <<EOL > /etc/fail2ban/filter.d/phpmyadmin.conf
[Definition]
failregex = .*client denied by server configuration:.*phpmyadmin.*
ignoreregex =
EOL

systemctl restart fail2ban

# Headers securitate Apache
cat <<EOL > /etc/apache2/conf-available/security-hardening.conf
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
EOL

a2enconf security-hardening
systemctl reload apache2

# Activare actualizări automate
dpkg-reconfigure -f noninteractive unattended-upgrades
cat <<EOL > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Autoremove "1";
EOL

# Instalare Webmin .deb fallback
wget https://www.webmin.com/download/deb/webmin-current.deb -O webmin.deb
apt install -y ./webmin.deb

# Firewall
ufw allow 'OpenSSH'
ufw allow 'Apache Full'
ufw allow 10000/tcp
ufw --force enable

# Cleanup
rm -f /var/www/html/info.php
apt autoremove -y
apt autoclean

echo "✅ Instalare finalizată cu succes. phpMyAdmin: http://<IP>/phpmyadmin | Webmin: https://<IP>:10000"


# Blocare login root în phpMyAdmin
PMA_CONFIG_FILE="/etc/phpmyadmin/config.inc.php"
if grep -q "AllowRoot" "$PMA_CONFIG_FILE"; then
    sed -i "s/\$cfg\['Servers'\]\[\$i\]\['AllowRoot'\] = true;/\$cfg['Servers'][\$i]['AllowRoot'] = false;/" "$PMA_CONFIG_FILE"
else
    echo "$cfg['Servers'][\$i]['AllowRoot'] = false;" >> "$PMA_CONFIG_FILE"
fi
