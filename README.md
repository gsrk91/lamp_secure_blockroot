Nu uita să-i dai permisiuni de execuție pe server: chmod +x lamp_secure_blockroot.sh
Apoi rulează-l cu: sudo ./nume_script.sh sau sudo bash nume_script.sh

Fisierul lamp_change_ssh_port.sh contine si modificarea automata a port-ului pentru SSH in baza input-ului, 
adica in functie de port-ul care se vrea si va adauga si regula in UFW.

Daca la rularea sudo bash nume_script.sh se genereaza o eroare, se va solutiona prin executarea comenzii "sudo sed -i 's/\r//' nume_script.sh". 
Eroarea este generata de diferentele dintre Windows (unde s-a generat intreg fisierul) si Ubuntu Server (unde se ruleaza script-ul).

Scriptul final_boss.sh îți cere subrețeaua LAN și portul SSH la început, apoi face totul automat. 
La final îți afișează comanda exactă de conectare (ssh -p PORT user@ip). 

Adăugarea unui site se face cu sudo add-wp-site domeniu.ro nume_db user_db parola_db.

Pentru un website static ai două opțiuni, în funcție de cât de des vei face asta.
Opțiunea 1 — instalează helperul add-static-site (recomandat)
L-am construit să fie perechea statică a lui add-wp-site. Îl pui pe server o singură dată:
bashsudo cp add-static-site /usr/local/bin/add-static-site
sudo chmod +x /usr/local/bin/add-static-site
Apoi îl folosești pentru orice site static:
bashsudo add-static-site domeniu.ro
Creează directorul /var/www/domeniu.ro, pune un index.html demonstrativ (pe care îl înlocuiești cu al tău), 
setează permisiunile corecte și creează un VirtualHost curat — fără reguli WordPress (xmlrpc, wp-config), fără bază de date, fără PHP. 
Doar servire statică.

Opțiunea 2 — manual, dacă e un singur site și nu vrei helper
bash# 1. Creezi directorul si pui fisierul tau
sudo mkdir -p /var/www/domeniu.ro
sudo cp index.html /var/www/domeniu.ro/
# 2. Permisiuni
sudo chown -R www-data:www-data /var/www/domeniu.ro
sudo find /var/www/domeniu.ro -type d -exec chmod 755 {} \;
sudo find /var/www/domeniu.ro -type f -exec chmod 644 {} \;
# 3. VirtualHost
sudo tee /etc/apache2/sites-available/domeniu.ro.conf > /dev/null << 'EOF'
<VirtualHost *:80>
    ServerName domeniu.ro
    ServerAlias www.domeniu.ro
    DocumentRoot /var/www/domeniu.ro
    DirectoryIndex index.html
    <Directory /var/www/domeniu.ro>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog  ${APACHE_LOG_DIR}/domeniu.ro-error.log
    CustomLog ${APACHE_LOG_DIR}/domeniu.ro-access.log combined
</VirtualHost>
EOF
# 4. Activezi si reincarci
sudo a2ensite domeniu.ro.conf
sudo systemctl reload apache2
Diferența cheie față de add-wp-site: un site static n-are nevoie de PHP rulat pe fișiere, deci VirtualHost-ul e mai simplu și 
mai sigur (suprafață de atac mai mică). 
Options -Indexes rămâne în ambele, ca să nu se poată lista conținutul directorului dacă lipsește index.html.
Pentru SSL gratuit, după ce domeniul pointează către IP-ul serverului: sudo certbot --apache -d domeniu.ro -d www.domeniu.ro — funcționează 
identic și pentru site-uri statice.

# Site WordPress complet (cu baza de date)
sudo add-wp-site domeniu.ro nume_db user_db parola_db

# Site static (doar HTML/CSS/JS, fara DB)
sudo add-static-site domeniu.ro

Ambele apar și în sumarul afișat la finalul instalării, ca să le ai la îndemână. 
Pentru oricare dintre ele, SSL-ul gratuit se adaugă la fel: sudo certbot --apache -d domeniu.ro -d www.domeniu.ro.

Daca phpMyAdmin da eroare la rulare, se va inlocui linia 165, astfel: 
sudo nano /etc/phpmyadmin/config.inc.php cu $cfg['Servers'][$i]['AllowRoot'] = false;

Daca nu se poate accesa phpMyAdmin primind eroarea: mysqli::real_connect(): (HY000/1045): 
Access denied for user 'utilizator'@'localhost' (using password: YES) atunci CREATE USER 'utilizator'@'localhost' IDENTIFIED BY 'oParolaBlana123!'; 
GRANT ALL PRIVILEGES ON . TO 'utilizator'@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;

Daca in phpMyAdmin, inca exista utilizatorul root sau o derivatie, se va actiona astfel:
* se va verifica exista oricarei extensii root prin: sudo mysql SELECT User, Host FROM mysql.user WHERE User = 'root';
* apoi se va sterge acel utilizator prin: DROP USER 'root'@'127.0.0.1'; DROP USER 'root'@'::1'; 
DROP USER 'root'@'%'; (se va adapta in functie de ceea ce se gaseste in server)
