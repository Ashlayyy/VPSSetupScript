#!/bin/bash

export LC_ALL=C

GithubURL_Config="https://github.com/Ashlayyy/config.git"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ScriptPath="$SCRIPT_DIR/script-on-login.sh"
SSH_Port=1087
NFTY_Port=2586

cancel() {
    echo -e
    echo -e " Aborted..."
    exit
}

SendHelpMenu() {
    echo -e
    echo -e
    echo -e
    echo -e "Usage: sudo ./setup.sh [-mh]"
    echo -e
    echo -e "Flags:"
    echo -e "       -h | --help : prints this lovely message, then exits"
    echo -e "       -d | --domain : Add your domain name"
    echo -e "       -gh_w | --githubHook : Add your github webhook in the following format:"
    echo -e "               'WEBHOOK_ID=WEBHOOK_SECRET'"
    echo -e "       -gh | --githubUrl : Add your github repository url"
    echo -e "       -gh_b | --githubBranch : Add your github branch"
    echo -e "       -u | --user : Add the user in control of the site"
    echo -e "       -cu | --createUser : Create a new user and uses that user for the site control. You should also add this user to the --user variable, so that everything will be set accordingly."
    echo -e "       -of | --optionalFolder : Add the folder name for the optional folder(s) in the project"
    echo -e "       --project : Add the project name"
    echo -e "       -f | --filename : Add the file name that PM2 needs to startup"
    echo -e "       -s | --ssl : Add the SSL certificate"
    echo -e "       -p | --port : Add the port number your server will be running on"
    echo -e "       --email : The email connected to this server"
    echo -e "       --ssh-key : Add the SSH key for the user"
    echo -e 
    echo -e 
    echo -e 
    exit 0
}

ConfigureFolderStructure() {
    mkdir -p /sites/$domain/
    chown -R $user:$user /sites/$domain/
    chmod -R 755 /sites/$domain/
    echo -e "Site folder has been created"
    mkdir -p /sites/$domain/API/
    mkdir -p /sites/$domain/Config/
    mkdir -p /sites/$domain/Config/Webhooks/
    mkdir -p /sites/$domain/Projects/
    mkdir -p /sites/$domain/Scripts/
    mkdir -p /sites/$domain/Scripts/OnLogin/
    mkdir -p /sites/$domain/Site/
    sudo touch /var/www/html/404.html
    sudo touch /var/www/html/502.html

    mkdir -p /sites/$domain/Temp/
    
    ls -la /sites/$domain/

    echo -e "Folder structure has been created"
}

ConfigureErrorPage() {
    ErrorPage="error_page 404 /404.html;
    location = /404.html {
        root /var/www/html;
        internal;
    }"
    InternalErrorPage="error_page 502 /502.html;
    location = /502.html {
        root /var/www/html;
        internal;
    }"
}

ConfigureGithubHook() {
    GithubHookID=$(echo "$githubHook" | cut -f1 -d '=')
    GithubHookSecret=$(echo "$githubHook" | cut -f2 -d '=')
    echo -e "Github Hook ID: $GithubHookID"
    echo -e "Github Hook Secret: $GithubHookSecret"
    GithubHookLocation="location = /hooks/ {
        proxy_pass http://localhost:9000/hooks/;
    }"

    git clone $GithubURL_Config /sites/$domain/Temp/config/
    ls -la /sites/$domain/Temp/
    ls -la /sites/$domain/Temp/config/
    mv /sites/$domain/Temp/config/hooks.json /sites/$domain/Config/Webhooks/hooks.json
    rm -rf /sites/$domain/Temp/
    sed -i "/--id--/c\\$GithubHookID/g" /sites/$domain/Config/Webhooks/hooks.json
    sed -i "/--scriptUrl--/c\/sites/$domain/Scripts/site_hook.sh/g" /sites/$domain/Config/Webhooks/hooks.json
    sed -i "/--directive--/c\//g" /sites/$domain/Config/Webhooks/hooks.json
    sed -i "/--secret--/c\\$GithubHookSecret/g" /sites/$domain/Config/Webhooks/hooks.json

    cat <<EOF >"/sites/$domain/Scripts/site_hook.sh"
        cd "/sites/$domain/site/$optionalFolder"
        git pull origin $githubBranch
        npm install
        pm2 reload all
EOF
    chmod +x /sites/$domain/Scripts/site_hook.sh
    echo -e "Github Webhook has been configured"
}

ConfigureNGINX() {
    ConfigureErrorPage
    fileLocation="/etc/nginx/conf.d/$domain.conf"
    rm -rf "/etc/nginx/sites-enabled/default"
    touch $fileLocation
    cat <<EOF >"/etc/nginx/conf.d/$domain.conf"
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        return 301 https:/\$host\$request_uri;
    }

    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=main_cache:10m max_size=1g inactive=360m use_temp_path=off;

    server {
        listen 443 http2;
        listen [::]:443 http2;
        server_name ntfy.$domain www.ntfy.$domain;
        access_log /var/log/nginx/ntfy.$domain.access.log;

        location / {
            proxy_pass http://127.0.0.1:$NFTY_Port;
            proxy_http_version 1.1;

            proxy_buffering off;
            proxy_request_buffering off;
            proxy_redirect off;

            proxy_set_header Host \$http_host;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

            proxy_connect_timeout 3m;
            proxy_send_timeout 3m;
            proxy_read_timeout 3m;

            client_max_body_size 0;
        }
    }

    server {
        listen 443 http2;
        listen [::]:443 http2;
        server_name $domain www.$domain;
        access_log /var/log/nginx/$domain.access.log;

        #sslLocation

        $ErrorPage
        $InternalErrorPage
        $GithubHookLocation


        proxy_set_header                Host \$host:\$server_port;
        proxy_set_header                X-Real-IP \$remote_addr;
        proxy_set_header                X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header                X-Forwarded-Proto \$scheme;
        add_header                      X-Cache-Status \$upstream_cache_status;
        add_header                      Strict-Transport-Security "max-age=63072000 always;";
        add_header                      X-Frame-Options DENY;
        add_header                      X-Content-Type-Options nosniff;
        add_header                      X-XSS-Protection "1; mode=block";
        add_header                      Content-Security-Policy "default-src 'self'; font-src *;img-src * data:; script-src *; style-src *";
        add_header                      Referrer-Policy "origin";
        proxy_cache                     main_cache;
        proxy_cache_valid               200 302 60m;
        proxy_cache_valid               404 1m;
        proxy_cache_use_stale           error timeout http_500 http_502 http_503 http_504;
        proxy_cache_background_update   on;
        proxy_cache_methods             GET HEAD;
        proxy_read_timeout              90;
        rewrite ^([^.]*[^/])$ \$1/ permanent;

        location / {
          proxy_set_header        Host \$host:\$server_port;
          proxy_set_header        X-Real-IP \$remote_addr;
          proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
          proxy_set_header        X-Forwarded-Proto \$scheme;
          proxy_cache main_cache;
          proxy_cache_valid 200 302 30m;
          proxy_cache_valid 404 1m;
          proxy_pass              http://localhost:$port;
          proxy_read_timeout      90;
          add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
          add_header X-Frame-Options DENY;
          add_header X-Content-Type-Options nosniff;
          add_header X-XSS-Protection "1; mode=block";
          add_header Referrer-Policy "origin";
          rewrite ^([^.]*[^/])$ \$1/ permanent;
        }
    }
EOF
}

ConfigurePM2() {
    ps aux | grep pm2 | grep -v grep | awk '{print $2}' | xargs kill -9 >/dev/null 2>&1
    npm install pm2 -g
    pm2 startup -u $user
    sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u $user --hp /home/$user
    pm2 save
    sudo systemctl start pm2-$user
}

ConfigureSSL() {
    sudo certbot --nginx -d $domain -d www.$domain --email $email --agree-tos
    sudo certbot --nginx -d ntfy.$domain -d www.ntfy.$domain --email $email --agree-tos
    sudo systemctl status certbot.timer
    chmod +x $SCRIPT_DIR/sed-command.sh
    sudo $SCRIPT_DIR/sed-command.sh /etc/nginx/conf.d/$domain.conf
    sed -i "/listen 443 http2;/c\listen 443 ssl http2;" /etc/nginx/conf.d/$domain.conf
    sed -i "/listen [::]:443 http2;/c\listen [::]:443 ssl http2;" /etc/nginx/conf.d/$domain.conf
    sudo nginx -t
    sudo systemctl reload nginx
}

ConfigureUser() {
    if [[ $createUser != "" ]]; then
        user=$createUser
        adduser --disabled-password --gecos "" $createUser
        usermod -aG sudo $createUser
        echo -e "User: $createUser has been created!"
        if [[ ! -d "/home/$USERNAME/.ssh" ]]; then
            mkdir -p /home/$USERNAME/.ssh
        fi
        touch /home/$USERNAME/.ssh/authorized_keys
        echo -e "$key" >>/home/$USERNAME/.ssh/authorized_keys
        echo -e 'Saved SSH Key\n'
    fi
}

ConfigurePackages() {
    sudo apt update -y
    mkdir -p /etc/apt/keyrings
    rm -rf /etc/apt/keyrings/nodesource.gpg
    rm -rf /etc/apt/keyrings/archive.heckel.io.gpg
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
    NODE_MAJOR=22
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
    curl -fsSL https://archive.heckel.io/apt/pubkey.txt | sudo gpg --dearmor -o /etc/apt/keyrings/archive.heckel.io.gpg
    sudo apt-get install apt-transport-https
    sudo sh -c "echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/archive.heckel.io.gpg] https://archive.heckel.io/apt debian main' \
        > /etc/apt/sources.list.d/archive.heckel.io.list"  
    sudo apt update -y
    apt install nodejs npm -y
    apt-get install nodejs npm -y
    sudo apt install ntfy -y
    apt install ca-certificates curl gnupg sudo ufw htop curl nginx tmux git certbot python3-certbot-nginx autojump webhook -y
    sudo systemctl enable ntfy
    sudo systemctl start ntfy
    sudo apt-get install nodejs -y
    apt update -y
    apt upgrade -y
}

ConfigureServer() {
    timedatectl set-timezone Europe/Amsterdam
    sed -i '/PermitRootLogin yes/c\PermitRootLogin no' /etc/ssh/sshd_config
    sed -i '/PasswordAuthentication yes/c\PasswordAuthentication no' /etc/ssh/sshd_config
    sed -i '/#LoginGraceTime 2m/c\LoginGraceTime 20' /etc/ssh/sshd_config
    sed -i '/#MaxAuthTries 6/c\MaxAuthTries 3' /etc/ssh/sshd_config
    sed -i '/#MaxSessions 10/c\MaxSessions 5' /etc/ssh/sshd_config
    sed -i '/#PermitEmptyPasswords no/c\PermitEmptyPasswords no' /etc/ssh/sshd_config
    sed -i '/#KerberosAuthentication no/c\KerberosAuthentication no' /etc/ssh/sshd_config
    sed -i '/#GSSAPIAuthentication no/c\GSSAPIAuthentication no' /etc/ssh/sshd_config
    sed -i '/#AllowAgentForwarding yes/c\AllowAgentForwarding no' /etc/ssh/sshd_config
    sed -i '/#AllowTcpForwarding yes/c\AllowTcpForwarding no' /etc/ssh/sshd_config
    sed -i '/#X11Forwarding no/c\X11Forwarding no' /etc/ssh/sshd_config
    sed -i '/#ClientAliveInterval 0/c\ClientAliveInterval 120' /etc/ssh/sshd_config
    sed -i '/#ClientAliveCountMax 3/c\ClientAliveCountMax 2' /etc/ssh/sshd_config
    sed -i '/#MaxStartups 10:30:100/c\MaxStartups 10:30:55' /etc/ssh/sshd_config
    sed -i '/#PermitTunnel no/c\PermitTunnel no' /etc/ssh/sshd_config
    sed -i '/#Banner none/c\Banner none' /etc/ssh/sshd_config
    sed -i '/Subsystem\"/c\#Subsystem' /etc/ssh/sshd_config
    sed -i "/#Port 22/c\Port $SSH_Port" /etc/ssh/sshd_config
    sed -i "/UsePAM yes/c\UsePAM no" /etc/ssh/sshd_config
    echo -e "ForceCommand /sites/$domain/Scripts/OnLogin/script-on-login.sh" >> /etc/ssh/sshd_config
    echo -e "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes256-cbc
            KexAlgorithms diffie-hellman-group14-sha256,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521
            MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" >> /etc/ssh/sshd_config
    echo -e "SSH has been configured. It uses port $SSH_Port"
    sudo ufw default allow outgoing
    #sudo ufw default deny incoming
    #sudo grep IPV6 /etc/default/ufw
    sudo ufw deny 80 comment 'Deny use of unsecured trafic'
    sudo ufw allow 443 comment 'Allow use of secured trafic'
    sudo ufw allow $SSH_Port/tcp
    sudo ufw allow ssh
    #sudo ufw limit $SSH_Port comment 'SSH port rate limit'
    yes 'y' | sudo ufw enable
    sudo ufw status
    sudo nginx -s reload 
    sudo apt autoremove -y

    echo -e "Server has been configured"
    echo -e "You should consider rebooting!"
}

ConfigureFail2Ban() {
    apt-get install fail2ban -y
    systemctl status fail2ban.service
    sudo cp $SCRIPT_DIR/fail2ban.txt /etc/fail2ban/jail.local
}

ConfigureScriptOnLogin() {
    mv $ScriptPath /sites/$domain/Scripts/OnLogin/script-on-login.sh
    chmod +x /sites/$domain/Scripts/OnLogin/script-on-login.sh
    sudo rm -rf /etc/ntfy/server.yml
    sudo touch /etc/ntfy/server.yml
    sudo echo -e "  
    base-url: "http://ntfy.$domain"
    upstream-base-url: "https://ntfy.sh"
    listen-http: ""
    listen-https: ":443"
    behind-proxy: true
    auth-file: "/var/lib/ntfy/user.db"
    auth-default-access: "deny-all"
    key-file: "/etc/letsencrypt/live/ntfy.$domain.key"
    cert-file: "/etc/letsencrypt/live/ntfy.$domain.crt"
    cache-file: "/var/cache/ntfy/cache.db"
    attachment-cache-dir: "/var/cache/ntfy/attachments"
    " >> /etc/ntfy/server.yml
    ntfy serve
    ntfy user add --role=admin ashlay
    (&>/dev/null ntfy serve &)
}

ConfigureDocker() {
    if [[ -z "$(command -v docker)" ]]; then
        curl -fsSL https://get.docker.com | bash
    fi
    usermod -aG docker $user

    if [[ -z "$(command -v docker-compose)" ]]; then
        curl -L "https://github.com/docker/compose/releases/download/1.25.5/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
    fi
}

ConfigureGitClone() {
    git clone $githubUrl /sites/$domain/Site/
    git config --global --add safe.directory /sites/$domain
    cd /sites/$domain/Site/
    git checkout $githubBranch
    git pull origin $githubBranch
    npm install
    pm2 start $filename --watch --ignore-watch="node_modules" --time --name $project
    pm2 save
}

if [[ $# -eq 0 ]]; then
    SendHelpMenu
fi

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
    -d | --domain)
        domain="$2"
        shift # past argument
        shift # past value
        ;;
    -gh_w | --githubHook)
        githubHook="$2"
        shift # past argument
        shift # past value
        ;;
    -gh | --githubUrl)
        githubUrl="$2"
        shift # past argument
        shift # past value
        ;;
    -gh_b | --githubBranch)
        githubBranch="$2"
        shift # past argument
        shift # past value
        ;;
    -u | --user)
        user="$2"
        shift # past argument
        shift # past value
        ;;
    -cu | --createUser)
        createUser="$2"
        shift # past argument
        shift # past value
        ;;
    -of | --optionalFolder)
        optionalFolder="$2"
        shift # past argument
        shift # past value
        ;;
    --project)
        project="$2"
        shift # past argument
        shift # past value
        ;;
    -f | --filename)
        filename="$2"
        shift # past argument
        shift # past value
        ;;
    -s | --ssl)
        ssl=true
        shift # past argument
        ;;
    -p | --port)
        port="$2"
        shift # past argument
        shift # past value
        ;;
    --email)
        email="$2"
        shift # past argument
        shift # past value
        ;;
    --ssh-key)
        key="$2"
        shift # past argument
        shift # past value
        ;;
    -h | --help)
        SendHelpMenu
        ;;
    -* | --*)
        echo "Unknown option $1"
        exit 1
        ;;
    *)
        echo "Unknown option $1"
        POSITIONAL_ARGS+=("$1") # save positional arg
        shift                   # past argument
        ;;
    esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

echo -e '# ## ## ## ## ## ## ## ## ## ## ## ## #'
echo -e '#           VPS Setup Script          #'
echo -e '# ## ## ## ## ## ## ## ## ## ## ## ## #'

echo -e
date

if [[ $domain == "" ]]; then
    echo -e "Please enter a domain"
    cancel
fi

if [[ $githubUrl == "" ]]; then
    echo -e "Please enter a github url"
    cancel
fi

if [[ $githubBranch == "" ]]; then
    echo -e "Please enter a github branch"
    cancel
fi

if [[ $user == "" ]]; then
    echo -e "Please enter a user"
    cancel
fi

if [[ $project == "" ]]; then
    echo -e "Please enter a project"
    cancel
fi

if [[ $port == "" ]]; then
    echo -e "Please enter a port"
    cancel
fi

if [[ $filename == "" ]]; then
    echo -e "Please enter a filename"
    cancel
fi

if [[ $ssl == true ]]; then
    if [[ $domain == "" ]]; then
        echo -e "Please enter a domain"
        cancel
    fi
fi

if [[ $email == "" ]]; then
    echo -e "Please enter an email"
    cancel
fi

if [[ $ssl == false || $ssl == "" ]]; then
        echo -e "Please enter a valid argument for ssl"
        cancel
fi

ConfigureEverything() {
    ConfigurePackages
    ConfigureDocker
    ConfigureUser
    ConfigureFolderStructure
    ConfigurePM2
    ConfigureErrorPage
    ConfigureGithubHook
    ConfigureNGINX
    ConfigureGitClone
    ConfigureFail2Ban
    ConfigureSSL
    ConfigureScriptOnLogin
    ConfigureServer
}

ConfigureEverything

unset LC_ALL

echo -e
echo -e 'Finished setup script. Enjoy!'
exit 0