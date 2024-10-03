#!/bin/bash

echo -e '# ## ## ## ## ## ## ## ## ## ## ## ## #'
echo -e '#           VPS Setup Script          #'
echo -e '# ## ## ## ## ## ## ## ## ## ## ## ## #'

echo -e
date

# override locale to eliminate parsing errors (i.e. using commas a delimiters rather than periods)
export LC_ALL=C

cancel() {
  echo -e
  echo -e " Aborted..."
  exit
}

init() {
  # check release
  if [ -f /etc/redhat-release ]; then
      RELEASE="centos"
  elif cat /etc/issue | grep -Eqi "debian"; then
      RELEASE="debian"
  elif cat /etc/issue | grep -Eqi "ubuntu"; then
      RELEASE="ubuntu"
  elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
      RELEASE="centos"
  elif cat /proc/version | grep -Eqi "debian"; then
      RELEASE="debian"
  elif cat /proc/version | grep -Eqi "ubuntu"; then
      RELEASE="ubuntu"
  elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
      RELEASE="centos"
  fi
}

createAndGitClone () {
    webhookConfig=https://github.com/Ashlayyy/WebhookConfig.git
    read < /dev/tty -p "Enter your username of the user that needs to be in control of the site. Enter root if you didn't add a user during setup: " NAME
    read < /dev/tty -p 'What is the github url? It needs to be a public repository: ' GITHUB_URL
    read < /dev/tty -p 'Is there a additional folder?: [Name of folder] ' OPTIONAL

    if [[ "$NAME" = 'root' ]]; then
        echo "Removing /sites/$DOMAIN_NAME"
        rm -rf /sites/$DOMAIN_NAME
        echo "Creating /sites/$DOMAIN_NAME/"
        mkdir -p "/sites/$DOMAIN_NAME/"
        echo "Move into /sites/$DOMAIN_NAME/"
        cd /sites/$DOMAIN_NAME/
        echo "Creating /sites/$DOMAIN_NAME/scripts"
        mkdir scripts/
        cd /sites/$DOMAIN_NAME/
        echo "Creating /sites/$DOMAIN_NAME/site"
        mkdir site/
        cd /sites/$DOMAIN_NAME/
        echo "Creating /sites/$DOMAIN_NAME/config"
        mkdir config/
        cd /sites/$DOMAIN_NAME/
        echo "Move into /sites/$DOMAIN_NAME/config"
        cd config/
        echo "Removing /sites/$DOMAIN_NAME/config/webhook"
        rm -rf webhook/
        echo "Creating /sites/$DOMAIN_NAME/config/webhook/hooks.json"
        git clone $webhookConfig webhook/
        cd /sites/$DOMAIN_NAME/
        rm -rf scripts/webhookScript.sh
        cd /sites/$DOMAIN_NAME/

        echo "Optional: $OPTIONAL"
        echo "Hello!"

        cat << EOF > "scripts/webhookScript.sh"
        cd "/sites/$DOMAIN_NAME/site/$OPTIONAL"
        git pull origin main
        npm install
        pm2 reload all
EOF
        chmod +x scripts/webhookScript.sh
        cd /sites/$DOMAIN_NAME/
        git clone $GITHUB_URL site/
        cd /sites/$DOMAIN_NAME/site/$OPTIONAL
        npm install
        if [ -f "index.js" ]; then
        SETTING="TRUE"
            pm2 start index.js --watch --ignore-watch="node_modules" --time --name "ashlay"
        fi
        if [ -f "server.js" ]; then
            pm2 start server.js --watch --ignore-watch="node_modules" --time --name "ashlay"
        fi


        if [[ "$GITHUB_HOOK" =~ ^([yY][eE][sS]|[yY])$ ]]; then
          WEBHOOK_ID=''
          WEBHOOK_SECRET=''

          read < /dev/tty -p 'What is the id for the webhook?: ' WEBHOOK_ID
          read < /dev/tty -p 'What is the secrect for the webhook?: ' WEBHOOK_SECRET
          sed -i "/\"id\": \"--id--\",/c\"id\": \"$WEBHOOK_ID\"," /sites/$DOMAIN_NAME/config/webhook/hooks.json
          sed -i "/\"execute-command\": \"--scriptUrl--\",/c\"execute-command\": \"/sites/$DOMAIN_NAME/scripts/webhookScript.sh\"," /sites/$DOMAIN_NAME/config/webhook/hooks.json
          sed -i "/\"command-working-directory\": \"--directive--\",/c\"command-working-directory\": \"/sites/$DOMAIN_NAME/site\"," /sites/$DOMAIN_NAME/config/webhook/hooks.json
          sed -i "/\"secret\": \"--secret--\",/c\"secret\": \"$WEBHOOK_SECRET\"," /sites/$DOMAIN_NAME/config/webhook/hooks.json
          if [[ $OPTIONAL = '01-Werkbestanden' ]]; then
            sed -i "/\"command-working-directory\": \"/sites/$DOMAIN_NAME/site\",/c\"command-working-directory\": \"/sites/$DOMAIN_NAME/site/01-Werkbestanden\"," /sites/$DOMAIN_NAME/config/webhook/hooks.json
          fi
          sed -i "/include /etc/nginx/sites-enabled/\*\;",/c"#include /etc/nginx/sites-enabled/*\;" /etc/nginx/nginx.conf
        fi
    fi
}
createConfig () {
    fileLocation="/etc/nginx/conf.d/$DOMAIN_NAME.conf"
    rm -rf "/etc/nginx/sites-enabled/default"
    touch $fileLocation
    cat << EOF > "/etc/nginx/conf.d/$DOMAIN_NAME.conf"
    server {
        listen 80;
        server_name $DOMAIN_NAME www.$DOMAIN_NAME;
        return 301 https:/$DOMAIN_NAME/\$request_uri;
    }

    server {
        listen 443;
        server_name $DOMAIN_NAME www.$DOMAIN_NAME;
        access_log /var/log/nginx/$DOMAIN_NAME.access.log;
        $CUSTOMPAGELOCATION
        $GITHUBHOOKLOCATION
        location / {
          proxy_set_header        Host \$host:\$server_port;
          proxy_set_header        X-Real-IP \$remote_addr;
          proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
          proxy_set_header        X-Forwarded-Proto \$scheme;
          proxy_pass              http://localhost:$PORT_NUMBER;
          proxy_read_timeout      90;
          add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
          add_header X-Frame-Options DENY;
          add_header X-Content-Type-Options nosniff;
          add_header X-XSS-Protection "1; mode=block";
          add_header Referrer-Policy "origin";
          rewrite ^([^.]*[^/])$ \$1/ permanent;
        }
        $LOCATIONS
    }
EOF
}

trap cancel SIGINT

while getopts 'ah' flag; do
  case "${flag}" in
  a) AUTO="True" ;;
  h) HELP="True" ;;
  *) exit 1 ;;
  esac
done

if [[ -n $HELP ]]; then
  echo -e
  echo -e "Usage: ./setup.sh [-mh]"
  echo -e "       curl -sL json.id/setup.sh | sudo bash"
  echo -e "       curl -sL json.id/setup.sh | sudo bash -s --{ah}"
  echo -e
  echo -e "Flags:"
  echo -e "       -a : run setup script automatically"
  echo -e "       -h : prints this lovely message, then exits"
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root"
  exit 1
fi

init

echo -e 'Updating system...'
if [[ "$RELEASE" == "centos" ]]; then
  yum -y -q update
else
  apt-get update -y -qq && apt-get upgrade -y -qq
fi

echo -e
DISABLE_ROOT="N"
DISABLE_PASSWORD_AUTH="N"
INSTALL_BASIC_PACKAGES="Y"
INSTALL_DOCKER="Y"
INSTALL_DOCKER_COMPOSE="Y"
TIMEZONE="Central European Summer Time"
USERNAME="$(echo $SUDO_USER)"
NGINX="Y"
ADD_NEW_USER="Y"
INSTALL_ZSH="Y"
USEGITHUBFORFILES="Y"
if [ -z "$AUTO" ]; then
    read < /dev/tty -p 'Install basic packages? [y/N]: ' INSTALL_BASIC_PACKAGES
    read < /dev/tty -p 'Add Sudo User? [y/N]: ' ADD_NEW_USER
    read < /dev/tty -p 'Disable Root Login? [y/N]: ' DISABLE_ROOT
    read < /dev/tty -p 'Disable Password Authentication? [y/N]: ' DISABLE_PASSWORD_AUTH
    read < /dev/tty -p 'Install zsh and oh-my-zsh? [y/N]: ' INSTALL_ZSH
    read < /dev/tty -p 'Install Docker? [y/N]: ' INSTALL_DOCKER
    read < /dev/tty -p 'Install Docker Compose? [y/N]: ' INSTALL_DOCKER_COMPOSE
    read < /dev/tty -p 'Configure NGINX? [y/N]: ' NGINX
    read < /dev/tty -p 'Pull your repository from Github? [y/N]: ' USEGITHUBFORFILES
    read < /dev/tty -p 'Enter your TIMEZONE [Empty to skip]: ' TIMEZONE
    read < /dev/tty -p 'Enter any other packages to be installed [Empty to skip]: ' packages
fi

if [[ "$INSTALL_BASIC_PACKAGES" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  # Install basic packages
  echo -e
  echo -e 'Installing Basic Packages...'
  if [[ "$RELEASE" == "centos" ]]; then
    yum -y -q install sudo ufw fail2ban htop curl nginx tmux git python3-certbot-dns-cloudflare autojump
  else
    apt-get update
    apt-get install -y ca-certificates curl gnupg
    mkdir -p /etc/apt/keyrings
    rm -rf /etc/apt/keyrings/nodesource.gpg
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
    NODE_MAJOR=20
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list 
    apt-get update
    apt-get install nodejs -y -qq
    apt-get -y -qq install sudo ufw fail2ban htop curl nginx tmux git certbot autojump webhook
    npm install pm2 -g && pm2 update
    apt-get update
  fi
fi

if [[ "$ADD_NEW_USER" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo -e
  echo -e 'Setting sudo user...'
  read < /dev/tty -rp 'Username: ' USERNAME
  echo -n 'Password: '
  read < /dev/tty -rs password
  if [[ "$RELEASE" == "centos" ]]; then
    adduser $USERNAME
    usermod -aG wheel $USERNAME
  else
    adduser --disabled-password --gecos "" $USERNAME
    usermod -aG sudo $USERNAME
  fi
  echo "$USERNAME:$password" | sudo chpasswd

  echo -e
  echo -e 'Adding SSH Keys'
  while true; do
    read < /dev/tty -rp 'Enter SSH Key [Empty to skip]: ' sshKey
    if [[ -z "$sshKey" ]]; then
      break
    fi
    if [[ ! -d '/home/$USERNAME/.ssh' ]]; then
      mkdir -p /home/$USERNAME/.ssh
    fi
    touch /home/$USERNAME/.ssh/authorized_keys
    echo -e "$sshKey" >>/home/$USERNAME/.ssh/authorized_keys
    echo -e 'Saved SSH Key\n'
  done
fi

if [[ "$DISABLE_ROOT" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo -e
  echo -e 'Disabling Root Login...'
  sed -i '/PermitRootLogin yes/c\PermitRootLogin no' /etc/ssh/sshd_config
fi
if [[ "$DISABLE_PASSWORD_AUTH" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo -e
  echo -e 'Disabling Password Authentication...'
  sed -i '/PasswordAuthentication yes/c\PasswordAuthentication no' /etc/ssh/sshd_config
fi
systemctl restart sshd

if [[ -n $TIMEZONE ]]; then
  echo -e
  echo -e 'Setting Timezone...'
  timedatectl set-timezone $TIMEZONE
fi

if [[ "$INSTALL_ZSH" =~ ^([yY][eE][sS]|[yY])$  ]]; then
  echo -e
  if [[ -z "$(command -v zsh)" ]]; then
    echo -e 'Installing zsh and ohmyzsh...'
    if [[ "$RELEASE" == "centos" ]]; then
      yum -y -q install zsh git
    else
      apt-get -y -qq install zsh git
    fi
    sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
  fi
fi

# Install Docker
if [[ "$INSTALL_DOCKER" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo -e
  if [[ -z "$(command -v docker)" ]]; then
    curl -fsSL https://get.docker.com | bash
  fi
  usermod -aG docker $USERNAME
  echo -e "Docker Installed. Added $USERNAME to docker group"
fi
if [[ "$INSTALL_DOCKER_COMPOSE" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo -e
  if [[ -z "$(command -v docker-compose)" ]]; then
    curl -L "https://github.com/docker/compose/releases/download/1.25.5/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
  fi
  echo -e "Docker Compose Installed."
fi

if [[ -n $packages ]]; then
  echo -e
  echo -e "Installing $packages ..."
  if [[ "$RELEASE" == "centos" ]]; then
    yum -y -q install $packages
  else
    apt-get -y -qq install $packages
  fi
fi

DOMAIN_NAME='';
CUSTOMPAGELOCATION='';
GITHUBHOOKLOCATION='';

if [[ "$NGINX" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo -e
    echo -e "Setting up NGINX..."
    read < /dev/tty -p 'Domain Name? Just the root domain, we will ad the www prefix to it: ' DOMAIN_NAME
    read < /dev/tty -p 'Port Number the service runs on?: ' PORT_NUMBER
    read < /dev/tty -p 'Do you want a custom error page? [y/N]: ' CUSTOM_PAGE
    read < /dev/tty -p 'Do you want a Github Hook for Webhook to use? [y/N]: ' GITHUB_HOOK 
    read < /dev/tty -p "Do you want to configure projects locations? [y/N]: " MAKELOCATIONS 
    read < /dev/tty -p "Do you want to configure Let's encrypt? [y/N]: " LETS_ENCRYPT 

    if [[ "$CUSTOM_PAGE" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        standaardLocation='/var/www/html'
        echo -e
        echo -e "Setting up Custom error page..."
        echo -e "The custom error page wil get used. The location is at ${standaardLocation}, place a file called 502.html there to activate it"
        CUSTOMPAGELOCATION="
            error_page 502 /502.html;

            location = /502.html {
                root /var/www/html;
                internal;
            }
        "
    fi

    if [[ "$GITHUB_HOOK" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e
        echo -e "Setting up Github Hook..."
        GITHUBHOOKLOCATION="
            location /hooks/ {
                proxy_pass http://127.0.0.1:9000/hooks/;
            }
        "
    fi
    if [[ "$MAKELOCATIONS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e
        echo -e "Setting up Project Locations..."
        read < /dev/tty -p "Which port will the Projects handling unit be on?: " PORT_PROJECTS 
        LOCATIONS="
            location /project/:id/ {
              proxy_set_header        Host \$host:\$server_port;
              proxy_set_header        X-Real-IP \$remote_addr;
              proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
              proxy_set_header        X-Forwarded-Proto \$scheme;
              proxy_pass              http://localhost:$PORT_PROJECTS;
              proxy_read_timeout      90;
              add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
              add_header X-Frame-Options DENY;
              add_header X-Content-Type-Options nosniff;
              add_header X-XSS-Protection "1; mode=block";
              add_header Referrer-Policy "origin";
              rewrite ^([^.]*[^/])$ \$1/ permanent;
            }
        "
    fi

    createConfig
    nginx -t
    nginx -s reload
fi

if [[ "$USEGITHUBFORFILES" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    createAndGitClone
fi

if [[ "$LETS_ENCRYPT" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo -e
    echo -e "Setting up Let's encrypt..."
    apt update -y
    apt install snapd -y
    apt-get remove certbot -y
    snap remore cerbot -y
    snap install --classic certbot
    ln -s /snap/bin/certbot /usr/bin/certbot
    certbot --nginx -d $DOMAIN_NAME -d www.$DOMAIN_NAME
fi

# reset locale settings
unset LC_ALL

echo -e
echo -e 'Finished setup script.'
exit 0