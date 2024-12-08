#!/bin/bash

export LC_ALL=C
set -e;

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ScriptPath="$SCRIPT_DIR/Config/script-on-login.sh"

# Add at the top after the initial variables
ERROR_LOG="/tmp/setup_errors.log"
WARN_LOG="/tmp/setup_warnings.log"

log_error() {
    local msg="$1"
    local fatal="${2:-false}"
    echo -e "[ERROR] $msg" | tee -a "$ERROR_LOG"
    if [[ "$fatal" == "true" ]]; then
        echo -e "Fatal error, cannot continue. Check $ERROR_LOG for details."
        exit 1
    fi
}

log_warning() {
    local msg="$1"
    echo -e "[WARNING] $msg" | tee -a "$WARN_LOG"
}

log_info() {
    local msg="$1"
    echo -e "[INFO] $msg"
}

cancel() {
    echo -e
    echo -e " Aborted..."
    exit
}

SendHelpMenu() {
    echo -e
    echo -e "Usage: sudo ./setup.sh config.json"
    echo -e
    echo -e "The config.json file should contain all necessary configuration."
    echo -e "See example.config.json for the expected format."
    echo -e
    exit 0
}

LoadConfig() {
    if [ -z "$1" ]; then
        log_error "Please provide a config file path" true
    fi

    if [ ! -f "$1" ]; then
        log_error "Config file not found: $1" true
    fi

    # Parse JSON config using jq
    if ! config=$(cat "$1" | jq .); then
        log_error "Failed to parse JSON config file" true
    fi
    
    # Load base configuration with fallbacks
    domain=$(echo "$config" | jq -r '.domain // empty')
    [[ -z "$domain" ]] && log_error "Domain is required in config" true
    
    email=$(echo "$config" | jq -r '.email // empty')
    [[ -z "$email" ]] && log_error "Email is required in config" true
    
    user=$(echo "$config" | jq -r '.user // empty')
    [[ -z "$user" ]] && log_error "User is required in config" true
    
    # Load ports with defaults if not specified
    SSH_Port=$(echo "$config" | jq -r '.ports.ssh // 22')
    NFTY_Port=$(echo "$config" | jq -r '.ports.ntfy // 2586')
    
    # Load repositories with fallback
    GithubURL_Config=$(echo "$config" | jq -r '.repositories.config // empty')
    if [ -z "$GithubURL_Config" ]; then
        log_warning "Config repository URL not specified, using default"
        GithubURL_Config="https://github.com/Ashlayyy/config.git"
    fi

    # Load features with defaults
    ssl=$(echo "$config" | jq -r '.features.ssl // false')
    nginx_enabled=$(echo "$config" | jq -r '.features.nginx // true')
    docker_enabled=$(echo "$config" | jq -r '.features.docker // false')
    fail2ban_enabled=$(echo "$config" | jq -r '.features.fail2ban // true')
    prometheus_enabled=$(echo "$config" | jq -r '.features.prometheus // false')
    grafana_enabled=$(echo "$config" | jq -r '.features.grafana // false')
    ntfy_enabled=$(echo "$config" | jq -r '.features.ntfy // true')
    pm2_enabled=$(echo "$config" | jq -r '.features.pm2 // true')
    github_webhooks_enabled=$(echo "$config" | jq -r '.features.githubWebhooks // true')
    server_hardening_enabled=$(echo "$config" | jq -r '.features.serverHardening // true')

    # Load SSH keys (optional)
    if ! ssh_keys=$(echo "$config" | jq -r '.sshKeys[]'); then
        log_warning "No SSH keys specified in config"
        ssh_keys=""
    fi

    # Load VPN IPs (optional)
    vpn_ip_primary=$(echo "$config" | jq -r '.vpnIps.primary // empty')
    vpn_ip_secondary=$(echo "$config" | jq -r '.vpnIps.secondary // empty')
    if [[ -z "$vpn_ip_primary" && -z "$vpn_ip_secondary" ]]; then
        log_warning "No VPN IPs specified, some features may be limited"
    fi
}

ConfigurePackages() {
    log_info "Installing packages..."
    
    # Define required packages
    local base_packages=(
        ca-certificates
        curl
        gnupg
        sudo
        ufw
        htop
        tmux
        git
        certbot
        autojump
        jq  # Add jq explicitly
    )

    # Check for required commands
    for cmd in curl wget jq; do
        if ! command -v $cmd &> /dev/null; then
            log_warning "$cmd not found, will be installed"
        fi
    done

    # Update package list with retry
    local max_retries=3
    local retry_count=0
    while ! apt update -y && ((retry_count < max_retries)); do
        log_warning "apt update failed, retrying..."
        sleep 5
        ((retry_count++))
    done

    if ((retry_count >= max_retries)); then
        log_error "Failed to update package list after $max_retries attempts" true
    fi

    # Install base packages
    for pkg in "${base_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$pkg"; then
            log_info "Installing $pkg..."
            if ! apt install -y "$pkg"; then
                log_error "Failed to install $pkg" true
            fi
        else
            log_info "$pkg is already installed"
        fi
    done

    # ... rest of package installation ...
}

ConfigureUser() {
    log_info "Configuring user: $user"

    # Check if user exists
    if ! id "$user" &>/dev/null; then
        log_info "Creating user: $user"
        if ! adduser --disabled-password --gecos "" "$user"; then
            log_error "Failed to create user" true
        fi

        # Add user to sudo group
        if ! usermod -aG sudo "$user"; then
            log_warning "Failed to add user to sudo group"
        fi

        # Set password with retry
        local max_retries=3
        local retry_count=0
        while ! yes "$USER_PASSWORD" | passwd "$user" && ((retry_count < max_retries)); do
            log_warning "Failed to set password, retrying..."
            sleep 2
            ((retry_count++))
        done
        if ((retry_count >= max_retries)); then
            log_error "Failed to set user password after $max_retries attempts" true
        fi
    else
        log_info "User $user already exists"
    fi

    # Setup SSH directory with proper permissions
    local ssh_dir="/home/$user/.ssh"
    if ! mkdir -p "$ssh_dir"; then
        log_warning "Failed to create SSH directory, trying alternative method"
        sudo -u "$user" mkdir -p "$ssh_dir" || log_error "Failed to create SSH directory" true
    fi

    local auth_keys="$ssh_dir/authorized_keys"
    touch "$auth_keys" || log_error "Failed to create authorized_keys file" true

    # Set proper permissions
    chmod 700 "$ssh_dir" || log_warning "Failed to set SSH directory permissions"
    chmod 600 "$auth_keys" || log_warning "Failed to set authorized_keys permissions"
    chown -R "$user:$user" "$ssh_dir" || log_warning "Failed to set SSH directory ownership"

    # Add SSH keys
    if [ ! -z "$ssh_keys" ]; then
        while IFS= read -r key; do
            if [ ! -z "$key" ]; then
                echo "$key" >> "$auth_keys" || log_warning "Failed to add SSH key: ${key:0:30}..."
                log_info "Added SSH key to authorized_keys"
            fi
        done <<< "$ssh_keys"
    else
        log_warning "No SSH keys to add"
    fi

    # Configure service users
    if [[ "$prometheus_enabled" == "true" ]]; then
        if ! getent group prometheus >/dev/null; then
            groupadd --system prometheus || log_warning "Failed to create prometheus group"
        fi
        if ! id prometheus &>/dev/null; then
            useradd -s /sbin/nologin --system -g prometheus prometheus || log_warning "Failed to create prometheus user"
        fi
        htpasswd -b -c /etc/nginx/.prometheus.htpasswd "$PROMETHEUS_USERNAME" "$PROMETHEUS_PASSWORD" || log_warning "Failed to set prometheus password"
    fi

    if [[ "$grafana_enabled" == "true" ]]; then
        htpasswd -b -c /etc/nginx/.grafana.htpasswd "$GRAFANA_USERNAME" "$GRAFANA_PASSWORD" || log_warning "Failed to set grafana password"
    fi

    log_info "User configuration completed"
}

ConfigureDocker() {
    if [[ "$docker_enabled" != "true" ]]; then
        log_info "Docker installation skipped (disabled in config)"
        return
    fi

    log_info "Configuring Docker..."

    # Check if Docker is already installed
    if command -v docker &>/dev/null; then
        log_info "Docker is already installed"
    else
        log_info "Installing Docker..."
        
        # Try to install Docker with retry mechanism
        local max_retries=3
        local retry_count=0
        while ! curl -fsSL https://get.docker.com | bash && ((retry_count < max_retries)); do
            log_warning "Docker installation failed, retrying..."
            sleep 5
            ((retry_count++))
        done

        if ! command -v docker &>/dev/null; then
            log_error "Failed to install Docker after $max_retries attempts" true
        fi
        
        log_info "Docker installed successfully"
    fi

    # Add user to docker group
    if ! getent group docker >/dev/null; then
        log_warning "Docker group doesn't exist, creating..."
        groupadd docker || log_warning "Failed to create docker group"
    fi

    if ! usermod -aG docker "$user"; then
        log_warning "Failed to add user to docker group. User may need to be added manually"
    fi

    # Install Docker Compose if not present
    if ! command -v docker-compose &>/dev/null; then
        log_info "Installing Docker Compose..."
        
        local compose_url="https://github.com/docker/compose/releases/download/1.25.5/docker-compose-$(uname -s)-$(uname -m)"
        local max_retries=3
        local retry_count=0
        
        while ! curl -L "$compose_url" -o /usr/local/bin/docker-compose && ((retry_count < max_retries)); do
            log_warning "Docker Compose download failed, retrying..."
            sleep 5
            ((retry_count++))
        done

        if [ ! -f /usr/local/bin/docker-compose ]; then
            log_error "Failed to download Docker Compose" true
        fi

        chmod +x /usr/local/bin/docker-compose || log_error "Failed to make Docker Compose executable" true
        log_info "Docker Compose installed successfully"
    else
        log_info "Docker Compose is already installed"
    fi

    # Start and enable Docker service
    if ! systemctl is-active --quiet docker; then
        log_info "Starting Docker service..."
        systemctl start docker || log_warning "Failed to start Docker service"
    fi

    if ! systemctl is-enabled --quiet docker; then
        log_info "Enabling Docker service..."
        systemctl enable docker || log_warning "Failed to enable Docker service"
    fi

    # Verify Docker is working
    if ! docker info &>/dev/null; then
        log_warning "Docker service is not responding properly"
    else
        log_info "Docker is running and responding properly"
    fi

    log_info "Docker configuration completed"
}

ConfigureFolderStructure() {
    log_info "Setting up folder structure..."

    # Create main site directory
    local site_root="/sites/$domain"
    if ! mkdir -p "$site_root"; then
        log_error "Failed to create main site directory" true
    fi
    
    # Create standard subdirectories
    local directories=(
        "API"
        "Config/Webhooks"
        "Projects"
        "Scripts/OnLogin"
        "Site"
        "Temp"
    )

    for dir in "${directories[@]}"; do
        if ! mkdir -p "$site_root/$dir"; then
            log_warning "Failed to create directory: $site_root/$dir, trying alternative method"
            sudo -u "$user" mkdir -p "$site_root/$dir" || log_error "Failed to create directory: $site_root/$dir" true
        fi
        log_info "Created directory: $site_root/$dir"
    done

    # Create error pages if they don't exist
    local error_pages_dir="/var/www/html"
    if ! mkdir -p "$error_pages_dir"; then
        log_warning "Failed to create error pages directory"
    else
        # Create 404 page if it doesn't exist
        if [ ! -f "$error_pages_dir/404.html" ]; then
            touch "$error_pages_dir/404.html" || log_warning "Failed to create 404.html"
        fi

        # Create 502 page if it doesn't exist
        if [ ! -f "$error_pages_dir/502.html" ]; then
            touch "$error_pages_dir/502.html" || log_warning "Failed to create 502.html"
        fi
    fi

    # Set permissions with retry mechanism
    local max_retries=3
    local retry_count=0
    while ! chown -R "$user:$user" "$site_root" && ((retry_count < max_retries)); do
        log_warning "Failed to set ownership, retrying..."
        sleep 2
        ((retry_count++))
    done
    if ((retry_count >= max_retries)); then
        log_error "Failed to set proper ownership after $max_retries attempts" true
    fi

    # Set directory permissions
    if ! chmod -R 755 "$site_root"; then
        log_warning "Failed to set directory permissions"
    fi

    # Create project directories from config
    echo "$config" | jq -c '.projects[]' | while read -r project; do
        name=$(echo "$project" | jq -r '.name')
        optional_folder=$(echo "$project" | jq -r '.optionalFolder // empty')
        
        local project_path="$site_root/Site/$name"
        if [ ! -z "$optional_folder" ]; then
            project_path="$project_path/$optional_folder"
        fi

        if ! mkdir -p "$project_path"; then
            log_warning "Failed to create project directory: $project_path"
            continue
        fi
        log_info "Created project directory: $project_path"

        # Set project directory permissions
        chown -R "$user:$user" "$site_root/Site/$name" || log_warning "Failed to set ownership for project: $name"
        chmod -R 755 "$site_root/Site/$name" || log_warning "Failed to set permissions for project: $name"
    done

    # Verify structure
    if ! ls -la "$site_root/"; then
        log_warning "Unable to verify folder structure"
    else
        log_info "Folder structure verified"
    fi

    log_info "Folder structure setup completed"
}

ConfigurePM2() {
    if [[ "$pm2_enabled" != "true" ]]; then
        log_info "PM2 setup skipped (disabled in config)"
        return
    fi

    log_info "Configuring PM2..."

    # Kill existing PM2 if running
    if pm2 ping >/dev/null 2>&1; then
        log_info "Stopping existing PM2 instance"
        pm2 kill || log_warning "Failed to kill existing PM2 instance"
    fi

    # Install PM2 globally with retry mechanism
    local max_retries=3
    local retry_count=0
    while ! npm install pm2 -g && ((retry_count < max_retries)); do
        log_warning "PM2 installation failed, retrying..."
        sleep 5
        ((retry_count++))
    done

    if ! command -v pm2 &>/dev/null; then
        log_error "Failed to install PM2 after $max_retries attempts" true
    fi
    log_info "PM2 installed globally"

    # Setup PM2 startup
    log_info "Setting up PM2 startup script"
    if ! pm2 startup -u "$user"; then
        log_warning "Failed to setup PM2 startup script, trying alternative method"
        if ! sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u "$user" --hp "/home/$user"; then
            log_error "Failed to setup PM2 startup script" true
        fi
    fi

    # Start all projects
    echo "$config" | jq -c '.projects[]' | while read -r project; do
        name=$(echo "$project" | jq -r '.name')
        filename=$(echo "$project" | jq -r '.filename')
        optional_folder=$(echo "$project" | jq -r '.optionalFolder // empty')
        
        project_path="/sites/$domain/Site/$name"
        if [ ! -z "$optional_folder" ]; then
            project_path="$project_path/$optional_folder"
        fi

        log_info "Starting PM2 for project: $name"
        
        # Check if directory exists
        if [ ! -d "$project_path" ]; then
            log_warning "Project directory not found: $project_path"
            continue
        fi

        # Navigate to project directory
        if ! cd "$project_path"; then
            log_warning "Failed to access project directory: $project_path"
            continue
        fi

        # Check if file exists
        if [ ! -f "$filename" ]; then
            log_warning "Project file not found: $filename in $project_path"
            continue
        fi

        # Start project with PM2
        if ! pm2 start "$filename" --watch --ignore-watch="node_modules" --time --name "$name"; then
            log_warning "Failed to start PM2 for project: $name"
            # Try to restart if it exists
            pm2 restart "$name" || log_warning "Failed to restart PM2 for project: $name"
        fi
    done

    # Save PM2 configuration
    log_info "Saving PM2 configuration"
    if ! pm2 save; then
        log_warning "Failed to save PM2 configuration"
    fi

    # Start PM2 service
    log_info "Starting PM2 service"
    if ! systemctl start "pm2-$user"; then
        log_warning "Failed to start PM2 service, it may need to be started manually"
    fi

    # Verify PM2 is running
    if ! pm2 list; then
        log_warning "Unable to verify PM2 processes"
    else
        log_info "PM2 processes verified"
    fi

    log_info "PM2 configuration completed"
}

ConfigureErrorPage() {
    if [[ "$nginx_enabled" != "true" ]]; then
        log_info "Error page setup skipped (nginx disabled in config)"
        return
    fi

    log_info "Configuring error pages..."

    # Create error pages directory if it doesn't exist
    local error_dir="/var/www/html"
    if ! mkdir -p "$error_dir"; then
        log_warning "Failed to create error pages directory, trying alternative method"
        sudo mkdir -p "$error_dir" || log_error "Failed to create error pages directory" true
    fi

    # Function to create error page with content
    create_error_page() {
        local code="$1"
        local title="$2"
        local message="$3"
        local file="$error_dir/${code}.html"

        cat <<EOF > "$file"
<!DOCTYPE html>
<html>
<head>
    <title>${code} - ${title}</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            text-align: center; 
            padding-top: 50px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { color: #444; margin-bottom: 20px; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>${code} - ${title}</h1>
        <p>${message}</p>
    </div>
</body>
</html>
EOF

        # Set proper permissions
        if ! chmod 644 "$file"; then
            log_warning "Failed to set permissions for $file"
        fi
        if ! chown www-data:www-data "$file"; then
            log_warning "Failed to set ownership for $file"
        fi

        log_info "Created error page: $file"
    }

    # Create error pages
    create_error_page "404" "Not Found" "The requested page could not be found."
    create_error_page "502" "Bad Gateway" "The server encountered a temporary error and could not complete your request."

    # Create NGINX error page configuration
    error_page_config="
    error_page 404 /404.html;
    location = /404.html {
        root /var/www/html;
        internal;
    }

    error_page 502 /502.html;
    location = /502.html {
        root /var/www/html;
        internal;
    }
    "

    # Verify error pages exist
    local missing_pages=0
    for code in 404 502; do
        if [ ! -f "$error_dir/${code}.html" ]; then
            log_warning "Error page ${code}.html is missing"
            ((missing_pages++))
        fi
    done

    if ((missing_pages > 0)); then
        log_warning "Some error pages are missing, NGINX might use default pages"
    else
        log_info "All error pages verified"
    fi

    log_info "Error pages configuration completed"
}

ConfigureGithubHook() {
    if [[ "$github_webhooks_enabled" != "true" ]]; then
        log_info "Github webhooks setup skipped (disabled in config)"
        return
    fi

    log_info "Configuring Github Webhooks..."

    # Clone webhook config repository with retry
    local max_retries=3
    local retry_count=0
    while ! git clone "$GithubURL_Config" "/sites/$domain/Temp/config/" && ((retry_count < max_retries)); do
        log_warning "Failed to clone config repository, retrying..."
        rm -rf "/sites/$domain/Temp/config/"
        sleep 5
        ((retry_count++))
    done

    if [ ! -d "/sites/$domain/Temp/config/" ]; then
        log_error "Failed to clone webhook config repository" true
    fi

    # Move webhook configuration
    if ! mv "/sites/$domain/Temp/config/hooks.json" "/sites/$domain/Config/Webhooks/hooks.json"; then
        log_error "Failed to move webhook configuration" true
    fi
    rm -rf "/sites/$domain/Temp/"

    # Process each project's webhook
    echo "$config" | jq -c '.projects[]' | while read -r project; do
        name=$(echo "$project" | jq -r '.name')
        hook=$(echo "$project" | jq -r '.githubHook')
        github_branch=$(echo "$project" | jq -r '.githubBranch')
        optional_folder=$(echo "$project" | jq -r '.optionalFolder // empty')

        # Validate webhook configuration
        if [ -z "$hook" ] || [ "$hook" = "null" ]; then
            log_warning "No webhook configuration for project: $name"
            continue
        fi

        # Extract webhook credentials
        hook_id=$(echo "$hook" | cut -f1 -d '=' || echo "")
        hook_secret=$(echo "$hook" | cut -f2 -d '=' || echo "")

        if [ -z "$hook_id" ] || [ -z "$hook_secret" ]; then
            log_warning "Invalid webhook format for project: $name"
            continue
        fi

        log_info "Setting up webhook for project: $name"

        # Create webhook script
        webhook_script="/sites/$domain/Scripts/webhook_$name.sh"
        if ! cat <<EOF > "$webhook_script"; then
            log_warning "Failed to create webhook script for: $name"
            continue
        fi
#!/bin/bash
cd "/sites/$domain/Site/$name${optional_folder:+/$optional_folder}"
git pull origin $github_branch
npm install
pm2 reload $name
EOF

        chmod +x "$webhook_script" || log_warning "Failed to make webhook script executable: $name"

        # Update webhook configuration
        hooks_json="/sites/$domain/Config/Webhooks/hooks.json"
        cp "$hooks_json" "${hooks_json}.bak" || log_warning "Failed to backup hooks.json"
        
        # Add new webhook configuration
        if ! jq --arg id "$hook_id" \
           --arg cmd "$webhook_script" \
           --arg secret "$hook_secret" \
           --arg name "$name" \
        '.[] |= if .id == "--id--" then
            {
                "id": $id,
                "execute-command": $cmd,
                "command-working-directory": "/",
                "response-message": "Webhook received for \($name)",
                "trigger-rule": {
                    "and": [
                        {
                            "match": {
                                "type": "payload-hmac-sha1",
                                "secret": $secret,
                                "parameter": {
                                    "source": "header",
                                    "name": "X-Hub-Signature"
                                }
                            }
                        }
                    ]
                }
            }
        else . end' "$hooks_json" > "${hooks_json}.tmp"; then
            log_warning "Failed to update webhook configuration for: $name"
            continue
        fi

        mv "${hooks_json}.tmp" "$hooks_json" || log_warning "Failed to save webhook configuration for: $name"
        log_info "Webhook configured for project: $name"
    done

    # Start webhook service with retry
    local retry_count=0
    while ! webhook -hooks "/sites/$domain/Config/Webhooks/hooks.json" -verbose & && ((retry_count < max_retries)); do
        log_warning "Failed to start webhook service, retrying..."
        sleep 5
        ((retry_count++))
    done

    if ! pgrep webhook >/dev/null; then
        log_warning "Webhook service may not be running properly"
    else
        log_info "Webhook service started successfully"
    fi

    log_info "Github Webhooks configuration completed"
}

ConfigureNGINX() {
    if [[ "$nginx_enabled" != "true" ]]; then
        log_info "NGINX setup skipped (disabled in config)"
        return
    fi

    log_info "Configuring NGINX..."

    # Remove default config if it exists
    rm -f "/etc/nginx/sites-enabled/default"

    # Create config file
    local config_file="/etc/nginx/conf.d/$domain.conf"
    if ! touch "$config_file"; then
        log_error "Failed to create NGINX configuration file" true
    fi

    # Create IP access control string if VPN IPs are provided
    local ip_access_control=""
    local ip_access_control_list=""
    
    if [[ -n "$vpn_ip_primary" ]]; then
        ip_access_control_list+="allow $vpn_ip_primary;"$'\n'
        log_info "Added primary VPN IP to access control"
    fi
    if [[ -n "$vpn_ip_secondary" ]]; then
        ip_access_control_list+="allow $vpn_ip_secondary;"$'\n'
        log_info "Added secondary VPN IP to access control"
    fi
    
    # Add proper indentation
    if [[ -n "$ip_access_control_list" ]]; then
        while IFS= read -r line; do
            ip_access_control+="          $line"
        done <<< "$ip_access_control_list"
    else
        log_warning "No VPN IPs configured for access control"
    fi

    # Generate location blocks for each project
    local project_locations=""
    echo "$config" | jq -c '.projects[]' | while read -r project; do
        name=$(echo "$project" | jq -r '.name')
        port=$(echo "$project" | jq -r '.port')
        
        if [ -z "$port" ] || [ "$port" = "null" ]; then
            log_warning "No port specified for project: $name, skipping"
            continue
        fi

        project_locations+="
        location /$name/ {
            proxy_set_header        Host \$host:\$server_port;
            proxy_set_header        X-Real-IP \$remote_addr;
            proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header        X-Forwarded-Proto \$scheme;
            proxy_cache            main_cache;
            proxy_cache_valid      200 302 30m;
            proxy_cache_valid      404 1m;
            proxy_pass             http://localhost:$port/;
            proxy_read_timeout     90;
            add_header            Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\";
            add_header            X-Frame-Options DENY;
            add_header            X-Content-Type-Options nosniff;
            add_header            X-XSS-Protection \"1; mode=block\";
            add_header            Referrer-Policy \"origin\";
            rewrite              ^([^.]*[^/])$ \$1/ permanent;
        }"
        log_info "Added NGINX configuration for project: $name"
    done

    # Write NGINX configuration with error handling
    if ! cat <<EOF > "$config_file"; then
        log_error "Failed to write NGINX configuration" true
    fi
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        return 301 https://\$host\$request_uri;
    }

    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=main_cache:10m max_size=1g inactive=360m use_temp_path=off;

    server {
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
        server_name $domain www.$domain;
        access_log /var/log/nginx/$domain.access.log;

        $error_page_config

        location /hooks/ {
            proxy_pass http://localhost:9000/hooks/;
        }

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

        $project_locations

        location /$RANDOMSTRING_PROMETHEUS/prometheus/$RANDOMSTRING_PROMETHEUS/ {
            satisfy all;
            allow 127.0.0.1;
            ${ip_access_control}          
            deny all;
            auth_basic                "Prometheus";
            auth_basic_user_file      /etc/nginx/.prometheus.htpasswd;
            proxy_pass                http://localhost:9090/;
            proxy_read_timeout        90;
        }

        location /$RANDOMSTRING_GRAFANA/grafana/$RANDOMSTRING_GRAFANA/ {
            satisfy all;
            allow 127.0.0.1;
            ${ip_access_control}          
            deny all;
            auth_basic                "Grafana";
            auth_basic_user_file      /etc/nginx/.grafana.htpasswd;
            proxy_pass                http://localhost:3000/;
            proxy_read_timeout        90;
        }
    }
EOF

    # Test NGINX configuration
    if ! nginx -t; then
        log_error "NGINX configuration test failed" true
    fi
    log_info "NGINX configuration test passed"

    # Reload NGINX with retry mechanism
    local max_retries=3
    local retry_count=0
    while ! systemctl reload nginx && ((retry_count < max_retries)); do
        log_warning "Failed to reload NGINX, retrying..."
        sleep 5
        ((retry_count++))
    done

    if ! systemctl is-active --quiet nginx; then
        log_error "NGINX failed to reload after $max_retries attempts" true
    fi

    log_info "NGINX configuration completed"
}

ConfigureGitClone() {
    log_info "Setting up Git repositories..."

    # Process each project
    echo "$config" | jq -c '.projects[]' | while read -r project; do
        name=$(echo "$project" | jq -r '.name')
        github_url=$(echo "$project" | jq -r '.githubUrl')
        github_branch=$(echo "$project" | jq -r '.githubBranch')
        optional_folder=$(echo "$project" | jq -r '.optionalFolder // empty')
        
        # Validate project configuration
        if [ -z "$github_url" ] || [ "$github_url" = "null" ]; then
            log_warning "No GitHub URL specified for project: $name"
            continue
        fi
        if [ -z "$github_branch" ] || [ "$github_branch" = "null" ]; then
            log_warning "No branch specified for project: $name"
            continue
        fi

        project_path="/sites/$domain/Site/$name"
        log_info "Cloning repository for project: $name"

        # Remove existing directory if it exists
        if [ -d "$project_path" ]; then
            log_info "Removing existing project directory: $project_path"
            rm -rf "$project_path" || log_warning "Failed to remove existing directory"
        fi
        
        # Clone with retry mechanism
        local max_retries=3
        local retry_count=0
        while ! git clone "$github_url" "$project_path" && ((retry_count < max_retries)); do
            log_warning "Failed to clone repository for project: $name, retrying..."
            rm -rf "$project_path"
            sleep 5
            ((retry_count++))
        done

        if [ ! -d "$project_path" ]; then
            log_warning "Failed to clone repository for project: $name after $max_retries attempts"
            continue
        fi

        # Configure git
        cd "$project_path" || {
            log_warning "Failed to access project directory: $project_path"
            continue
        }

        # Set git safe directory
        git config --global --add safe.directory "$project_path" || log_warning "Failed to set safe directory for: $name"
        
        # Checkout specific branch
        log_info "Checking out branch: $github_branch for project: $name"
        if ! git checkout "$github_branch"; then
            log_warning "Failed to checkout branch: $github_branch for project: $name"
            continue
        fi

        if ! git pull origin "$github_branch"; then
            log_warning "Failed to pull latest changes for project: $name"
        fi

        # Navigate to optional folder if specified
        if [ ! -z "$optional_folder" ]; then
            if ! cd "$optional_folder"; then
                log_warning "Failed to access optional folder: $optional_folder for project: $name"
                continue
            fi
        fi

        # Install dependencies if package.json exists
        if [ -f "package.json" ]; then
            log_info "Installing npm dependencies for project: $name"
            local max_retries=3
            local retry_count=0
            while ! npm install && ((retry_count < max_retries)); do
                log_warning "Failed to install dependencies for project: $name, retrying..."
                sleep 5
                ((retry_count++))
            done

            if ((retry_count >= max_retries)); then
                log_warning "Failed to install dependencies for project: $name after $max_retries attempts"
            fi
        else
            log_warning "No package.json found for project: $name"
        fi

        log_info "Repository setup completed for project: $name"
    done

    log_info "Git repositories setup completed"
}

ConfigureFail2Ban() {
    if [[ "$fail2ban_enabled" != "true" ]]; then
        log_info "Fail2ban setup skipped (disabled in config)"
        return
    fi

    log_info "Configuring Fail2ban..."

    # Install required packages if not already installed
    if ! dpkg -l | grep -q fail2ban; then
        log_info "Installing fail2ban and dependencies"
        apt-get install fail2ban python3-systemd -y || log_error "Failed to install fail2ban" true
    fi

    # Create fail2ban config directory if it doesn't exist
    mkdir -p /etc/fail2ban || log_error "Failed to create fail2ban directory" true

    # Copy fail2ban configuration from template with retry
    local max_retries=3
    local retry_count=0
    while ! cp "$SCRIPT_DIR/Config/fail2ban.txt" "/etc/fail2ban/jail.local" && ((retry_count < max_retries)); do
        log_warning "Failed to copy fail2ban configuration, retrying..."
        sleep 2
        ((retry_count++))
    done

    if [ ! -f "/etc/fail2ban/jail.local" ]; then
        log_error "Failed to create fail2ban configuration" true
    fi

    # Update SSH port in fail2ban config
    if ! sed -i "s/port = 1087, 22/port = $SSH_Port, 22/" "/etc/fail2ban/jail.local"; then
        log_warning "Failed to update SSH port in fail2ban configuration"
    fi

    # Ensure proper permissions
    chmod 644 /etc/fail2ban/jail.local || log_warning "Failed to set fail2ban config permissions"

    # Start and enable fail2ban service with retry
    systemctl enable fail2ban || log_warning "Failed to enable fail2ban service"
    
    local retry_count=0
    while ! systemctl restart fail2ban && ((retry_count < max_retries)); do
        log_warning "Failed to start fail2ban service, retrying..."
        sleep 5
        ((retry_count++))
    done

    # Verify service status
    if systemctl is-active --quiet fail2ban; then
        log_info "Fail2ban service is running"
        systemctl status fail2ban.service
    else
        log_warning "Fail2ban service failed to start"
        systemctl status fail2ban.service
    fi

    log_info "Fail2ban configuration completed"
}

ConfigurePrometheus() {
    if [[ "$prometheus_enabled" != "true" ]]; then
        log_info "Prometheus setup skipped (disabled in config)"
        return
    fi

    log_info "Configuring Prometheus..."

    # Create required directories
    local directories=(
        "/etc/prometheus"
        "/var/lib/prometheus"
    )

    for dir in "${directories[@]}"; do
        if ! mkdir -p "$dir"; then
            log_error "Failed to create directory: $dir" true
        fi
        log_info "Created directory: $dir"
    done

    # Move prometheus binary and tools with retry
    local max_retries=3
    local retry_count=0
    
    cd prometheus* || log_error "Prometheus directory not found" true
    
    # Move binaries
    local binaries=("prometheus" "promtool")
    for binary in "${binaries[@]}"; do
        retry_count=0
        while ! sudo mv "$binary" "/usr/local/bin/" && ((retry_count < max_retries)); do
            log_warning "Failed to move $binary, retrying..."
            sleep 2
            ((retry_count++))
        done
        if ((retry_count >= max_retries)); then
            log_error "Failed to move $binary after $max_retries attempts" true
        fi
    done

    # Move console files
    local console_dirs=("consoles" "console_libraries")
    for dir in "${console_dirs[@]}"; do
        retry_count=0
        while ! sudo mv "$dir" "/etc/prometheus/" && ((retry_count < max_retries)); do
            log_warning "Failed to move $dir, retrying..."
            sleep 2
            ((retry_count++))
        done
        if ((retry_count >= max_retries)); then
            log_error "Failed to move $dir after $max_retries attempts" true
        fi
    done
    
    cd ..

    # Set ownership
    local prometheus_paths=(
        "/usr/local/bin/prometheus"
        "/usr/local/bin/promtool"
        "/etc/prometheus"
        "/var/lib/prometheus"
    )

    for path in "${prometheus_paths[@]}"; do
        if ! chown -R prometheus:prometheus "$path"; then
            log_warning "Failed to set ownership for: $path"
        fi
    done

    # Create prometheus configuration
    cat <<EOF > "/etc/prometheus/prometheus.yml"
global:
    scrape_interval: 15s
    external_labels:
        monitor: 'codelab-monitor'

scrape_configs:
    - job_name: 'prometheus'
      scrape_interval: 5s
      static_configs:
          - targets: ['localhost:9090']
            labels: 'Prometheus PROD'

    - job_name: 'NTFY'
      scrape_interval: 5s
      static_configs:
          - targets: ['localhost:$NFTY_Port']
            labels: 'Ntfy PROD'

    - job_name: 'grafana'
      scrape_interval: 5s
      static_configs:
          - targets: ['localhost:3000']
            labels: 'Grafana PROD'
EOF

    # Setup systemd service with retry
    retry_count=0
    while ! cp "$SCRIPT_DIR/Config/prometheus.service" "/etc/systemd/system/prometheus.service" && ((retry_count < max_retries)); do
        log_warning "Failed to copy service file, retrying..."
        sleep 2
        ((retry_count++))
    done

    if [ ! -f "/etc/systemd/system/prometheus.service" ]; then
        log_error "Failed to create service file" true
    fi

    # Update prometheus path in service file
    if ! sed -i "s|PATHHEREPLEASE|/usr/local/bin/prometheus|" "/etc/systemd/system/prometheus.service"; then
        log_warning "Failed to update prometheus path in service file"
    fi

    # Set proper permissions
    chmod 644 /etc/systemd/system/prometheus.service || log_warning "Failed to set service file permissions"
    chmod 644 /etc/prometheus/prometheus.yml || log_warning "Failed to set config file permissions"

    # Start and enable service
    systemctl daemon-reload || log_warning "Failed to reload systemd configuration"
    
    if ! systemctl enable prometheus; then
        log_warning "Failed to enable prometheus service"
    fi

    retry_count=0
    while ! systemctl start prometheus && ((retry_count < max_retries)); do
        log_warning "Failed to start prometheus service, retrying..."
        sleep 5
        ((retry_count++))
    done

    # Verify service status
    if systemctl is-active --quiet prometheus; then
        log_info "Prometheus service is running"
        systemctl status prometheus
    else
        log_warning "Prometheus service failed to start"
        systemctl status prometheus
    fi

    log_info "Prometheus configuration completed"
}

ConfigureGrafana() {
    if [[ "$grafana_enabled" != "true" ]]; then
        log_info "Grafana setup skipped (disabled in config)"
        return
    fi

    log_info "Configuring Grafana..."

    # Create required directories
    local directories=(
        "/etc/grafana"
        "/var/lib/grafana"
    )

    for dir in "${directories[@]}"; do
        if ! mkdir -p "$dir"; then
            log_error "Failed to create directory: $dir" true
        fi
        log_info "Created directory: $dir"
    done

    # Configure Grafana settings
    local config_file="/etc/grafana/grafana.ini"
    if ! cat <<EOF > "$config_file"; then
        log_error "Failed to create Grafana configuration" true
    fi
[server]
protocol = http
http_port = 3000
domain = $domain
root_url = https://$domain/$RANDOMSTRING_GRAFANA/grafana/$RANDOMSTRING_GRAFANA/
serve_from_sub_path = true

[security]
admin_user = admin
admin_password = $GRAFANA_PASSWORD
disable_gravatar = true
cookie_secure = true
cookie_samesite = strict

[auth]
disable_login_form = false
disable_signout_menu = false

[auth.basic]
enabled = true

[auth.proxy]
enabled = false

[analytics]
reporting_enabled = false
check_for_updates = true

[log]
mode = console file
level = info
EOF

    # Set proper permissions
    local max_retries=3
    local retry_count=0
    while ! chown -R grafana:grafana /etc/grafana && ((retry_count < max_retries)); do
        log_warning "Failed to set Grafana config ownership, retrying..."
        sleep 2
        ((retry_count++))
    done

    while ! chown -R grafana:grafana /var/lib/grafana && ((retry_count < max_retries)); do
        log_warning "Failed to set Grafana data ownership, retrying..."
        sleep 2
        ((retry_count++))
    done

    chmod 640 "$config_file" || log_warning "Failed to set Grafana config permissions"

    # Import NTFY dashboard if NTFY is enabled
    if [[ "$ntfy_enabled" == "true" ]]; then
        local dashboard_dir="/var/lib/grafana/dashboards"
        if ! mkdir -p "$dashboard_dir"; then
            log_warning "Failed to create dashboards directory"
        else
            if ! cp "$SCRIPT_DIR/grafana/ntfy-grafana.json" "$dashboard_dir/"; then
                log_warning "Failed to copy NTFY dashboard"
            else
                chown grafana:grafana "$dashboard_dir/ntfy-grafana.json" || log_warning "Failed to set dashboard ownership"
                log_info "NTFY dashboard imported successfully"
            fi
        fi
    fi

    # Start and enable Grafana service
    systemctl daemon-reload || log_warning "Failed to reload systemd configuration"
    
    if ! systemctl enable grafana-server; then
        log_warning "Failed to enable Grafana service"
    fi

    retry_count=0
    while ! systemctl start grafana-server && ((retry_count < max_retries)); do
        log_warning "Failed to start Grafana service, retrying..."
        sleep 5
        ((retry_count++))
    done

    # Verify service status
    if systemctl is-active --quiet grafana-server; then
        log_info "Grafana service is running"
        systemctl status grafana-server
    else
        log_warning "Grafana service failed to start"
        systemctl status grafana-server
    fi

    # Wait for Grafana to be ready
    log_info "Waiting for Grafana to be ready..."
    retry_count=0
    while ! curl -s http://localhost:3000 >/dev/null && ((retry_count < max_retries)); do
        log_warning "Grafana not yet ready, retrying..."
        sleep 5
        ((retry_count++))
    done

    if curl -s http://localhost:3000 >/dev/null; then
        log_info "Grafana is responding"
    else
        log_warning "Grafana is not responding, may need manual verification"
    fi

    log_info "Grafana configuration completed"
}

ConfigureSSL() {
    if [[ "$ssl" != "true" ]]; then
        log_info "SSL setup skipped (disabled in config)"
        return
    fi

    log_info "Configuring SSL certificates..."

    # Install certbot if not already installed
    if [[ ! -f "/usr/bin/certbot" ]]; then
        log_info "Installing certbot..."
        local max_retries=3
        local retry_count=0
        
        # Update and install snapd
        apt update -y || log_warning "Failed to update package list"
        if ! apt install snapd -y; then
            log_error "Failed to install snapd" true
        fi

        # Remove existing certbot installations
        apt-get remove certbot -y || log_warning "Failed to remove old certbot"
        snap remove certbot || log_warning "Failed to remove old certbot snap"

        # Install certbot with retry
        while ! snap install --classic certbot && ((retry_count < max_retries)); do
            log_warning "Failed to install certbot, retrying..."
            sleep 5
            ((retry_count++))
        done

        if ((retry_count >= max_retries)); then
            log_error "Failed to install certbot after $max_retries attempts" true
        fi

        # Create symlink
        if [ ! -f "/usr/bin/certbot" ]; then
            ln -s /snap/bin/certbot /usr/bin/certbot || log_error "Failed to create certbot symlink" true
        fi
    fi

    # Get SSL certificates for main domain
    log_info "Getting SSL certificate for $domain"
    if ! certbot --nginx -d "$domain" -d "www.$domain" --email "$email" --agree-tos --non-interactive; then
        log_error "Failed to obtain SSL certificate for main domain" true
    fi

    # Get SSL certificates for NTFY subdomain if enabled
    if [[ "$ntfy_enabled" == "true" ]]; then
        log_info "Getting SSL certificate for ntfy.$domain"
        if ! certbot --nginx -d "ntfy.$domain" -d "www.ntfy.$domain" --email "$email" --agree-tos --non-interactive; then
            log_warning "Failed to obtain SSL certificate for NTFY subdomain"
        fi
    fi

    # Verify certbot timer is active
    if ! systemctl is-active --quiet certbot.timer; then
        log_warning "Certbot renewal timer is not active, attempting to enable..."
        systemctl enable certbot.timer || log_warning "Failed to enable certbot timer"
        systemctl start certbot.timer || log_warning "Failed to start certbot timer"
    fi

    # Update NGINX config for HTTP/2
    if [[ -f "$SCRIPT_DIR/sed-command.sh" ]]; then
        chmod +x "$SCRIPT_DIR/sed-command.sh" || log_warning "Failed to make sed script executable"
        if ! sudo "$SCRIPT_DIR/sed-command.sh" "/etc/nginx/conf.d/$domain.conf"; then
            log_warning "Failed to update NGINX config for HTTP/2"
        fi
    else
        log_warning "sed-command.sh not found, skipping HTTP/2 configuration"
    fi

    # Test NGINX config and reload
    if nginx -t; then
        log_info "NGINX configuration test passed"
        if ! systemctl reload nginx; then
            log_warning "Failed to reload NGINX"
            # Try to restart if reload fails
            systemctl restart nginx || log_warning "Failed to restart NGINX"
        fi
    else
        log_error "NGINX configuration test failed" true
    fi

    # Verify SSL certificates
    if ! certbot certificates | grep -q "$domain"; then
        log_warning "SSL certificate verification failed"
    else
        log_info "SSL certificates verified successfully"
    fi

    log_info "SSL configuration completed"
}

ConfigureServer() {
    if [[ "$server_hardening_enabled" != "true" ]]; then
        log_info "Server hardening skipped (disabled in config)"
        return
    fi

    log_info "Configuring server security..."

    # Set timezone
    if ! timedatectl set-timezone Europe/Amsterdam; then
        log_warning "Failed to set timezone"
    fi

    # Configure SSH security settings
    log_info "Configuring SSH security..."
    local ssh_config="/etc/ssh/sshd_config"
    local backup_file="/etc/ssh/sshd_config.bak"

    # Backup original config
    cp "$ssh_config" "$backup_file" || log_warning "Failed to backup SSH config"

    # SSH security configurations with error handling
    local ssh_settings=(
        "s/PermitRootLogin yes/PermitRootLogin no/"
        "s/PasswordAuthentication yes/PasswordAuthentication no/"
        "s/#LoginGraceTime 2m/LoginGraceTime 20/"
        "s/#MaxAuthTries 6/MaxAuthTries 3/"
        "s/#MaxSessions 10/MaxSessions 5/"
        "s/#PermitEmptyPasswords no/PermitEmptyPasswords no/"
        "s/#KerberosAuthentication no/KerberosAuthentication no/"
        "s/#GSSAPIAuthentication no/GSSAPIAuthentication no/"
        "s/#AllowAgentForwarding yes/AllowAgentForwarding no/"
        "s/#AllowTcpForwarding yes/AllowTcpForwarding no/"
        "s/#X11Forwarding no/X11Forwarding no/"
        "s/#ClientAliveInterval 0/ClientAliveInterval 120/"
        "s/#ClientAliveCountMax 3/ClientAliveCountMax 2/"
        "s/#MaxStartups 10:30:100/MaxStartups 10:30:55/"
        "s/#PermitTunnel no/PermitTunnel no/"
        "s/#Banner none/Banner none/"
        "s/Subsystem\"/c\#Subsystem/"
        "s/#Port 22/Port $SSH_Port/"
    )

    for setting in "${ssh_settings[@]}"; do
        if ! sed -i "$setting" "$ssh_config"; then
            log_warning "Failed to apply SSH setting: $setting"
        fi
    done

    # Add allowed users and force command
    echo "AllowUsers $user" >> "$ssh_config" || log_warning "Failed to add allowed users"
    echo "ForceCommand /sites/$domain/Scripts/OnLogin/script-on-login.sh" >> "$ssh_config" || log_warning "Failed to add force command"

    # Add SSH ciphers and algorithms
    local security_config="
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes256-cbc
KexAlgorithms diffie-hellman-group14-sha256,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"

    echo "$security_config" >> "$ssh_config" || log_warning "Failed to add security configurations"

    log_info "SSH configured to use port $SSH_Port"

    # Configure UFW (firewall)
    log_info "Configuring firewall..."
    
    # Basic UFW setup
    ufw default allow outgoing || log_warning "Failed to set default outgoing policy"
    ufw default deny incoming || log_warning "Failed to set default incoming policy"

    # Configure UFW rules with retry mechanism
    local max_retries=3
    local ufw_rules=(
        "deny 80 comment 'Deny use of unsecured traffic'"
        "allow 443 comment 'Allow use of secured traffic'"
        "allow OpenSSH"
        "allow 'Nginx HTTPS'"
        "limit $SSH_Port/tcp comment 'SSH port rate limit'"
        "limit $SSH_Port/udp comment 'SSH port rate limit'"
    )

    for rule in "${ufw_rules[@]}"; do
        local retry_count=0
        while ! ufw $rule && ((retry_count < max_retries)); do
            log_warning "Failed to add UFW rule: $rule, retrying..."
            sleep 2
            ((retry_count++))
        done
    done

    # Enable UFW
    log_info "Enabling UFW..."
    echo "y" | ufw enable || log_error "Failed to enable UFW" true
    
    # Reload UFW
    ufw reload || log_warning "Failed to reload UFW"
    
    # Show UFW status
    ufw status || log_warning "Failed to get UFW status"

    # Reload services
    systemctl reload nginx || log_warning "Failed to reload NGINX"
    systemctl enable ssh || log_warning "Failed to enable SSH"
    systemctl restart ssh || log_warning "Failed to restart SSH"

    # Clean up
    apt autoremove -y || log_warning "Failed to clean up packages"

    # Verify SSH service
    if ! systemctl is-active --quiet ssh; then
        log_warning "SSH service is not running"
        systemctl status ssh
    else
        log_info "SSH service is running properly"
    fi

    # Test SSH configuration
    if ! sshd -t; then
        log_error "SSH configuration test failed" true
    fi
    log_info "SSH configuration test passed"

    log_info "Server security configuration completed"
}

SendEchoToEndUser() {
    log_info "Generating configuration summary..."

    # Create a temporary file for credentials
    local credentials_file="/root/server_credentials.txt"
    local summary=""

    # Function to add a section to the summary
    add_section() {
        local title="$1"
        local content="$2"
        summary+="=== $title ===\n"
        summary+="$content\n\n"
    }

    # Base Information
    add_section "Server Information" "$(cat <<EOF
Domain: $domain
Email: $email
Date: $(date)
EOF
)"

    # SSH Information
    add_section "SSH Configuration" "$(cat <<EOF
User: $user
Port: $SSH_Port
Note: SSH password authentication is disabled, use SSH keys for access
EOF
)"

    # NTFY Information (if enabled)
    if [[ "$ntfy_enabled" == "true" ]]; then
        add_section "NTFY Configuration" "$(cat <<EOF
Domain: ntfy.$domain
Topic: $STRING
Username: $user
Password: $NTFY_PASSWORD
URL: https://ntfy.$domain/$STRING
EOF
)"
    fi

    # Prometheus Information (if enabled)
    if [[ "$prometheus_enabled" == "true" ]]; then
        add_section "Prometheus Configuration" "$(cat <<EOF
URL: $domain/$RANDOMSTRING_PROMETHEUS/prometheus/$RANDOMSTRING_PROMETHEUS/
Username: $PROMETHEUS_USERNAME
Password: $PROMETHEUS_PASSWORD
EOF
)"
    fi

    # Grafana Information (if enabled)
    if [[ "$grafana_enabled" == "true" ]]; then
        add_section "Grafana Configuration" "$(cat <<EOF
URL: $domain/$RANDOMSTRING_GRAFANA/grafana/$RANDOMSTRING_GRAFANA/
Username: $GRAFANA_USERNAME
Password: $GRAFANA_PASSWORD
EOF
)"
    fi

    # Projects Information
    local projects_info=""
    echo "$config" | jq -c '.projects[]' | while read -r project; do
        name=$(echo "$project" | jq -r '.name')
        port=$(echo "$project" | jq -r '.port')
        projects_info+="Project: $name\n"
        projects_info+="  URL: https://$domain/$name/\n"
        projects_info+="  Port: $port\n"
        projects_info+="\n"
    done
    
    if [ ! -z "$projects_info" ]; then
        add_section "Configured Projects" "$projects_info"
    fi

    # Feature Status
    local features_info=""
    features_info+="SSL: ${ssl}\n"
    features_info+="NGINX: ${nginx_enabled}\n"
    features_info+="Docker: ${docker_enabled}\n"
    features_info+="Fail2ban: ${fail2ban_enabled}\n"
    features_info+="Prometheus: ${prometheus_enabled}\n"
    features_info+="Grafana: ${grafana_enabled}\n"
    features_info+="NTFY: ${ntfy_enabled}\n"
    features_info+="PM2: ${pm2_enabled}\n"
    features_info+="Github Webhooks: ${github_webhooks_enabled}\n"
    features_info+="Server Hardening: ${server_hardening_enabled}\n"
    
    add_section "Enabled Features" "$features_info"

    # Save to file
    echo -e "$summary" > "$credentials_file"
    chmod 600 "$credentials_file"

    # Display summary
    echo -e "\n=== Configuration Summary ===\n"
    echo -e "$summary"
    echo -e "Full credentials have been saved to: $credentials_file"
    echo -e "\nIMPORTANT:"
    echo -e "1. Save these credentials in a secure location"
    echo -e "2. The credentials file on the server will be removed on next reboot for security"
    echo -e "3. Consider rebooting the system to ensure all services start properly"

    # Add cleanup script to /etc/rc.local if it doesn't exist
    if [ -f "/etc/rc.local" ]; then
        if ! grep -q "$credentials_file" "/etc/rc.local"; then
            sed -i "s|^exit 0|rm -f $credentials_file\\nexit 0|" /etc/rc.local
        fi
    else
        cat <<EOF > /etc/rc.local
#!/bin/bash
rm -f $credentials_file
exit 0
EOF
        chmod +x /etc/rc.local
    fi

    # Check for warnings or errors
    if [ -s "$WARN_LOG" ]; then
        echo -e "\nWarnings occurred during setup. Check $WARN_LOG for details."
    fi
    if [ -s "$ERROR_LOG" ]; then
        echo -e "\nErrors occurred during setup. Check $ERROR_LOG for details."
    fi
}

# Add new OS check function
check_os() {
    # Check if /etc/os-release exists
    if [ ! -f "/etc/os-release" ]; then
        log_error "Cannot determine OS - /etc/os-release file not found" true
    fi

    # Source the OS release information
    . /etc/os-release

    # Check if it's Debian or Ubuntu
    case "$ID" in
        debian|ubuntu)
            log_info "Running on supported OS: $PRETTY_NAME"
            ;;
        *)
            log_error "This script only supports Debian and Ubuntu systems. Detected OS: $PRETTY_NAME" true
            ;;
    esac

    # Check minimum version requirements
    case "$ID" in
        debian)
            # Check for Debian 10 (buster) or higher
            if [ "${VERSION_ID%%.*}" -lt 10 ]; then
                log_error "This script requires Debian 10 (Buster) or higher. Detected version: $VERSION_ID" true
            fi
            ;;
        ubuntu)
            # Check for Ubuntu 20.04 or higher
            if [ "$(echo $VERSION_ID | awk -F. '{print $1$2}')" -lt 2004 ]; then
                log_error "This script requires Ubuntu 20.04 or higher. Detected version: $VERSION_ID" true
            fi
            ;;
    esac
}

# Main execution
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    SendHelpMenu
fi

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Initialize log files
: > "$ERROR_LOG"
: > "$WARN_LOG"

log_info "Starting server configuration..."

# Add OS check before loading configuration
check_os

# Load and validate configuration
LoadConfig "$1"

# Run all configuration functions
ConfigurePackages
ConfigureUser
ConfigureDocker
ConfigureFolderStructure
ConfigurePM2
ConfigureErrorPage
ConfigureGithubHook
ConfigureNGINX
ConfigureGitClone
ConfigureFail2Ban
ConfigurePrometheus
ConfigureGrafana
ConfigureSSL
ConfigureScriptOnLogin
ConfigureServer
SendEchoToEndUser

# Clean up
unset LC_ALL

# Show final status
if [ -s "$ERROR_LOG" ]; then
    echo -e "\nWarning: Some errors occurred during setup. Check $ERROR_LOG for details."
    exit 1
else
    log_info "Setup completed successfully!"
    exit 0
fi