# Production Deployment Guide for Pyntry

This guide provides step-by-step instructions for securely deploying Pyntry in a production environment.

---

## Prerequisites

- Linux server (Ubuntu 22.04 LTS recommended)
- Python 3.10 or higher
- Nginx (for reverse proxy)
- SSL certificate (Let's Encrypt recommended)
- Non-root user for running the application

---

## 1. Server Setup

### Create Application User
```bash
# Create dedicated user for the application
sudo adduser --system --group --home /opt/pyntry pyntry

# Create application directory
sudo mkdir -p /opt/pyntry
sudo chown pyntry:pyntry /opt/pyntry
```

### Install System Dependencies
```bash
sudo apt update
sudo apt install python3-pip python3-venv nginx certbot python3-certbot-nginx
```

---

## 2. Application Installation

### Clone/Copy Application
```bash
# As pyntry user
sudo -u pyntry bash
cd /opt/pyntry

# Copy your application files here
# Or clone from git:
# git clone https://github.com/yourusername/pyntry.git .

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Create Environment File
```bash
# Create .env file
cat > /opt/pyntry/.env << 'EOF'
# Application secret (generate with: python3 -c "import os; print(os.urandom(32).hex())")
APP_SECRET=CHANGE_THIS_TO_A_LONG_RANDOM_STRING

# Database
DB_PATH=pyntry.db

# API Configuration
PRODUCT_API_URL=https://world.openfoodfacts.org/api/v2/product/{BARCODE}
CONTACT_EMAIL=your-email@example.com

# Production settings
FLASK_DEBUG=False
FLASK_ENV=production
FORCE_HTTPS=True
EOF

# Generate secure secret
SECRET=$(python3 -c "import os; print(os.urandom(32).hex())")
sed -i "s/CHANGE_THIS_TO_A_LONG_RANDOM_STRING/$SECRET/" /opt/pyntry/.env

# Set secure permissions
chmod 600 /opt/pyntry/.env
```

### Initialize Database
```bash
# Still as pyntry user
source venv/bin/activate
python3 main.py

# This will create the database and show master credentials
# Save these credentials securely!

# Set database permissions
chmod 600 /opt/pyntry/pyntry.db
```

---

## 3. Systemd Service Configuration

### Create Service File
```bash
# As root
sudo cat > /etc/systemd/system/pyntry.service << 'EOF'
[Unit]
Description=Pyntry Web Application
After=network.target

[Service]
Type=notify
User=pyntry
Group=pyntry
WorkingDirectory=/opt/pyntry
Environment="PATH=/opt/pyntry/venv/bin"
ExecStart=/opt/pyntry/venv/bin/gunicorn \
    --workers 4 \
    --bind 127.0.0.1:8000 \
    --timeout 120 \
    --access-logfile /var/log/pyntry/access.log \
    --error-logfile /var/log/pyntry/error.log \
    --log-level info \
    main:app

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/pyntry
ReadOnlyPaths=/opt/pyntry/static

# Restart policy
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create log directory
sudo mkdir -p /var/log/pyntry
sudo chown pyntry:pyntry /var/log/pyntry

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable pyntry
sudo systemctl start pyntry

# Check status
sudo systemctl status pyntry
```

---

## 4. Nginx Configuration

### Install SSL Certificate
```bash
# Get Let's Encrypt certificate
sudo certbot certonly --nginx -d your-domain.com
```

### Configure Nginx
```bash
sudo cat > /etc/nginx/sites-available/pyntry << 'EOF'
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=general:10m rate=100r/m;

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name your-domain.com;
    
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name your-domain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    
    # Logging
    access_log /var/log/nginx/pyntry_access.log;
    error_log /var/log/nginx/pyntry_error.log;
    
    # Max upload size
    client_max_body_size 16M;
    
    # Static files
    location /static {
        alias /opt/pyntry/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check (no rate limiting)
    location /health {
        proxy_pass http://127.0.0.1:8000;
        access_log off;
    }
    
    # Login endpoint (strict rate limiting)
    location /login {
        limit_req zone=login burst=3 nodelay;
        limit_req_status 429;
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }
    
    # API endpoints (moderate rate limiting)
    location /api {
        limit_req zone=api burst=10 nodelay;
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # All other locations (general rate limiting)
    location / {
        limit_req zone=general burst=20 nodelay;
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/pyntry /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## 5. Firewall Configuration

```bash
# Configure UFW
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable

# Check status
sudo ufw status
```

---

## 6. Automated Backups

### Create Backup Script
```bash
sudo cat > /opt/pyntry/backup.sh << 'EOF'
#!/bin/bash
set -e

# Configuration
BACKUP_DIR="/opt/pyntry/backups"
DB_PATH="/opt/pyntry/pyntry.db"
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/pyntry_backup_$TIMESTAMP.db"

# Create backup
cp "$DB_PATH" "$BACKUP_FILE"
gzip "$BACKUP_FILE"

# Remove old backups
find "$BACKUP_DIR" -name "pyntry_backup_*.db.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: ${BACKUP_FILE}.gz"
EOF

sudo chmod +x /opt/pyntry/backup.sh
sudo chown pyntry:pyntry /opt/pyntry/backup.sh
```

### Setup Cron Job
```bash
# Add to crontab for pyntry user
sudo -u pyntry crontab -e

# Add this line (daily backup at 2 AM):
0 2 * * * /opt/pyntry/backup.sh >> /var/log/pyntry/backup.log 2>&1
```

---

## 7. Monitoring Setup

### Install and Configure Fail2Ban
```bash
# Install fail2ban
sudo apt install fail2ban

# Create Pyntry jail
sudo cat > /etc/fail2ban/jail.d/pyntry.conf << 'EOF'
[pyntry-auth]
enabled = true
port = http,https
filter = pyntry-auth
logpath = /var/log/pyntry/app.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

# Create filter
sudo cat > /etc/fail2ban/filter.d/pyntry-auth.conf << 'EOF'
[Definition]
failregex = ^.*Failed login attempt for user .* from <HOST>.*$
            ^.*SECURITY EVENT: FAILED_LOGIN .* IP: <HOST>.*$
ignoreregex =
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
sudo fail2ban-client status pyntry-auth
```

### Setup Log Rotation
```bash
sudo cat > /etc/logrotate.d/pyntry << 'EOF'
/var/log/pyntry/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 pyntry pyntry
    sharedscripts
    postrotate
        systemctl reload pyntry > /dev/null 2>&1 || true
    endscript
}
EOF
```

---

## 8. Security Hardening Checklist

### Application Security
- [ ] Changed APP_SECRET to strong random value
- [ ] Set FLASK_DEBUG=False
- [ ] Database file permissions set to 0600
- [ ] .env file permissions set to 0600
- [ ] Removed or disabled test endpoints
- [ ] Updated CONTACT_EMAIL in .env

### Server Security
- [ ] Firewall configured (UFW or iptables)
- [ ] SSH key authentication only (disable password auth)
- [ ] Fail2ban configured and running
- [ ] Regular security updates enabled
- [ ] Non-root user for application
- [ ] SELinux or AppArmor enabled (optional but recommended)

### Web Server Security
- [ ] SSL certificate installed and valid
- [ ] HTTPS enforced (HTTP redirects to HTTPS)
- [ ] Security headers configured
- [ ] Rate limiting enabled
- [ ] Max upload size set
- [ ] Static file caching enabled

### Monitoring
- [ ] Application logs being written
- [ ] Nginx logs being written
- [ ] Log rotation configured
- [ ] Automated backups running
- [ ] Health check endpoint accessible
- [ ] Fail2ban monitoring application logs

---

## 9. Maintenance

### Daily Tasks
```bash
# Check application status
sudo systemctl status pyntry

# Check recent logs
sudo tail -f /var/log/pyntry/app.log

# Check fail2ban bans
sudo fail2ban-client status pyntry-auth
```

### Weekly Tasks
```bash
# Check disk usage
df -h

# Check backup status
ls -lh /opt/pyntry/backups/

# Review security logs
sudo grep "SECURITY EVENT" /var/log/pyntry/*.log
```

### Monthly Tasks
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Python dependencies
sudo -u pyntry bash -c "cd /opt/pyntry && source venv/bin/activate && pip install --upgrade -r requirements.txt"

# Restart application
sudo systemctl restart pyntry

# Review SSL certificate expiry
sudo certbot certificates
```

---

## 10. Troubleshooting

### Application Won't Start
```bash
# Check service status
sudo systemctl status pyntry

# Check logs
sudo journalctl -u pyntry -n 50

# Check application logs
sudo tail -50 /var/log/pyntry/error.log

# Test gunicorn manually
sudo -u pyntry bash
cd /opt/pyntry
source venv/bin/activate
gunicorn --bind 127.0.0.1:8000 main:app
```

### Database Issues
```bash
# Check database file permissions
ls -l /opt/pyntry/pyntry.db

# Restore from backup
sudo -u pyntry bash
cd /opt/pyntry
cp pyntry.db pyntry.db.broken
gunzip -c backups/pyntry_backup_YYYYMMDD_HHMMSS.db.gz > pyntry.db
chmod 600 pyntry.db
exit
sudo systemctl restart pyntry
```

### SSL Certificate Issues
```bash
# Renew certificate
sudo certbot renew

# Test renewal
sudo certbot renew --dry-run
```

### High CPU/Memory Usage
```bash
# Check processes
top
htop

# Increase gunicorn workers if needed (edit /etc/systemd/system/pyntry.service)
# Recommended: 2-4 workers per core

# Restart service
sudo systemctl restart pyntry
```

---

## 11. Rolling Updates

### Update Application Code
```bash
# Stop application
sudo systemctl stop pyntry

# Backup database
sudo -u pyntry /opt/pyntry/backup.sh

# Update code (as pyntry user)
sudo -u pyntry bash
cd /opt/pyntry
git pull  # or copy new files

# Update dependencies if needed
source venv/bin/activate
pip install -r requirements.txt

# Test configuration
python3 -c "from main import app; print('OK')"

exit

# Start application
sudo systemctl start pyntry

# Check status
sudo systemctl status pyntry
```

---

## 12. Emergency Procedures

### Application Down
1. Check service status: `sudo systemctl status pyntry`
2. Check logs: `sudo journalctl -u pyntry -n 100`
3. Restart service: `sudo systemctl restart pyntry`
4. If still failing, restore from backup

### Database Corruption
1. Stop application: `sudo systemctl stop pyntry`
2. Backup corrupted database: `cp pyntry.db pyntry.db.corrupt`
3. Restore from latest backup
4. Start application: `sudo systemctl start pyntry`
5. Verify data integrity

### Security Breach
1. Immediately disconnect from network
2. Review all logs for suspicious activity
3. Change all passwords and secrets
4. Restore from known-good backup
5. Update and patch all software
6. Review security configurations
7. Consider forensic analysis

---

## Resources

- [Flask Deployment Options](https://flask.palletsprojects.com/en/latest/deploying/)
- [Gunicorn Documentation](https://docs.gunicorn.org/)
- [Nginx Security Guide](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)
- [Let's Encrypt](https://letsencrypt.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

