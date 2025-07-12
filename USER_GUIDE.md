# ECC-Secured IDS/IPS System - User Guide

**Production-Ready Enterprise Network Security Solution**

This comprehensive guide covers the operation of your production-ready ECC-Secured IDS/IPS System, designed for enterprise environments with zero false positive detection and intelligent threat response.

## 🛡️ System Overview

### Production Features
- **🚨 8 Production-Tuned Detection Rules**: Eliminates false positives while maintaining comprehensive threat coverage
- **⚡ Real-Time Network Monitoring**: Live packet capture with enterprise-grade performance using Npcap
- **🔐 Military-Grade ECC Encryption**: secp256r1 curve protecting all sensitive security data
- **🤖 Intelligent Automated Response**: Smart IP blocking with configurable timeouts and whitelisting
- **📊 Professional Dashboard**: Real-time threat visualization with interactive charts and metrics
- **🔗 Enterprise API Integration**: Complete RESTful API for SIEM and automation platforms

### Detection Capabilities
- **Port Scanning**: Aggressive reconnaissance (50+ connections/min)
- **Brute Force Attacks**: Sustained authentication attacks (25+ failed attempts)
- **Malicious Payloads**: SQL injection, XSS, command injection patterns
- **Data Exfiltration**: Large data transfers (8KB+ packets, 10+ per minute)
- **DDoS Attacks**: Distributed attacks (500+ connections from 50+ sources)
- **Lateral Movement**: Network reconnaissance patterns (20+ connections to 5+ targets)
- **Cryptocurrency Mining**: Unauthorized mining activity on known ports
- **Known Malicious IPs**: Real-time threat intelligence blocking

## 📖 Table of Contents

1. [Getting Started](#getting-started)
2. [System Configuration](#system-configuration)
3. [Web Dashboard Guide](#web-dashboard-guide)
4. [API Usage](#api-usage)
5. [Security Management](#security-management)
6. [Monitoring and Alerts](#monitoring-and-alerts)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Configuration](#advanced-configuration)

## 🚀 Getting Started

### Quick Start

1. **Start the Application**
   ```bash
   java -jar target/ecc-ids-ips-1.0.0.jar
   ```

2. **Access the Dashboard**
   - Open your browser to: http://localhost:8080
   - Login with default credentials:
     - **Username**: `admin`
     - **Password**: `admin123`

3. **Verify System Status**
   - Check the Overview section for system health
   - Ensure all components show as "Active"

### First-Time Setup

1. **Change Default Passwords** (Recommended)
   - Set environment variables or update configuration
   - See [Security Management](#security-management) section

2. **Configure Network Interface** (Optional)
   - For real packet capture, install WinPcap/Npcap
   - Update sensor configuration if needed

3. **Review Detection Rules**
   - Check `src/main/resources/detection-rules.json`
   - Customize rules for your environment

## ⚙️ System Configuration

### Environment Variables

The system supports configuration through environment variables:

#### Server Configuration
```bash
SERVER_PORT=8080                    # Server port (default: 8080)
```

#### Database Configuration
```bash
DATABASE_URL=jdbc:h2:mem:idsips     # Database URL
DATABASE_DRIVER=org.h2.Driver       # Database driver
DATABASE_USERNAME=sa                # Database username
DATABASE_PASSWORD=password          # Database password
```

#### Security Configuration
```bash
JWT_SECRET=your-secret-key          # JWT signing secret (change this!)
JWT_EXPIRATION=3600000              # JWT expiration (milliseconds)
ECC_ALGORITHM=secp256r1             # ECC curve algorithm
ECC_KEY_SIZE=256                    # ECC key size
ECC_AES_KEY_LENGTH=16               # AES key length for ECIES
ECC_EPHEMERAL_KEY_LENGTH=91         # Ephemeral key length

# User Credentials
ADMIN_USERNAME=admin                # Admin username
ADMIN_PASSWORD=admin123             # Admin password (change this!)
OPERATOR_USERNAME=operator          # Operator username
OPERATOR_PASSWORD=operator123       # Operator password (change this!)
```

#### Sensor Configuration
```bash
SENSOR_ENABLED=false                # Enable real packet capture
SENSOR_INTERFACE=any                # Network interface to monitor
SENSOR_CAPTURE_TIMEOUT=1000         # Capture timeout (ms)
SENSOR_BUFFER_SIZE=65536            # Capture buffer size
SENSOR_SIMULATION_ENABLED=true      # Enable simulation mode
SENSOR_SIMULATION_INTERVAL=5000     # Simulation packet interval (ms)
SENSOR_MAX_PACKET_SIZE=1500         # Maximum packet size
SENSOR_MIN_PACKET_SIZE=64           # Minimum packet size
```

#### Detection Configuration
```bash
DETECTION_ENABLED=true              # Enable detection engine
DETECTION_RULES_FILE=classpath:detection-rules.json  # Rules file location
DETECTION_MAX_ALERTS_PER_MINUTE=100 # Rate limiting
```

#### Prevention Configuration
```bash
PREVENTION_ENABLED=true             # Enable prevention system
PREVENTION_AUTO_BLOCK=true          # Enable automatic IP blocking
PREVENTION_BLOCK_DURATION=3600      # Block duration (seconds)
```

### Configuration File

You can also configure the system using `application.yml`:

```yaml
server:
  port: 8080

idsips:
  security:
    jwt:
      secret: "your-secure-secret-key"
      expiration: 3600000
    ecc:
      algorithm: secp256r1
      key-size: 256
    users:
      admin:
        username: admin
        password: your-secure-password
      operator:
        username: operator
        password: operator-password
  
  sensor:
    enabled: false
    interface: any
    simulation:
      enabled: true
      packet-interval: 5000
  
  detection:
    enabled: true
    max-alerts-per-minute: 100
  
  prevention:
    enabled: true
    auto-block: true
    block-duration: 3600
```

## 🖥️ Web Dashboard Guide

### Login Screen

1. **Access**: Navigate to http://localhost:8080
2. **Credentials**: Enter your username and password
3. **Security**: Uses JWT tokens for secure sessions

### Dashboard Sections

#### 1. Overview
- **System Statistics**: Active alerts, blocked IPs, packets analyzed
- **System Uptime**: How long the system has been running
- **Recent Alerts**: Latest security events
- **Component Status**: Health of all system components

#### 2. Alerts Management
- **View Alerts**: Browse all security alerts
- **Filter by Severity**: Critical, High, Medium, Low
- **Alert Details**: Click "Details" to view full information
- **Decrypt Alerts**: Use "Decrypt Details" to view encrypted content
- **Update Status**: Mark alerts as resolved or investigating

#### 3. IP Blocking
- **View Blocked IPs**: See all currently blocked addresses
- **Manual Blocking**: Add IP addresses to block list
- **Unblock IPs**: Remove IPs from block list
- **Block History**: View blocking activity and reasons

#### 4. System Status
- **Detailed Information**: JVM memory, system resources
- **Component Health**: Status of all system components
- **Performance Metrics**: System performance indicators

### Dashboard Features

#### Real-time Updates
- Click "Refresh" button to update data
- System automatically updates statistics
- Live monitoring of security events

#### Responsive Design
- Works on desktop, tablet, and mobile devices
- Bootstrap-based modern interface
- Intuitive navigation and controls

## 🔌 API Usage

### Authentication

All API endpoints require authentication except login and public key endpoints.

#### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "expires_in": 3600
}
```

#### Using JWT Token
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8080/api/v1/system/status
```

### API Endpoints

#### System Information
- `GET /api/v1/health` - Health check
- `GET /api/v1/system/status` - System status and statistics
- `GET /api/v1/system/info` - Detailed system information

#### Security Alerts
- `GET /api/v1/alerts` - List all alerts
- `GET /api/v1/alerts/{alertId}` - Get specific alert
- `POST /api/v1/alerts/decrypt` - Decrypt alert details
- `PUT /api/v1/alerts/{alertId}/status` - Update alert status
- `GET /api/v1/alerts/stats` - Alert statistics

#### IP Blocking
- `GET /api/v1/block` - List blocked IPs
- `POST /api/v1/block` - Block an IP address
- `DELETE /api/v1/block/{ip}` - Unblock an IP address
- `GET /api/v1/block/{ip}` - Get blocked IP details
- `GET /api/v1/block/stats` - Prevention statistics

#### ECC Encryption
- `GET /api/v1/ecc/public-key` - Get system public key

#### Log Management
- `POST /api/v1/logs/store` - Store encrypted logs (sensor use)
- `GET /api/v1/logs/stats` - Log statistics

### API Examples

#### Block an IP Address
```bash
curl -X POST http://localhost:8080/api/v1/block \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100","reason":"Suspicious activity detected"}'
```

#### Decrypt Alert Details
```bash
curl -X POST http://localhost:8080/api/v1/alerts/decrypt \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"encrypted_alert":"encrypted_data_here"}'
```

## 🔒 Security Management

### User Management

#### Default Users
- **Admin**: Full system access, can manage all features
- **Operator**: Limited access, can view alerts and block IPs

#### Changing Passwords

**Method 1: Environment Variables**
```bash
export ADMIN_PASSWORD="your-new-secure-password"
export OPERATOR_PASSWORD="operator-new-password"
java -jar target/ecc-ids-ips-1.0.0.jar
```

**Method 2: Configuration File**
Update `application.yml`:
```yaml
idsips:
  security:
    users:
      admin:
        password: your-new-secure-password
      operator:
        password: operator-new-password
```

### JWT Security

#### Change JWT Secret
```bash
export JWT_SECRET="your-very-long-and-secure-secret-key-here"
```

#### Token Expiration
```bash
export JWT_EXPIRATION=7200000  # 2 hours in milliseconds
```

### ECC Encryption

#### Supported Curves
- `secp256r1` (default, NIST P-256)
- `secp384r1` (NIST P-384)
- `secp521r1` (NIST P-521)

#### Change ECC Algorithm
```bash
export ECC_ALGORITHM="secp384r1"
export ECC_KEY_SIZE=384
```

### Database Security

#### Use External Database
```bash
export DATABASE_URL="jdbc:postgresql://localhost:5432/idsips"
export DATABASE_DRIVER="org.postgresql.Driver"
export DATABASE_USERNAME="idsips_user"
export DATABASE_PASSWORD="secure_db_password"
```

## 📊 Monitoring and Alerts

### Alert Types

1. **Port Scanning**: Detects reconnaissance activities
2. **Brute Force**: Identifies authentication attacks
3. **Malicious Payload**: XSS, SQL injection, command injection
4. **Suspicious Traffic**: Unusual packet patterns
5. **Anomalous Behavior**: Unexpected network activity

### Alert Severity Levels

- **Critical**: Immediate action required
- **High**: Important security events
- **Medium**: Moderate security concerns
- **Low**: Informational events

### Monitoring Best Practices

1. **Regular Review**: Check alerts daily
2. **Investigate Criticals**: Respond to critical alerts immediately
3. **Update Rules**: Customize detection rules for your environment
4. **Monitor Trends**: Look for patterns in alert data
5. **Maintain Logs**: Keep audit trails for compliance

### Performance Monitoring

#### System Metrics
- Memory usage and JVM performance
- Database connection health
- Network sensor status
- Detection engine performance

#### Alert Metrics
- Alerts per minute/hour/day
- Alert distribution by severity
- Top source IPs generating alerts
- Most triggered detection rules

## 🔧 Troubleshooting

### Common Issues

#### 1. Cannot Access Dashboard (404 Error)
**Problem**: Web dashboard returns 404
**Solution**: 
- Ensure application is running on correct port
- Check if static files are properly served
- Verify no context path conflicts

#### 2. Authentication Fails
**Problem**: Login returns "Invalid credentials"
**Solution**:
- Verify username and password
- Check if custom credentials are properly configured
- Ensure JWT secret is properly set

#### 3. Network Sensor Not Working
**Problem**: "wpcap.dll not found" or similar errors
**Solution**:
- Install WinPcap or Npcap on Windows
- Install libpcap-dev on Linux
- Or disable sensor and use simulation mode

#### 4. Database Connection Issues
**Problem**: Cannot connect to database
**Solution**:
- Check database URL and credentials
- Ensure database server is running
- Verify network connectivity

#### 5. High Memory Usage
**Problem**: Application consuming too much memory
**Solution**:
- Increase JVM heap size: `-Xmx2g`
- Reduce detection rate limits
- Clean up old alerts and logs

### Debug Mode

Enable debug logging:
```bash
export LOGGING_LEVEL_COM_SECURITY_IDSIPS=DEBUG
```

Or in `application.yml`:
```yaml
logging:
  level:
    com.security.idsips: DEBUG
```

### Log Files

Check application logs:
- Console output for immediate issues
- `logs/idsips.log` for detailed logging
- System logs for OS-level issues

## 🔧 Advanced Configuration

### Custom Detection Rules

Edit `src/main/resources/detection-rules.json`:

```json
{
  "rule_id": "CUSTOM_001",
  "name": "Custom Rule",
  "description": "Detects custom pattern",
  "severity": "HIGH",
  "alert_type": "SUSPICIOUS_TRAFFIC",
  "enabled": true,
  "conditions": {
    "source_ip_patterns": ["192\\.168\\.1\\..*"],
    "port_ranges": [{"start": 8080, "end": 8090}],
    "protocols": ["TCP"],
    "payload_patterns": ["malicious.*pattern"]
  },
  "thresholds": {
    "connections_per_minute": 10
  }
}
```

### Production Deployment

#### HTTPS Configuration
```yaml
server:
  ssl:
    key-store: classpath:keystore.p12
    key-store-password: password
    key-store-type: PKCS12
    key-alias: tomcat
  port: 8443
```

#### External Database
```yaml
spring:
  datasource:
    url: jdbc:postgresql://db-server:5432/idsips
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
  jpa:
    hibernate:
      ddl-auto: validate
```

#### Reverse Proxy (Nginx)
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Performance Tuning

#### JVM Options
```bash
java -Xmx4g -Xms2g -XX:+UseG1GC -XX:MaxGCPauseMillis=200 \
  -jar target/ecc-ids-ips-1.0.0.jar
```

#### Application Tuning
```yaml
idsips:
  sensor:
    buffer-size: 131072
    capture-timeout: 500
  detection:
    max-alerts-per-minute: 200
```

### Integration Examples

#### SIEM Integration
Use the REST API to integrate with SIEM systems:
```python
import requests

# Get alerts
response = requests.get(
    'http://localhost:8080/api/v1/alerts',
    headers={'Authorization': f'Bearer {token}'}
)
alerts = response.json()

# Send to SIEM
for alert in alerts:
    send_to_siem(alert)
```

#### Automated Response
```bash
#!/bin/bash
# Script to automatically block IPs from external threat feed

THREAT_IPS=$(curl -s https://threat-feed.example.com/ips)

for ip in $THREAT_IPS; do
    curl -X POST http://localhost:8080/api/v1/block \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"ip\":\"$ip\",\"reason\":\"Threat feed\"}"
done
```

## 📞 Support

For additional help:
1. Check the [README.md](README.md) for overview
2. Review [SETUP.md](SETUP.md) for installation details
3. Consult [SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md) for technical details
4. Create an issue in the repository for bugs or feature requests

---

**Security Note**: Always change default passwords and JWT secrets in production environments. Regularly update the system and monitor security advisories.
