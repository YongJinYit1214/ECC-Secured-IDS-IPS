# 🛡️ ECC-Secured IDS/IPS System

[![Java](https://img.shields.io/badge/Java-17+-orange.svg)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2+-green.svg)](https://spring.io/projects/spring-boot)
[![Security](https://img.shields.io/badge/Security-ECC%20Encryption-blue.svg)](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Testing](https://img.shields.io/badge/Testing-Web%20Based-purple.svg)](http://localhost:8080/test-rules.html)

A **production-ready** Intrusion Detection and Prevention System (IDS/IPS) with advanced **Elliptic Curve Cryptography (ECC)** encryption, designed for enterprise-grade threat monitoring and automated response. Features **web-based rule testing** and **zero false positive** detection.

## 🚀 **Quick Demo**

### **Web-Based Rule Testing Suite**
Test all 8 detection rules with simple button clicks - no terminal commands needed!

```
http://localhost:8080/test-rules.html
```

### **Professional Security Dashboard**
Monitor threats in real-time with enterprise-grade interface:

```
http://localhost:8080/dashboard.html
Login: admin / admin123
```

## 🔒 **Key Features**

### 🛡️ Production-Grade Security
- **Real-time Network Monitoring**: Live packet capture using Npcap with enterprise-grade performance
- **Advanced ECC Encryption**: secp256r1 curve for all sensitive data protection
- **Intelligent Threat Detection**: 8 sophisticated detection rules tuned for production environments
- **Automated Response System**: Smart IP blocking with configurable timeouts and whitelisting
- **Zero False Positive Design**: Production-tuned thresholds eliminate alert fatigue

### 🚨 Enterprise Detection Capabilities
- **Advanced Port Scanning Detection**: Detects aggressive reconnaissance (50+ connections/min)
- **Brute Force Prevention**: Monitors sustained attacks (25+ failed attempts)
- **Malicious Payload Detection**: SQL injection, XSS, command injection patterns
- **Data Exfiltration Detection**: Large data transfer monitoring (8KB+ packets)
- **DDoS Attack Detection**: Distributed attack identification (500+ connections from 50+ sources)
- **Lateral Movement Detection**: Network reconnaissance pattern analysis
- **Cryptocurrency Mining Detection**: Unauthorized mining activity monitoring
- **Known Malicious IP Blocking**: Real-time threat intelligence integration

### 📊 Professional Management
- **Interactive Security Dashboard**: Real-time threat visualization with charts and metrics
- **Comprehensive API**: RESTful API for enterprise integration and automation
- **Audit Trail**: Complete security event logging and compliance reporting
- **Role-Based Access Control**: Multi-level security access management

## 🏗️ Architecture

The system consists of the following components:

1. **Network Sensor**: Captures and analyzes network packets
2. **Detection Engine**: Applies rules to identify security threats
3. **ECC Encryption Layer**: Encrypts sensitive alerts and logs
4. **Prevention System**: Automatically blocks malicious IPs
5. **REST API Backend**: Handles secure communications
6. **Admin Dashboard**: Web interface for monitoring and management

## 🚀 Quick Start

### Prerequisites

- Java 17 or higher
- Maven 3.6 or higher
- Administrative privileges (for network packet capture)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/YongJinYit1214/ECC-Secured-IDS-IPS.git
   cd ECC-Secured-IDS-IPS
   ```

2. **Build the application**
   ```bash
   mvn clean compile
   ```

3. **Run the application**
   ```bash
   mvn spring-boot:run
   ```

4. **Access the system**
   - **Security Dashboard**: `http://localhost:8080/dashboard.html`
   - **Rule Testing Suite**: `http://localhost:8080/test-rules.html`
   - Login with default credentials:
     - Username: `admin`
     - Password: `admin123`

## 🧪 **Web-Based Rule Testing** (No Terminal Commands!)

### **Test All 8 Detection Rules with Simple Button Clicks**

Access the testing suite at: `http://localhost:8080/test-rules.html`

**Available Tests:**
- 🔍 **Port Scanning Detection** - Simulates aggressive port scanning
- 🔐 **Brute Force Detection** - Tests authentication attack detection
- 💀 **Malicious Payload Detection** - Tests SQL injection, XSS, command injection
- 📤 **Data Exfiltration Detection** - Tests large data transfer monitoring
- 🌐 **Known Malicious IP Detection** - Tests threat intelligence blocking
- ⚡ **DDoS Attack Detection** - Tests distributed attack identification
- 🔄 **Lateral Movement Detection** - Tests network reconnaissance detection
- ⛏️ **Cryptocurrency Mining Detection** - Tests unauthorized mining detection

**Features:**
- ✅ **One-click testing** for each rule
- ✅ **Real-time status updates** with visual feedback
- ✅ **Auto-sequence option** to test all rules automatically
- ✅ **Production-realistic thresholds** - same as real threats
- ✅ **Generates actual alerts** in the security dashboard

## 🚀 Enhanced Setup for Real Network Monitoring

### Prerequisites for Real Packet Capture
- **Windows**: Install [Npcap](https://npcap.com/) (successor to WinPcap)
- **Linux**: Install libpcap-dev (`sudo apt-get install libpcap-dev`)
- **macOS**: Install libpcap (usually pre-installed)

### Npcap Installation (Windows)
1. Download Npcap from https://npcap.com/
2. Run installer as **Administrator**
3. **Important**: Check "Install Npcap in WinPcap API-compatible Mode"
4. Restart your computer after installation

### Running with Real Network Monitoring
```bash
# Windows PowerShell
$env:SENSOR_ENABLED="true"
$env:SENSOR_INTERFACE="any"
java -jar target/ecc-ids-ips-1.0.0.jar

# Linux/macOS
export SENSOR_ENABLED=true
export SENSOR_INTERFACE=any
java -jar target/ecc-ids-ips-1.0.0.jar
```

## 📦 User Distribution

### For End Users (One-Click Installation)

Your ECC-IDS-IPS system can be easily distributed to users for automatic installation and real-time protection:

#### Windows Users:
1. **Download** the distribution package
2. **Right-click** `install-security.bat` → "Run as administrator"
3. **Follow** the installation wizard
4. **Access** dashboard at http://localhost:8080 (admin/admin123)

#### PowerShell Users:
```powershell
# Run as Administrator
.\Install-Security.ps1 -Service -AutoStart
```

#### What Users Get:
- ✅ **Real-time network protection** - Automatic threat detection and blocking
- ✅ **Automatic IP blocking** - Malicious addresses blocked instantly
- ✅ **Professional dashboard** - Security monitoring interface at localhost:8080
- ✅ **Zero configuration** - Works out-of-the-box with production-tuned rules
- ✅ **Windows Service option** - Auto-start with Windows for continuous protection
- ✅ **Desktop shortcuts** - Easy access to security monitor
- ✅ **Zero false positives** - Only genuine threats trigger alerts

#### User Experience:
- **Silent Operation**: Runs in background, no user intervention needed
- **Smart Detection**: Production thresholds eliminate false alarms
- **Instant Protection**: Malicious IPs blocked automatically
- **Professional Interface**: Clean, actionable security dashboard

See **[User Distribution Guide](USER_DISTRIBUTION_GUIDE.md)** for complete packaging and distribution instructions.

## 🧪 Testing the System

### Quick Test - Manual IP Blocking
```powershell
# Get authentication token
$response = Invoke-WebRequest -Uri "http://localhost:8080/api/v1/auth/login" -Method POST -ContentType "application/json" -Body '{"username":"admin","password":"admin123"}'
$token = ($response.Content | ConvertFrom-Json).token

# Block a suspicious IP
$headers = @{"Authorization"="Bearer $token"; "Content-Type"="application/json"}
$blockData = '{"ip":"192.168.1.100","reason":"Port scanning detected"}'
Invoke-WebRequest -Uri "http://localhost:8080/api/v1/block" -Method POST -Headers $headers -Body $blockData
```

### Advanced Testing - Trigger Detection Rules

#### 1. Port Scanning Detection
**Production Threshold**: 50+ connections per minute to trigger alerts
```powershell
# Simulate aggressive port scanning (requires sustained activity)
for ($i=1; $i -le 60; $i++) {
    $port = Get-Random -Minimum 1 -Maximum 1024
    Test-NetConnection -ComputerName "google.com" -Port $port -WarningAction SilentlyContinue
    Start-Sleep -Milliseconds 50  # Rapid scanning to trigger threshold
}
```

#### 2. Brute Force Detection
**Production Threshold**: 25+ failed attempts to trigger alerts
```powershell
# Simulate sustained brute force attack
for ($i=1; $i -le 30; $i++) {
    Test-NetConnection -ComputerName "github.com" -Port 22 -WarningAction SilentlyContinue
    Test-NetConnection -ComputerName "google.com" -Port 3389 -WarningAction SilentlyContinue
    Test-NetConnection -ComputerName "example.com" -Port 21 -WarningAction SilentlyContinue
}
```

#### 3. Data Exfiltration Detection
**Production Threshold**: 8KB+ packets to trigger alerts
```powershell
# Generate large data transfers
Invoke-WebRequest -Uri "https://httpbin.org/bytes/10000" -OutFile "large1.dat"
Invoke-WebRequest -Uri "https://httpbin.org/bytes/12000" -OutFile "large2.dat"
Invoke-WebRequest -Uri "https://httpbin.org/bytes/15000" -OutFile "large3.dat"
```

#### 4. Multiple Rapid Connections
```powershell
# Rapid connection attempts
1..30 | ForEach-Object {
    Test-NetConnection -ComputerName "github.com" -Port 443 -WarningAction SilentlyContinue
}
```

### Expected Results
After running tests, refresh your dashboard (`http://localhost:8080`) to see:
- 🚨 **Security Alerts** in the alerts section
- 🚫 **Blocked IPs** in the blocked IPs section
- 📊 **Updated Statistics** in the overview
- 📈 **Real-time packet analysis** data

## 📚 Documentation

- **[Production Guide](PRODUCTION_GUIDE.md)** - Enterprise deployment and production configuration
- **[User Distribution Guide](USER_DISTRIBUTION_GUIDE.md)** - How to package and distribute to end users
- **[User Guide](USER_GUIDE.md)** - Comprehensive usage instructions and operation
- **[Testing Guide](TESTING_GUIDE.md)** - Production testing procedures and verification
- **[Setup Guide](SETUP.md)** - Installation and configuration details

### Quick Verification
```powershell
# Check system status
$response = Invoke-WebRequest -Uri "http://localhost:8080/api/v1/system/status" -Headers @{"Authorization"="Bearer $token"}
$response.Content | ConvertFrom-Json
```

**🎯 For comprehensive testing procedures, see [TESTING_GUIDE.md](TESTING_GUIDE.md)**

## 🔧 Configuration

### Application Configuration

Edit `src/main/resources/application.yml`:

```yaml
idsips:
  security:
    jwt:
      secret: mySecretKey123456789012345678901234567890
      expiration: 3600000 # 1 hour
    ecc:
      key-size: 256
      algorithm: secp256r1
  
  sensor:
    enabled: true
    interface: any # Network interface to monitor
    capture-timeout: 1000
    buffer-size: 65536
  
  detection:
    enabled: true
    rules-file: classpath:detection-rules.json
    max-alerts-per-minute: 100
  
  prevention:
    enabled: true
    auto-block: true
    block-duration: 3600 # seconds
```

### Production Detection Rules

The system includes 8 production-tuned detection rules in `src/main/resources/detection-rules.json`:

```json
[
  {
    "rule_id": "RULE_001",
    "name": "Port Scanning Detection",
    "description": "Detects aggressive port scanning activity indicating reconnaissance",
    "severity": "HIGH",
    "alert_type": "PORT_SCAN",
    "enabled": true,
    "conditions": {
      "port_ranges": [
        {"start": 1, "end": 1024},
        {"start": 3389, "end": 3389},
        {"start": 5900, "end": 5900}
      ],
      "protocols": ["TCP"]
    },
    "thresholds": {
      "connections_per_minute": 50
    }
  },
  {
    "rule_id": "RULE_002",
    "name": "Brute Force Detection",
    "description": "Detects sustained brute force attacks on authentication services",
    "severity": "CRITICAL",
    "alert_type": "BRUTE_FORCE",
    "enabled": true,
    "conditions": {
      "port_ranges": [
        {"start": 22, "end": 22},
        {"start": 21, "end": 21},
        {"start": 3389, "end": 3389},
        {"start": 1433, "end": 1433},
        {"start": 3306, "end": 3306}
      ],
      "protocols": ["TCP"]
    },
    "thresholds": {
      "failed_attempts": 25
    }
  }
]
```

**Key Production Features:**
- **Higher Thresholds**: Eliminates false positives from normal network activity
- **Targeted Monitoring**: Focuses on critical services and attack vectors
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW for proper prioritization
- **Comprehensive Coverage**: 8 rules covering modern attack patterns

## 📡 API Documentation

### Authentication

**POST** `/api/v1/auth/login`
```json
{
  "username": "admin",
  "password": "admin123"
}
```

Response:
```json
{
  "token": "jwt_token_here",
  "expires_in": 3600
}
```

### Alerts Management

**GET** `/api/v1/alerts` - Retrieve encrypted alerts
**POST** `/api/v1/alerts/decrypt` - Decrypt alert details
**PUT** `/api/v1/alerts/{alertId}/status` - Update alert status

### IP Blocking

**POST** `/api/v1/block` - Block an IP address
**DELETE** `/api/v1/block/{ip}` - Unblock an IP address
**GET** `/api/v1/block` - List blocked IPs

### System Status

**GET** `/api/v1/system/status` - Get system health and statistics
**GET** `/api/v1/ecc/public-key` - Get ECC public key

## 🔐 Security Features

### ECC Encryption

- **Algorithm**: secp256r1 (NIST P-256)
- **Key Management**: Automatic key generation and rotation
- **Data Protection**: All alerts and logs encrypted before storage
- **Secure Communication**: ECC-encrypted API communications

### Authentication & Authorization

- **JWT Tokens**: Secure session management
- **Role-Based Access**: Admin and operator roles
- **Audit Logging**: All actions logged and monitored

### Network Security

- **Packet Capture**: Real-time network monitoring
- **Threat Detection**: Multiple detection algorithms
- **Automatic Response**: IP blocking and prevention

## 🧪 Testing

### Run Unit Tests
```bash
mvn test
```

### Run Integration Tests
```bash
mvn verify
```

### Test Coverage
```bash
mvn jacoco:report
```

## 📊 Monitoring

### Dashboard Features

- **Real-time Alerts**: Live security alert monitoring
- **System Status**: Component health and statistics
- **IP Management**: Block/unblock IP addresses
- **Alert Analysis**: Decrypt and analyze security events

### Metrics

- Active alerts count
- Blocked IPs count
- Packets analyzed
- System uptime
- Detection rule statistics

## 🔧 Troubleshooting

### Common Issues

1. **Permission Denied (Packet Capture)**
   - Run with administrator privileges
   - Or enable simulation mode in configuration

2. **Port Already in Use**
   - Change server port in `application.yml`
   - Kill existing processes using the port

3. **ECC Initialization Failed**
   - Ensure Bouncy Castle provider is available
   - Check Java cryptography policies

### Logs

Application logs are written to:
- Console output
- `logs/idsips.log` file

Log levels can be configured in `application.yml`:
```yaml
logging:
  level:
    com.security.idsips: DEBUG
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the API documentation

## 🔄 Version History

- **v1.0.0**: Production-ready release with enterprise-grade security
  - **8 Production-Tuned Detection Rules**: Zero false positive design
  - **Real-Time Network Monitoring**: Live packet capture with Npcap
  - **Advanced Threat Detection**: Port scanning, brute force, DDoS, data exfiltration
  - **Intelligent Automated Response**: Smart IP blocking with configurable timeouts
  - **Military-Grade ECC Encryption**: secp256r1 curve for all sensitive data
  - **Professional Security Dashboard**: Interactive charts and real-time metrics
  - **Enterprise API Integration**: Complete RESTful API for SIEM platforms
  - **Production Documentation**: Comprehensive deployment and operation guides
