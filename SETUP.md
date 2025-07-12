# ECC-Secured IDS/IPS Setup Guide

This guide provides detailed instructions for setting up and configuring the ECC-Secured IDS/IPS system.

## 📋 System Requirements

### Hardware Requirements
- **CPU**: 2+ cores recommended
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 10GB free space
- **Network**: Administrative access to network interfaces

### Software Requirements
- **Java**: OpenJDK 17 or Oracle JDK 17+
- **Maven**: 3.6.0 or higher
- **Operating System**: Windows 10+, Linux, or macOS
- **Browser**: Modern web browser (Chrome, Firefox, Safari, Edge)

## 🔧 Installation Steps

### Step 1: Environment Setup

#### Install Java 17
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install openjdk-17-jdk

# CentOS/RHEL
sudo yum install java-17-openjdk-devel

# Windows
# Download from https://adoptium.net/
# Or use chocolatey: choco install openjdk17
```

#### Install Maven
```bash
# Ubuntu/Debian
sudo apt install maven

# CentOS/RHEL
sudo yum install maven

# Windows
# Download from https://maven.apache.org/
# Or use chocolatey: choco install maven
```

#### Verify Installation
```bash
java -version
mvn -version
```

### Step 2: Download and Build

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ecc-ids-ips
   ```

2. **Build the application**
   ```bash
   mvn clean compile
   ```

3. **Run tests (optional)**
   ```bash
   mvn test
   ```

4. **Package the application**
   ```bash
   mvn package
   ```

### Step 3: Configuration

#### Basic Configuration

Edit `src/main/resources/application.yml`:

```yaml
server:
  port: 8080  # Change if port 8080 is in use

idsips:
  security:
    jwt:
      secret: "CHANGE_THIS_SECRET_KEY_TO_SOMETHING_SECURE"
      expiration: 3600000  # 1 hour
    ecc:
      algorithm: secp256r1
  
  sensor:
    enabled: true
    interface: "any"  # or specific interface like "eth0"
    
  detection:
    enabled: true
    max-alerts-per-minute: 100
    
  prevention:
    enabled: true
    auto-block: true
    block-duration: 3600  # 1 hour
```

#### Network Interface Configuration

To find available network interfaces:

**Linux:**
```bash
ip link show
# or
ifconfig -a
```

**Windows:**
```cmd
ipconfig /all
```

**macOS:**
```bash
ifconfig -a
```

Update the `interface` setting in `application.yml` with the desired interface name.

#### Security Configuration

1. **Change Default Passwords**
   
   Edit `src/main/java/com/security/idsips/security/CustomUserDetailsService.java`:
   ```java
   private void initializeUsers() {
       users.put("admin", passwordEncoder.encode("YOUR_SECURE_PASSWORD"));
       users.put("operator", passwordEncoder.encode("OPERATOR_PASSWORD"));
   }
   ```

2. **Update JWT Secret**
   
   Generate a secure secret key:
   ```bash
   openssl rand -base64 64
   ```
   
   Update the `jwt.secret` in `application.yml`.

3. **Configure HTTPS (Production)**
   
   Add SSL configuration to `application.yml`:
   ```yaml
   server:
     ssl:
       key-store: classpath:keystore.p12
       key-store-password: password
       key-store-type: PKCS12
       key-alias: tomcat
   ```

### Step 4: Database Configuration (Optional)

By default, the system uses H2 in-memory database. For production, configure a persistent database:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/idsips
    username: idsips_user
    password: secure_password
    driver-class-name: org.postgresql.Driver
  
  jpa:
    database-platform: org.hibernate.dialect.PostgreSQLDialect
    hibernate:
      ddl-auto: update
```

Add the database dependency to `pom.xml`:
```xml
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <scope>runtime</scope>
</dependency>
```

### Step 5: Detection Rules Configuration

Customize detection rules in `src/main/resources/detection-rules.json`:

```json
[
  {
    "rule_id": "CUSTOM_001",
    "name": "Custom Port Scan Detection",
    "description": "Detects scanning of specific ports",
    "severity": "HIGH",
    "alert_type": "PORT_SCAN",
    "enabled": true,
    "conditions": {
      "port_ranges": [
        {"start": 22, "end": 22},
        {"start": 80, "end": 80},
        {"start": 443, "end": 443}
      ],
      "protocols": ["TCP"]
    },
    "thresholds": {
      "connections_per_minute": 10
    }
  }
]
```

## 🚀 Running the Application

### Development Mode
```bash
mvn spring-boot:run
```

### Production Mode
```bash
java -jar target/ecc-ids-ips-1.0.0.jar
```

### With Custom Configuration
```bash
java -jar target/ecc-ids-ips-1.0.0.jar --spring.config.location=file:./config/application.yml
```

### As a Service (Linux)

Create a systemd service file `/etc/systemd/system/idsips.service`:

```ini
[Unit]
Description=ECC-Secured IDS/IPS
After=network.target

[Service]
Type=simple
User=idsips
ExecStart=/usr/bin/java -jar /opt/idsips/ecc-ids-ips-1.0.0.jar
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl enable idsips
sudo systemctl start idsips
sudo systemctl status idsips
```

## 🔍 Verification

### 1. Check Application Startup
```bash
curl http://localhost:8080/api/v1/health
```

Expected response:
```json
{
  "status": "UP",
  "timestamp": "2025-07-12T14:30:00Z"
}
```

### 2. Test Authentication
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### 3. Access Dashboard
Open browser to `http://localhost:8080` and login with admin credentials.

### 4. Check System Status
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8080/api/v1/system/status
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. Permission Denied (Network Capture)
**Problem**: Cannot capture network packets
**Solution**: 
- Run with administrator/root privileges
- Or enable simulation mode:
  ```yaml
  idsips:
    sensor:
      enabled: false  # Disables real packet capture
  ```

#### 2. Port Already in Use
**Problem**: Port 8080 is already in use
**Solution**: Change port in `application.yml`:
```yaml
server:
  port: 8081
```

#### 3. Out of Memory
**Problem**: Application runs out of memory
**Solution**: Increase JVM heap size:
```bash
java -Xmx2g -jar target/ecc-ids-ips-1.0.0.jar
```

#### 4. Database Connection Failed
**Problem**: Cannot connect to database
**Solution**: 
- Verify database is running
- Check connection parameters
- Ensure database user has proper permissions

### Log Analysis

Check application logs for errors:
```bash
tail -f logs/idsips.log
```

Enable debug logging:
```yaml
logging:
  level:
    com.security.idsips: DEBUG
```

## 📊 Performance Tuning

### JVM Options
```bash
java -Xmx4g -Xms2g -XX:+UseG1GC -XX:MaxGCPauseMillis=200 \
  -jar target/ecc-ids-ips-1.0.0.jar
```

### Application Tuning
```yaml
idsips:
  sensor:
    buffer-size: 131072  # Increase buffer size
    capture-timeout: 500  # Reduce timeout
  
  detection:
    max-alerts-per-minute: 200  # Increase if needed
```

## 🔒 Security Hardening

### 1. Network Security
- Run behind a reverse proxy (nginx, Apache)
- Use HTTPS in production
- Restrict access to management interfaces

### 2. Application Security
- Change default passwords
- Use strong JWT secrets
- Enable audit logging
- Regular security updates

### 3. System Security
- Run as non-root user
- Use firewall rules
- Monitor system logs
- Regular backups

## 📈 Monitoring and Maintenance

### Health Checks
Set up monitoring for:
- Application health endpoint
- System resource usage
- Alert generation rates
- Database performance

### Backup Strategy
- Database backups
- Configuration files
- Log files
- ECC keys (if persistent)

### Updates
- Monitor for security updates
- Test updates in staging environment
- Plan maintenance windows
- Document changes

## 🆘 Getting Help

If you encounter issues:

1. Check the troubleshooting section
2. Review application logs
3. Verify configuration settings
4. Test with minimal configuration
5. Create an issue with detailed information

For support, provide:
- Operating system and version
- Java version
- Application logs
- Configuration files (sanitized)
- Steps to reproduce the issue
