# ECC-Secured IDS/IPS System - Configuration Summary

All previously hardcoded values have been removed and made configurable through environment variables or configuration files.

## 📋 **Configuration Overview**

### ✅ **Removed Hardcoded Values**

| Component | Previous Hardcoded Value | Now Configurable As |
|-----------|-------------------------|-------------------|
| **Server Port** | `8080` | `SERVER_PORT` |
| **Database URL** | `jdbc:h2:mem:idsips` | `DATABASE_URL` |
| **Database Username** | `sa` | `DATABASE_USERNAME` |
| **Database Password** | `password` | `DATABASE_PASSWORD` |
| **JWT Secret** | `mySecretKey123...` | `JWT_SECRET` |
| **JWT Expiration** | `3600000` | `JWT_EXPIRATION` |
| **Admin Username** | `admin` | `ADMIN_USERNAME` |
| **Admin Password** | `admin123` | `ADMIN_PASSWORD` |
| **Operator Username** | `operator` | `OPERATOR_USERNAME` |
| **Operator Password** | `operator123` | `OPERATOR_PASSWORD` |
| **ECC Algorithm** | `secp256r1` | `ECC_ALGORITHM` |
| **ECC Key Size** | `256` | `ECC_KEY_SIZE` |
| **AES Key Length** | `16` | `ECC_AES_KEY_LENGTH` |
| **Ephemeral Key Length** | `91` | `ECC_EPHEMERAL_KEY_LENGTH` |
| **Sensor Interface** | `any` | `SENSOR_INTERFACE` |
| **Capture Timeout** | `1000` | `SENSOR_CAPTURE_TIMEOUT` |
| **Buffer Size** | `65536` | `SENSOR_BUFFER_SIZE` |
| **Simulation Interval** | `5000` | `SENSOR_SIMULATION_INTERVAL` |
| **Max Packet Size** | `1500` | `SENSOR_MAX_PACKET_SIZE` |
| **Min Packet Size** | `64` | `SENSOR_MIN_PACKET_SIZE` |
| **Detection Rules File** | `classpath:detection-rules.json` | `DETECTION_RULES_FILE` |
| **Max Alerts Per Minute** | `100` | `DETECTION_MAX_ALERTS_PER_MINUTE` |
| **Block Duration** | `3600` | `PREVENTION_BLOCK_DURATION` |

## 🔧 **Configuration Methods**

### Method 1: Environment Variables
```bash
export SERVER_PORT=9090
export ADMIN_PASSWORD="my-secure-password"
export JWT_SECRET="my-very-long-and-secure-secret-key"
java -jar target/ecc-ids-ips-1.0.0.jar
```

### Method 2: Configuration File (application.yml)
```yaml
server:
  port: 9090

idsips:
  security:
    jwt:
      secret: "my-very-long-and-secure-secret-key"
    users:
      admin:
        password: "my-secure-password"
```

### Method 3: Environment File (.env)
```bash
# Copy .env.template to .env and customize
cp .env.template .env
# Edit .env with your values
java -jar target/ecc-ids-ips-1.0.0.jar
```

## 🔒 **Security Configuration**

### Essential Security Changes for Production

1. **Change JWT Secret**
   ```bash
   export JWT_SECRET="$(openssl rand -base64 64)"
   ```

2. **Change Default Passwords**
   ```bash
   export ADMIN_PASSWORD="your-secure-admin-password"
   export OPERATOR_PASSWORD="your-secure-operator-password"
   ```

3. **Use External Database**
   ```bash
   export DATABASE_URL="jdbc:postgresql://localhost:5432/idsips"
   export DATABASE_USERNAME="idsips_user"
   export DATABASE_PASSWORD="secure-db-password"
   ```

## 🌐 **Environment-Specific Configurations**

### Development Environment
```bash
export SERVER_PORT=8080
export DATABASE_URL="jdbc:h2:mem:idsips"
export SENSOR_ENABLED=false
export SENSOR_SIMULATION_ENABLED=true
export DETECTION_ENABLED=true
export PREVENTION_ENABLED=true
```

### Production Environment
```bash
export SERVER_PORT=443
export DATABASE_URL="jdbc:postgresql://db-server:5432/idsips"
export DATABASE_USERNAME="idsips_prod"
export DATABASE_PASSWORD="$(cat /secrets/db-password)"
export JWT_SECRET="$(cat /secrets/jwt-secret)"
export ADMIN_PASSWORD="$(cat /secrets/admin-password)"
export SENSOR_ENABLED=true
export SENSOR_INTERFACE="eth0"
export SENSOR_SIMULATION_ENABLED=false
```

### Testing Environment
```bash
export SERVER_PORT=8081
export DATABASE_URL="jdbc:h2:mem:test"
export SENSOR_ENABLED=false
export SENSOR_SIMULATION_ENABLED=true
export SENSOR_SIMULATION_INTERVAL=1000
export DETECTION_MAX_ALERTS_PER_MINUTE=1000
```

## 📊 **Performance Tuning Configuration**

### High-Performance Setup
```bash
export SENSOR_BUFFER_SIZE=131072
export SENSOR_CAPTURE_TIMEOUT=500
export DETECTION_MAX_ALERTS_PER_MINUTE=500
export PREVENTION_BLOCK_DURATION=7200
```

### Low-Resource Setup
```bash
export SENSOR_BUFFER_SIZE=32768
export SENSOR_CAPTURE_TIMEOUT=2000
export DETECTION_MAX_ALERTS_PER_MINUTE=50
export SENSOR_SIMULATION_INTERVAL=10000
```

## 🔐 **Encryption Configuration**

### Standard Security (Default)
```bash
export ECC_ALGORITHM="secp256r1"
export ECC_KEY_SIZE=256
export ECC_AES_KEY_LENGTH=16
```

### High Security
```bash
export ECC_ALGORITHM="secp384r1"
export ECC_KEY_SIZE=384
export ECC_AES_KEY_LENGTH=24
export ECC_EPHEMERAL_KEY_LENGTH=120
```

### Maximum Security
```bash
export ECC_ALGORITHM="secp521r1"
export ECC_KEY_SIZE=521
export ECC_AES_KEY_LENGTH=32
export ECC_EPHEMERAL_KEY_LENGTH=158
```

## 🚀 **Quick Start Examples**

### 1. Default Development Setup
```bash
java -jar target/ecc-ids-ips-1.0.0.jar
# Uses all default values from application.yml
```

### 2. Custom Port and Credentials
```bash
export SERVER_PORT=9090
export ADMIN_PASSWORD="my-password"
java -jar target/ecc-ids-ips-1.0.0.jar
```

### 3. Production with External Database
```bash
export DATABASE_URL="jdbc:postgresql://localhost:5432/idsips"
export DATABASE_USERNAME="idsips_user"
export DATABASE_PASSWORD="secure-password"
export JWT_SECRET="very-long-secure-secret-key-for-production"
export ADMIN_PASSWORD="secure-admin-password"
java -jar target/ecc-ids-ips-1.0.0.jar
```

### 4. High-Security Configuration
```bash
export ECC_ALGORITHM="secp384r1"
export ECC_KEY_SIZE=384
export JWT_EXPIRATION=1800000  # 30 minutes
export PREVENTION_BLOCK_DURATION=86400  # 24 hours
java -jar target/ecc-ids-ips-1.0.0.jar
```

## 📝 **Configuration Validation**

The system validates all configuration values at startup:

- **Required values**: JWT secret, database credentials
- **Valid ranges**: Port numbers (1-65535), timeouts (>0)
- **Valid algorithms**: Supported ECC curves
- **Security checks**: Warns about default passwords in production

## 🔍 **Configuration Debugging**

Enable debug logging to see configuration values:
```bash
export LOGGING_LEVEL_COM_SECURITY_IDSIPS=DEBUG
java -jar target/ecc-ids-ips-1.0.0.jar
```

## 📚 **Related Documentation**

- **[USER_GUIDE.md](USER_GUIDE.md)**: Complete user guide with examples
- **[.env.template](.env.template)**: Template for environment configuration
- **[README.md](README.md)**: System overview and quick start
- **[SETUP.md](SETUP.md)**: Detailed installation instructions

## ✅ **Configuration Checklist**

Before deploying to production:

- [ ] Changed default JWT secret
- [ ] Changed default admin password
- [ ] Changed default operator password
- [ ] Configured external database (if needed)
- [ ] Set appropriate server port
- [ ] Configured network interface (if using real packet capture)
- [ ] Set appropriate security levels
- [ ] Configured logging levels
- [ ] Set up backup strategy
- [ ] Configured monitoring endpoints
- [ ] Tested all configurations

## 🎯 **Summary**

✅ **Zero hardcoded values** - Everything is configurable  
✅ **Environment variable support** - Easy deployment  
✅ **Configuration file support** - Flexible setup  
✅ **Security-first approach** - All secrets configurable  
✅ **Production-ready** - Supports external databases, HTTPS, etc.  
✅ **Performance tuning** - All performance parameters configurable  
✅ **Multiple deployment scenarios** - Dev, test, production ready  

The system is now **100% configurable** and ready for any deployment scenario!
