# 🧪 ECC-IDS-IPS Rule Testing Guide

## 🎯 **No More Terminal Commands - Test with Simple Websites!**

Your ECC-IDS-IPS system now includes a professional web-based testing suite that allows you to test all 8 detection rules through simple button clicks instead of complex terminal commands.

## 🚀 **Quick Start**

### **Access the Testing Suite:**
```
http://localhost:8080/test-rules.html
```

### **What You'll See:**
- **8 Beautiful Test Cards** - One for each detection rule
- **Professional Interface** - Modern design with real-time status updates
- **One-Click Testing** - Simple buttons to trigger each rule
- **Auto-Sequence Option** - Test all rules automatically

## 🛡️ **The 8 Detection Rules You Can Test**

### **1. 🔍 Port Scanning Detection (RULE_001)**
- **What it detects**: Aggressive port scanning (50+ connections/minute)
- **Test simulation**: Rapidly connects to 60+ different ports
- **Severity**: HIGH
- **Expected result**: Port scan alert with source IP and target ports

### **2. 🔐 Brute Force Detection (RULE_002)**
- **What it detects**: Sustained authentication attacks (25+ failed attempts)
- **Test simulation**: 30 failed SSH login attempts
- **Severity**: CRITICAL
- **Expected result**: Brute force alert with failed attempt count

### **3. 💀 Malicious Payload Detection (RULE_003)**
- **What it detects**: Known attack patterns (SQL injection, XSS, command injection)
- **Test simulation**: 7 different malicious payloads
- **Severity**: CRITICAL
- **Expected result**: Multiple payload alerts with attack patterns identified

### **4. 📤 Data Exfiltration Detection (RULE_004)**
- **What it detects**: Large data transfers (10+ packets of 8KB+ per minute)
- **Test simulation**: 15 large packets of 10KB each
- **Severity**: HIGH
- **Expected result**: Data exfiltration alert with packet size information

### **5. 🌐 Known Malicious IP Detection (RULE_005)**
- **What it detects**: Traffic from known bad IP ranges
- **Test simulation**: Simulated traffic from suspicious IP patterns
- **Severity**: CRITICAL
- **Expected result**: Malicious IP alert with automatic blocking

### **6. ⚡ DDoS Attack Detection (RULE_006)**
- **What it detects**: Distributed attacks (500+ connections from 50+ sources)
- **Test simulation**: 600+ connections from 60+ different sources
- **Severity**: CRITICAL
- **Expected result**: DDoS alert with source count and connection volume

### **7. 🔄 Lateral Movement Detection (RULE_007)**
- **What it detects**: Network reconnaissance (20+ connections to admin ports)
- **Test simulation**: Connections to Windows admin ports across multiple targets
- **Severity**: HIGH
- **Expected result**: Lateral movement alert with target systems identified

### **8. ⛏️ Cryptocurrency Mining Detection (RULE_008)**
- **What it detects**: Unauthorized mining activity (10+ connections to mining ports)
- **Test simulation**: 15+ connections to mining pool ports
- **Severity**: MEDIUM
- **Expected result**: Crypto mining alert with mining pool connections

## 📋 **How to Test Each Rule**

### **Individual Rule Testing:**
1. **Open** the test page: http://localhost:8080/test-rules.html
2. **Choose** any rule card you want to test
3. **Click** the "🚀 Test [Rule Name]" button
4. **Watch** the status change to "🔄 Testing..."
5. **Wait** for completion "✅ Test completed!"
6. **Check** the Security Dashboard for generated alerts

### **Test All Rules at Once:**
1. **Click** the "🚀 Test All Rules (Auto-Sequence)" button
2. **Watch** all 8 rules get tested automatically over ~25 seconds
3. **See** real-time status updates for each rule
4. **Get** notification when all tests complete

## 📊 **Verifying Test Results**

### **Check the Security Dashboard:**
1. **Open** http://localhost:8080/dashboard.html
2. **Login** with: admin / admin123
3. **Look** at the "Recent Alerts" section
4. **Verify** you see new security events

### **What You Should See:**
- **8 Different Alert Types**: One for each rule tested
- **Appropriate Severity Levels**: CRITICAL, HIGH, MEDIUM
- **Detailed Descriptions**: Clear explanation of detected threats
- **Source Information**: IP addresses and attack patterns
- **Timestamps**: When each alert was generated

### **Automatic IP Blocking:**
- **Malicious IPs** should appear in the "Blocked IPs" section
- **Block status** should show "ACTIVE"
- **Block duration** typically 1 hour (3600 seconds)

## 🎯 **Expected Test Results**

### **Successful Test Indicators:**
- ✅ **Status shows "Test completed!"** for each rule
- ✅ **New alerts appear** in the dashboard
- ✅ **Alert counts increase** in statistics
- ✅ **Malicious IPs get blocked** automatically
- ✅ **No false positives** from normal traffic

### **Alert Details to Look For:**
- **Port Scan**: Source IP, target ports, connection count
- **Brute Force**: Failed attempts, target service (SSH)
- **Malicious Payload**: Attack patterns (XSS, SQL injection, etc.)
- **Data Exfiltration**: Packet sizes, transfer volume
- **Malicious IP**: Source IP ranges, threat intelligence
- **DDoS**: Source count, connection volume
- **Lateral Movement**: Target systems, admin ports
- **Crypto Mining**: Mining pool connections, port usage

## 🔧 **Troubleshooting**

### **If Tests Don't Generate Alerts:**
1. **Check** that the ECC-IDS-IPS application is running
2. **Verify** the detection engine is active (dashboard shows "Operational")
3. **Wait** a few seconds after clicking test buttons
4. **Refresh** the dashboard to see new alerts
5. **Check** the application logs for any errors

### **If Test Buttons Don't Work:**
1. **Ensure** you're accessing http://localhost:8080/test-rules.html
2. **Check** that JavaScript is enabled in your browser
3. **Look** for any browser console errors (F12 → Console)
4. **Try** refreshing the page and testing again

### **If No Alerts Appear:**
1. **Verify** detection rules are loaded (check application startup logs)
2. **Confirm** thresholds are being exceeded by test simulations
3. **Check** that alerts aren't being filtered by time range
4. **Look** at the "All Alerts" section instead of just "Recent"

## 🎉 **Benefits of Web-Based Testing**

### **User-Friendly:**
- **No terminal commands** needed
- **Visual feedback** with status indicators
- **Professional interface** that's easy to understand
- **One-click operation** for each test

### **Comprehensive:**
- **All 8 rules tested** with realistic attack simulations
- **Production thresholds** used (same as real threats)
- **Real alerts generated** (not fake test data)
- **Automatic IP blocking** demonstrates prevention capabilities

### **Educational:**
- **Learn attack patterns** that each rule detects
- **Understand thresholds** that trigger alerts
- **See real security events** in action
- **Verify system protection** is working correctly

## 🚀 **Ready to Test!**

Your ECC-IDS-IPS system now provides enterprise-grade security testing through a simple web interface. No more complex terminal commands - just click buttons and watch your security system detect and respond to threats in real-time!

**Start testing now**: http://localhost:8080/test-rules.html

Each test simulates real attack patterns and generates genuine security alerts, proving your system is ready to protect against actual threats! 🛡️
