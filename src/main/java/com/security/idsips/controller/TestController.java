package com.security.idsips.controller;

import com.security.idsips.detection.DetectionEngine;
import com.security.idsips.sensor.NetworkPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Controller for testing detection rules with simulated attacks
 */
@RestController
@RequestMapping("/api/v1/test")
public class TestController {
    
    private static final Logger logger = LoggerFactory.getLogger(TestController.class);
    
    @Autowired
    private DetectionEngine detectionEngine;
    
    /**
     * Test malicious IP detection
     */
    @PostMapping("/malicious-ip")
    public ResponseEntity<String> testMaliciousIP(@RequestBody Map<String, String> request) {
        try {
            String sourceIP = request.get("source_ip");
            logger.info("🧪 Testing malicious IP detection with IP: {}", sourceIP);
            
            // Create a test packet from malicious IP
            NetworkPacket testPacket = new NetworkPacket();
            testPacket.setSourceIp(sourceIP);
            testPacket.setDestinationIp("192.168.1.100");
            testPacket.setSourcePort(12345);
            testPacket.setDestinationPort(80);
            testPacket.setProtocol("TCP");
            testPacket.setPayload("GET / HTTP/1.1\r\nHost: target.com\r\n\r\n");
            testPacket.setTimestamp(LocalDateTime.now());
            
            // Process through detection engine
            detectionEngine.analyzePacket(testPacket);
            
            return ResponseEntity.ok("Malicious IP test completed");
        } catch (Exception e) {
            logger.error("Error in malicious IP test", e);
            return ResponseEntity.ok("Test completed with errors");
        }
    }
    
    /**
     * Test port scanning detection
     */
    @PostMapping("/port-scan")
    public ResponseEntity<String> testPortScanning() {
        CompletableFuture.runAsync(() -> {
            try {
                logger.info("🧪 Testing port scanning detection");
                
                // Simulate rapid port scanning
                String sourceIP = "192.168.1.50";
                int[] ports = {22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900};
                
                for (int i = 0; i < 60; i++) { // Exceed threshold of 50
                    for (int port : ports) {
                        NetworkPacket packet = new NetworkPacket();
                        packet.setSourceIp(sourceIP);
                        packet.setDestinationIp("192.168.1.100");
                        packet.setSourcePort(12345 + i);
                        packet.setDestinationPort(port);
                        packet.setProtocol("TCP");
                        packet.setPayload("SYN");
                        packet.setTimestamp(LocalDateTime.now());
                        
                        detectionEngine.analyzePacket(packet);
                        
                        // Small delay to simulate rapid scanning
                        Thread.sleep(10);
                    }
                }
                
                logger.info("✅ Port scanning test completed");
            } catch (Exception e) {
                logger.error("Error in port scanning test", e);
            }
        });
        
        return ResponseEntity.ok("Port scanning test started");
    }
    
    /**
     * Test brute force detection
     */
    @PostMapping("/brute-force")
    public ResponseEntity<String> testBruteForce() {
        CompletableFuture.runAsync(() -> {
            try {
                logger.info("🧪 Testing brute force detection");
                
                String sourceIP = "192.168.1.60";
                
                // Simulate failed SSH login attempts
                for (int i = 0; i < 30; i++) { // Exceed threshold of 25
                    NetworkPacket packet = new NetworkPacket();
                    packet.setSourceIp(sourceIP);
                    packet.setDestinationIp("192.168.1.100");
                    packet.setSourcePort(12345 + i);
                    packet.setDestinationPort(22); // SSH port
                    packet.setProtocol("TCP");
                    packet.setPayload("SSH-2.0-OpenSSH_7.4\nuser" + i + "\nwrongpass" + i);
                    packet.setTimestamp(LocalDateTime.now());
                    
                    detectionEngine.analyzePacket(packet);
                    Thread.sleep(50);
                }
                
                logger.info("✅ Brute force test completed");
            } catch (Exception e) {
                logger.error("Error in brute force test", e);
            }
        });
        
        return ResponseEntity.ok("Brute force test started");
    }
    
    /**
     * Test malicious payload detection
     */
    @PostMapping("/malicious-payload")
    public ResponseEntity<String> testMaliciousPayload() {
        CompletableFuture.runAsync(() -> {
            try {
                logger.info("🧪 Testing malicious payload detection");
                
                String sourceIP = "192.168.1.70";
                String[] payloads = {
                    "<script>alert('XSS')</script>",
                    "' UNION SELECT * FROM users--",
                    "cmd.exe /c dir",
                    "eval(malicious_code)",
                    "DROP TABLE users;",
                    "cat /etc/passwd",
                    "powershell -enc base64payload"
                };
                
                for (String payload : payloads) {
                    NetworkPacket packet = new NetworkPacket();
                    packet.setSourceIp(sourceIP);
                    packet.setDestinationIp("192.168.1.100");
                    packet.setSourcePort(12345);
                    packet.setDestinationPort(80);
                    packet.setProtocol("TCP");
                    packet.setPayload("GET /?q=" + payload + " HTTP/1.1\r\nHost: target.com\r\n\r\n");
                    packet.setTimestamp(LocalDateTime.now());
                    
                    detectionEngine.analyzePacket(packet);
                    Thread.sleep(100);
                }
                
                logger.info("✅ Malicious payload test completed");
            } catch (Exception e) {
                logger.error("Error in malicious payload test", e);
            }
        });
        
        return ResponseEntity.ok("Malicious payload test started");
    }
    
    /**
     * Test data exfiltration detection
     */
    @PostMapping("/data-exfiltration")
    public ResponseEntity<String> testDataExfiltration() {
        CompletableFuture.runAsync(() -> {
            try {
                logger.info("🧪 Testing data exfiltration detection");
                
                String sourceIP = "192.168.1.80";
                
                // Generate large packets to simulate data exfiltration
                for (int i = 0; i < 15; i++) { // Exceed threshold of 10
                    NetworkPacket packet = new NetworkPacket();
                    packet.setSourceIp(sourceIP);
                    packet.setDestinationIp("192.168.1.100");
                    packet.setSourcePort(12345);
                    packet.setDestinationPort(443);
                    packet.setProtocol("TCP");

                    // Create large payload (10KB)
                    StringBuilder largePayload = new StringBuilder();
                    for (int j = 0; j < 10240; j++) {
                        largePayload.append((char) ('A' + (j % 26)));
                    }
                    packet.setPayload(largePayload.toString());
                    packet.setPacketSize(largePayload.length());
                    packet.setTimestamp(LocalDateTime.now());
                    
                    detectionEngine.analyzePacket(packet);
                    Thread.sleep(200);
                }
                
                logger.info("✅ Data exfiltration test completed");
            } catch (Exception e) {
                logger.error("Error in data exfiltration test", e);
            }
        });
        
        return ResponseEntity.ok("Data exfiltration test started");
    }
    
    /**
     * Test DDoS detection
     */
    @PostMapping("/ddos")
    public ResponseEntity<String> testDDoS() {
        CompletableFuture.runAsync(() -> {
            try {
                logger.info("🧪 Testing DDoS detection");
                
                // Simulate traffic from multiple sources
                for (int source = 1; source <= 60; source++) { // Exceed threshold of 50 sources
                    String sourceIP = "10.0.0." + source;
                    
                    for (int req = 0; req < 10; req++) {
                        NetworkPacket packet = new NetworkPacket();
                        packet.setSourceIp(sourceIP);
                        packet.setDestinationIp("192.168.1.100");
                        packet.setSourcePort(12345 + req);
                        packet.setDestinationPort(80);
                        packet.setProtocol("TCP");
                        packet.setPayload("GET / HTTP/1.1\r\nHost: target.com\r\n\r\n");
                        packet.setTimestamp(LocalDateTime.now());
                        
                        detectionEngine.analyzePacket(packet);
                    }
                    
                    Thread.sleep(20);
                }
                
                logger.info("✅ DDoS test completed");
            } catch (Exception e) {
                logger.error("Error in DDoS test", e);
            }
        });
        
        return ResponseEntity.ok("DDoS test started");
    }
    
    /**
     * Test lateral movement detection
     */
    @PostMapping("/lateral-movement")
    public ResponseEntity<String> testLateralMovement() {
        CompletableFuture.runAsync(() -> {
            try {
                logger.info("🧪 Testing lateral movement detection");
                
                String sourceIP = "192.168.1.90";
                int[] adminPorts = {135, 139, 445, 5985, 5986};
                String[] targets = {"192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40", "192.168.1.50", "192.168.1.60"};
                
                for (String target : targets) {
                    for (int port : adminPorts) {
                        NetworkPacket packet = new NetworkPacket();
                        packet.setSourceIp(sourceIP);
                        packet.setDestinationIp(target);
                        packet.setSourcePort(12345);
                        packet.setDestinationPort(port);
                        packet.setProtocol("TCP");
                        packet.setPayload("SMB negotiation");
                        packet.setTimestamp(LocalDateTime.now());
                        
                        detectionEngine.analyzePacket(packet);
                        Thread.sleep(100);
                    }
                }
                
                logger.info("✅ Lateral movement test completed");
            } catch (Exception e) {
                logger.error("Error in lateral movement test", e);
            }
        });
        
        return ResponseEntity.ok("Lateral movement test started");
    }
    
    /**
     * Test cryptocurrency mining detection
     */
    @PostMapping("/crypto-mining")
    public ResponseEntity<String> testCryptoMining() {
        CompletableFuture.runAsync(() -> {
            try {
                logger.info("🧪 Testing cryptocurrency mining detection");
                
                String sourceIP = "192.168.1.95";
                int[] miningPorts = {4444, 8333, 9999};
                
                for (int i = 0; i < 15; i++) { // Exceed threshold of 10
                    for (int port : miningPorts) {
                        NetworkPacket packet = new NetworkPacket();
                        packet.setSourceIp(sourceIP);
                        packet.setDestinationIp("mining-pool.example.com");
                        packet.setSourcePort(12345 + i);
                        packet.setDestinationPort(port);
                        packet.setProtocol("TCP");
                        packet.setPayload("stratum mining protocol");
                        packet.setTimestamp(LocalDateTime.now());
                        
                        detectionEngine.analyzePacket(packet);
                        Thread.sleep(200);
                    }
                }
                
                logger.info("✅ Cryptocurrency mining test completed");
            } catch (Exception e) {
                logger.error("Error in cryptocurrency mining test", e);
            }
        });
        
        return ResponseEntity.ok("Cryptocurrency mining test started");
    }
    
    /**
     * Run all tests sequentially
     */
    @PostMapping("/run-all")
    public ResponseEntity<String> runAllTests() {
        CompletableFuture.runAsync(() -> {
            try {
                logger.info("🧪 Running all detection rule tests");
                
                testMaliciousIP(Map.of("source_ip", "185.220.100.240"));
                Thread.sleep(2000);
                
                testPortScanning();
                Thread.sleep(3000);
                
                testBruteForce();
                Thread.sleep(3000);
                
                testMaliciousPayload();
                Thread.sleep(2000);
                
                testDataExfiltration();
                Thread.sleep(4000);
                
                testDDoS();
                Thread.sleep(5000);
                
                testLateralMovement();
                Thread.sleep(4000);
                
                testCryptoMining();
                
                logger.info("✅ All detection rule tests completed");
            } catch (Exception e) {
                logger.error("Error running all tests", e);
            }
        });
        
        return ResponseEntity.ok("All tests started - check dashboard for alerts!");
    }
}
