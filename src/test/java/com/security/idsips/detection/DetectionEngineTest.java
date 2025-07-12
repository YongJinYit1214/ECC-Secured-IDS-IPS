package com.security.idsips.detection;

import com.security.idsips.crypto.ECCCryptoService;
import com.security.idsips.prevention.PreventionService;
import com.security.idsips.sensor.NetworkPacket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.TestPropertySource;

import java.time.LocalDateTime;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for Detection Engine
 */
@SpringBootTest
@TestPropertySource(properties = {
    "idsips.detection.enabled=true",
    "idsips.detection.max-alerts-per-minute=100"
})
class DetectionEngineTest {
    
    @Mock
    private ResourceLoader resourceLoader;
    
    @Mock
    private ECCCryptoService eccCryptoService;
    
    @Mock
    private SecurityAlertRepository alertRepository;
    
    @Mock
    private PreventionService preventionService;
    
    private DetectionEngine detectionEngine;
    
    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        
        // Mock ECC service
        when(eccCryptoService.encryptWithSystemKey(any(String.class)))
            .thenReturn("encrypted_test_data");
        
        detectionEngine = new DetectionEngine();
        // Set private fields using reflection for testing
        setPrivateField(detectionEngine, "resourceLoader", resourceLoader);
        setPrivateField(detectionEngine, "eccCryptoService", eccCryptoService);
        setPrivateField(detectionEngine, "alertRepository", alertRepository);
        setPrivateField(detectionEngine, "preventionService", preventionService);
        setPrivateField(detectionEngine, "detectionEnabled", true);
        setPrivateField(detectionEngine, "maxAlertsPerMinute", 100);
        
        detectionEngine.init();
    }
    
    @Test
    void testDetectionEngineInitialization() {
        Map<String, Object> stats = detectionEngine.getDetectionStats();
        
        assertNotNull(stats);
        assertTrue((Boolean) stats.get("detection_enabled"));
        assertTrue((Integer) stats.get("rules_loaded") > 0);
    }
    
    @Test
    void testPortScanDetection() {
        // Create a packet that should trigger port scan detection
        NetworkPacket packet = new NetworkPacket();
        packet.setSourceIp("192.168.1.100");
        packet.setDestinationIp("192.168.1.1");
        packet.setSourcePort(12345);
        packet.setDestinationPort(22); // SSH port
        packet.setProtocol("TCP");
        packet.setPacketSize(64);
        packet.setTimestamp(LocalDateTime.now());
        
        // Simulate multiple connections from same IP to trigger threshold
        for (int i = 0; i < 25; i++) {
            packet.setSourcePort(12345 + i);
            detectionEngine.analyzePacket(packet);
        }
        
        // Verify that alert was generated
        verify(alertRepository, atLeastOnce()).save(any(SecurityAlert.class));
    }
    
    @Test
    void testMaliciousPayloadDetection() {
        NetworkPacket packet = new NetworkPacket();
        packet.setSourceIp("10.0.0.100");
        packet.setDestinationIp("192.168.1.50");
        packet.setSourcePort(54321);
        packet.setDestinationPort(80);
        packet.setProtocol("TCP");
        packet.setPacketSize(256);
        packet.setPayload("<script>alert('xss')</script>"); // XSS payload
        packet.setTimestamp(LocalDateTime.now());
        
        detectionEngine.analyzePacket(packet);
        
        // Verify that alert was generated for malicious payload
        verify(alertRepository, atLeastOnce()).save(any(SecurityAlert.class));
    }
    
    @Test
    void testBruteForceDetection() {
        NetworkPacket packet = new NetworkPacket();
        packet.setSourceIp("192.168.1.200");
        packet.setDestinationIp("192.168.1.10");
        packet.setSourcePort(55555);
        packet.setDestinationPort(22); // SSH port
        packet.setProtocol("TCP");
        packet.setPacketSize(128);
        packet.setTimestamp(LocalDateTime.now());
        
        // Simulate multiple failed login attempts
        for (int i = 0; i < 15; i++) {
            packet.setSourcePort(55555 + i);
            detectionEngine.analyzePacket(packet);
        }
        
        // Verify that alert was generated and prevention was triggered
        verify(alertRepository, atLeastOnce()).save(any(SecurityAlert.class));
        verify(preventionService, atLeastOnce()).handleAlert(any(SecurityAlert.class));
    }
    
    @Test
    void testSuspiciousTrafficDetection() {
        NetworkPacket packet = new NetworkPacket();
        packet.setSourceIp("192.168.1.150");
        packet.setDestinationIp("192.168.1.20");
        packet.setSourcePort(33333);
        packet.setDestinationPort(443);
        packet.setProtocol("TCP");
        packet.setPacketSize(1500); // Large packet size
        packet.setTimestamp(LocalDateTime.now());
        
        detectionEngine.analyzePacket(packet);
        
        // Verify that alert was generated for suspicious traffic
        verify(alertRepository, atLeastOnce()).save(any(SecurityAlert.class));
    }
    
    @Test
    void testRateLimiting() {
        NetworkPacket packet = new NetworkPacket();
        packet.setSourceIp("192.168.1.250");
        packet.setDestinationIp("192.168.1.30");
        packet.setSourcePort(44444);
        packet.setDestinationPort(80);
        packet.setProtocol("TCP");
        packet.setPacketSize(64);
        packet.setPayload("<script>alert('test')</script>");
        packet.setTimestamp(LocalDateTime.now());
        
        // Try to generate more alerts than the rate limit
        for (int i = 0; i < 150; i++) {
            packet.setSourcePort(44444 + i);
            detectionEngine.analyzePacket(packet);
        }
        
        // Verify that not all packets generated alerts due to rate limiting
        verify(alertRepository, atMost(100)).save(any(SecurityAlert.class));
    }
    
    @Test
    void testNormalTrafficIgnored() {
        NetworkPacket packet = new NetworkPacket();
        packet.setSourceIp("192.168.1.50");
        packet.setDestinationIp("8.8.8.8");
        packet.setSourcePort(12345);
        packet.setDestinationPort(53); // DNS
        packet.setProtocol("UDP");
        packet.setPacketSize(64);
        packet.setPayload("normal dns query");
        packet.setTimestamp(LocalDateTime.now());
        
        detectionEngine.analyzePacket(packet);
        
        // Verify that no alert was generated for normal traffic
        verify(alertRepository, never()).save(any(SecurityAlert.class));
    }
    
    // Helper method to set private fields for testing
    private void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}
