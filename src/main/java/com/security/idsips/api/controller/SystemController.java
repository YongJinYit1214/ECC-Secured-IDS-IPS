package com.security.idsips.api.controller;

import com.security.idsips.crypto.ECCCryptoService;
import com.security.idsips.detection.DetectionEngine;
import com.security.idsips.prevention.PreventionService;
import com.security.idsips.sensor.NetworkSensorService;
import com.security.idsips.sensor.PacketAnalysisService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller for system status and ECC key management
 */
@RestController
public class SystemController {
    
    private static final Logger logger = LoggerFactory.getLogger(SystemController.class);
    
    @Autowired
    private ECCCryptoService eccCryptoService;
    
    @Autowired
    private NetworkSensorService networkSensorService;
    
    @Autowired
    private PacketAnalysisService packetAnalysisService;
    
    @Autowired
    private DetectionEngine detectionEngine;
    
    @Autowired
    private PreventionService preventionService;
    
    private final LocalDateTime startTime = LocalDateTime.now();
    
    /**
     * Get IDS/IPS health and statistics
     */
    @GetMapping("/api/v1/system/status")
    public ResponseEntity<Map<String, Object>> getSystemStatus() {
        try {
            Map<String, Object> status = new HashMap<>();
            
            // System uptime
            LocalDateTime now = LocalDateTime.now();
            long uptimeHours = java.time.Duration.between(startTime, now).toHours();
            status.put("uptime", uptimeHours + "h");
            status.put("start_time", startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) + "Z");
            status.put("current_time", now.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) + "Z");
            
            // Sensor status
            status.put("sensor_active", networkSensorService.isCapturing());
            status.put("sensor_queue_size", networkSensorService.getQueueSize());
            
            // Analysis statistics
            status.put("packets_analyzed", packetAnalysisService.getTotalPacketsAnalyzed());
            
            // Detection engine stats
            Map<String, Object> detectionStats = detectionEngine.getDetectionStats();
            status.put("detection_rules", detectionStats.get("rules_loaded"));
            status.put("active_connections", detectionStats.get("active_connections"));
            status.put("alerts_this_minute", detectionStats.get("alerts_this_minute"));
            
            // Prevention stats
            PreventionService.PreventionStats preventionStats = preventionService.getPreventionStats();
            status.put("blocked_ips", preventionStats.getActiveBlocks());
            
            // Overall system health
            status.put("system_health", "HEALTHY");
            status.put("version", "1.0.0");
            
            return ResponseEntity.ok(status);
            
        } catch (Exception e) {
            logger.error("Error retrieving system status: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Allow client (frontend or sensor) to fetch the public ECC key
     */
    @GetMapping("/api/v1/ecc/public-key")
    public ResponseEntity<Map<String, String>> getPublicKey() {
        try {
            // Initialize ECC service if not already done
            if (eccCryptoService != null) {
                String publicKeyPEM = eccCryptoService.getSystemPublicKeyPEM();
                
                Map<String, String> response = new HashMap<>();
                response.put("public_key", publicKeyPEM);
                
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(500).body(Map.of("error", "ECC service not initialized"));
            }
            
        } catch (Exception e) {
            logger.error("Error retrieving public key: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Failed to retrieve public key"));
        }
    }
    
    /**
     * Get detailed system information (admin only)
     */
    @GetMapping("/api/v1/system/info")
    public ResponseEntity<Map<String, Object>> getSystemInfo() {
        try {
            Map<String, Object> info = new HashMap<>();
            
            // JVM information
            Runtime runtime = Runtime.getRuntime();
            info.put("jvm_memory_total", runtime.totalMemory());
            info.put("jvm_memory_free", runtime.freeMemory());
            info.put("jvm_memory_used", runtime.totalMemory() - runtime.freeMemory());
            info.put("jvm_processors", runtime.availableProcessors());
            
            // System properties
            info.put("java_version", System.getProperty("java.version"));
            info.put("os_name", System.getProperty("os.name"));
            info.put("os_version", System.getProperty("os.version"));
            
            // Application info
            info.put("application_name", "ECC-Secured IDS/IPS");
            info.put("version", "1.0.0");
            info.put("build_time", startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) + "Z");
            
            // Component status
            info.put("components", Map.of(
                "sensor", Map.of("status", networkSensorService.isCapturing() ? "ACTIVE" : "INACTIVE"),
                "detection", Map.of("status", "ACTIVE"),
                "prevention", Map.of("status", "ACTIVE"),
                "encryption", Map.of("status", "ACTIVE")
            ));
            
            return ResponseEntity.ok(info);
            
        } catch (Exception e) {
            logger.error("Error retrieving system info: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Health check endpoint
     */
    @GetMapping("/api/v1/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        Map<String, String> health = new HashMap<>();
        health.put("status", "UP");
        health.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) + "Z");
        return ResponseEntity.ok(health);
    }
}
