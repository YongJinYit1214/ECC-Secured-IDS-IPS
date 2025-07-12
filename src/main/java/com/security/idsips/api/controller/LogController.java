package com.security.idsips.api.controller;

import com.security.idsips.crypto.ECCCryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller for log storage (sensor use only)
 */
@RestController
@RequestMapping("/api/v1/logs")
public class LogController {
    
    private static final Logger logger = LoggerFactory.getLogger(LogController.class);
    
    @Autowired
    private ECCCryptoService eccCryptoService;
    
    /**
     * Send ECC-encrypted logs to backend for storage (Sensor use only)
     */
    @PostMapping("/store")
    public ResponseEntity<Map<String, Object>> storeLogs(@RequestBody Map<String, String> request) {
        try {
            String sensorId = request.get("sensor_id");
            String timestamp = request.get("timestamp");
            String encryptedLog = request.get("log_encrypted");
            
            // Validate required fields
            if (sensorId == null || encryptedLog == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "sensor_id and log_encrypted are required"));
            }
            
            // In a real implementation, you would:
            // 1. Validate the sensor ID
            // 2. Decrypt and validate the log content
            // 3. Store the log in a secure database
            // 4. Apply retention policies
            
            // For now, we'll just log the receipt and generate a log ID
            String logId = "LOG" + System.currentTimeMillis();
            
            logger.info("Received encrypted log from sensor {}: logId={}", sensorId, logId);
            
            // Optionally decrypt for validation (in production, you might want to keep logs encrypted)
            try {
                String decryptedLog = eccCryptoService.decryptWithSystemKey(encryptedLog);
                logger.debug("Log content preview: {}", decryptedLog.substring(0, Math.min(100, decryptedLog.length())));
            } catch (Exception e) {
                logger.warn("Failed to decrypt log for validation: {}", e.getMessage());
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "stored");
            response.put("log_id", logId);
            response.put("timestamp", LocalDateTime.now().toString() + "Z");
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error storing log: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Failed to store log"));
        }
    }
    
    /**
     * Get log storage statistics (admin only)
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getLogStats() {
        try {
            // In a real implementation, this would query the log database
            Map<String, Object> stats = new HashMap<>();
            stats.put("total_logs", 0); // Placeholder
            stats.put("logs_today", 0); // Placeholder
            stats.put("storage_size_mb", 0); // Placeholder
            stats.put("oldest_log", null); // Placeholder
            stats.put("newest_log", null); // Placeholder
            
            return ResponseEntity.ok(stats);
            
        } catch (Exception e) {
            logger.error("Error retrieving log stats: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
}
