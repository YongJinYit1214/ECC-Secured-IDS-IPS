package com.security.idsips.api.controller;

import com.security.idsips.crypto.ECCCryptoService;
import com.security.idsips.detection.SecurityAlert;
import com.security.idsips.detection.SecurityAlertRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Controller for managing security alerts
 */
@RestController
@RequestMapping("/api/v1/alerts")
public class AlertController {
    
    private static final Logger logger = LoggerFactory.getLogger(AlertController.class);
    
    @Autowired
    private SecurityAlertRepository alertRepository;
    
    @Autowired
    private ECCCryptoService eccCryptoService;
    
    /**
     * Retrieve list of ECC-encrypted alerts
     */
    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> getAlerts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String status) {
        
        try {
            List<SecurityAlert> alerts;
            
            // Apply filters if provided
            if (severity != null) {
                SecurityAlert.AlertSeverity alertSeverity = SecurityAlert.AlertSeverity.valueOf(severity.toUpperCase());
                alerts = alertRepository.findBySeverityOrderByTimestampDesc(alertSeverity);
            } else if (status != null) {
                SecurityAlert.AlertStatus alertStatus = SecurityAlert.AlertStatus.valueOf(status.toUpperCase());
                alerts = alertRepository.findByStatusOrderByTimestampDesc(alertStatus);
            } else {
                // Get recent alerts (last 24 hours)
                LocalDateTime since = LocalDateTime.now().minusHours(24);
                alerts = alertRepository.findRecentAlerts(since);
            }
            
            // Apply pagination
            int start = page * size;
            int end = Math.min(start + size, alerts.size());
            if (start >= alerts.size()) {
                alerts = List.of();
            } else {
                alerts = alerts.subList(start, end);
            }
            
            // Convert to response format
            List<Map<String, Object>> response = alerts.stream()
                .map(this::convertAlertToResponse)
                .toList();
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error retrieving alerts: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Get specific alert by ID
     */
    @GetMapping("/{alertId}")
    public ResponseEntity<Map<String, Object>> getAlert(@PathVariable String alertId) {
        try {
            Optional<SecurityAlert> alertOpt = alertRepository.findByAlertId(alertId);
            if (alertOpt.isPresent()) {
                Map<String, Object> response = convertAlertToResponse(alertOpt.get());
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            logger.error("Error retrieving alert {}: {}", alertId, e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Request backend to decrypt a specific ECC-encrypted alert
     */
    @PostMapping("/decrypt")
    public ResponseEntity<Map<String, Object>> decryptAlert(@RequestBody Map<String, String> request) {
        try {
            String encryptedAlert = request.get("encrypted_alert");
            if (encryptedAlert == null || encryptedAlert.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "encrypted_alert is required"));
            }
            
            // Decrypt the alert details
            String decryptedText = eccCryptoService.decryptWithSystemKey(encryptedAlert);
            
            Map<String, Object> response = new HashMap<>();
            response.put("alert_text", decryptedText);
            
            logger.info("Alert decrypted successfully");
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error decrypting alert: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Failed to decrypt alert"));
        }
    }
    
    /**
     * Update alert status
     */
    @PutMapping("/{alertId}/status")
    public ResponseEntity<Map<String, Object>> updateAlertStatus(
            @PathVariable String alertId,
            @RequestBody Map<String, String> request) {
        
        try {
            String newStatus = request.get("status");
            String resolvedBy = request.get("resolved_by");
            
            Optional<SecurityAlert> alertOpt = alertRepository.findByAlertId(alertId);
            if (alertOpt.isPresent()) {
                SecurityAlert alert = alertOpt.get();
                alert.setStatus(SecurityAlert.AlertStatus.valueOf(newStatus.toUpperCase()));
                
                if ("RESOLVED".equals(newStatus.toUpperCase())) {
                    alert.setResolvedAt(LocalDateTime.now());
                    alert.setResolvedBy(resolvedBy);
                }
                
                alertRepository.save(alert);
                
                Map<String, Object> response = new HashMap<>();
                response.put("status", "updated");
                response.put("alert_id", alertId);
                response.put("new_status", newStatus);
                
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.notFound().build();
            }
            
        } catch (Exception e) {
            logger.error("Error updating alert status: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Get alert statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getAlertStats() {
        try {
            Map<String, Object> stats = new HashMap<>();
            
            // Count by status
            stats.put("open_alerts", alertRepository.countByStatus(SecurityAlert.AlertStatus.OPEN));
            stats.put("investigating_alerts", alertRepository.countByStatus(SecurityAlert.AlertStatus.INVESTIGATING));
            stats.put("resolved_alerts", alertRepository.countByStatus(SecurityAlert.AlertStatus.RESOLVED));
            
            // Count by severity
            stats.put("critical_alerts", alertRepository.countBySeverity(SecurityAlert.AlertSeverity.CRITICAL));
            stats.put("high_alerts", alertRepository.countBySeverity(SecurityAlert.AlertSeverity.HIGH));
            stats.put("medium_alerts", alertRepository.countBySeverity(SecurityAlert.AlertSeverity.MEDIUM));
            stats.put("low_alerts", alertRepository.countBySeverity(SecurityAlert.AlertSeverity.LOW));
            
            // Alerts today
            stats.put("alerts_today", alertRepository.countAlertsToday());
            
            return ResponseEntity.ok(stats);
            
        } catch (Exception e) {
            logger.error("Error retrieving alert stats: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Convert SecurityAlert entity to response format
     */
    private Map<String, Object> convertAlertToResponse(SecurityAlert alert) {
        Map<String, Object> response = new HashMap<>();
        response.put("id", alert.getAlertId());
        response.put("timestamp", alert.getTimestamp().toString() + "Z");
        response.put("source_ip", alert.getSourceIp());
        response.put("destination_ip", alert.getDestinationIp());
        response.put("source_port", alert.getSourcePort());
        response.put("destination_port", alert.getDestinationPort());
        response.put("protocol", alert.getProtocol());
        response.put("severity", alert.getSeverity().toString());
        response.put("alert_type", alert.getAlertType().toString());
        response.put("description", alert.getDescription());
        response.put("status", alert.getStatus().toString());
        response.put("alert_encrypted", alert.getEncryptedDetails());
        
        if (alert.getResolvedAt() != null) {
            response.put("resolved_at", alert.getResolvedAt().toString() + "Z");
            response.put("resolved_by", alert.getResolvedBy());
        }
        
        return response;
    }
}
