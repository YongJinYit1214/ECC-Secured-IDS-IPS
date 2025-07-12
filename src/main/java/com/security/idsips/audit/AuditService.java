package com.security.idsips.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Audit service for tracking security-related actions
 */
@Service
public class AuditService {
    
    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);
    
    // In-memory audit log (in production, this would be persisted to database)
    private final ConcurrentLinkedQueue<AuditEvent> auditLog = new ConcurrentLinkedQueue<>();
    
    /**
     * Log authentication event
     */
    public void logAuthentication(String username, boolean success, String ipAddress) {
        AuditEvent event = new AuditEvent(
            AuditEventType.AUTHENTICATION,
            username,
            success ? "Login successful" : "Login failed",
            ipAddress
        );
        
        auditLog.offer(event);
        logger.info("AUDIT: {} - {} from {}", event.getEventType(), event.getDescription(), ipAddress);
    }
    
    /**
     * Log alert decryption
     */
    public void logAlertDecryption(String username, String alertId, String ipAddress) {
        AuditEvent event = new AuditEvent(
            AuditEventType.ALERT_DECRYPTION,
            username,
            "Alert decrypted: " + alertId,
            ipAddress
        );
        
        auditLog.offer(event);
        logger.info("AUDIT: {} - {} by {} from {}", event.getEventType(), event.getDescription(), username, ipAddress);
    }
    
    /**
     * Log IP blocking action
     */
    public void logIpBlocking(String username, String ipAddress, String targetIp, String reason) {
        AuditEvent event = new AuditEvent(
            AuditEventType.IP_BLOCKING,
            username,
            String.format("IP %s blocked: %s", targetIp, reason),
            ipAddress
        );
        
        auditLog.offer(event);
        logger.info("AUDIT: {} - {} by {} from {}", event.getEventType(), event.getDescription(), username, ipAddress);
    }
    
    /**
     * Log IP unblocking action
     */
    public void logIpUnblocking(String username, String ipAddress, String targetIp) {
        AuditEvent event = new AuditEvent(
            AuditEventType.IP_UNBLOCKING,
            username,
            "IP " + targetIp + " unblocked",
            ipAddress
        );
        
        auditLog.offer(event);
        logger.info("AUDIT: {} - {} by {} from {}", event.getEventType(), event.getDescription(), username, ipAddress);
    }
    
    /**
     * Log system access
     */
    public void logSystemAccess(String username, String resource, String ipAddress) {
        AuditEvent event = new AuditEvent(
            AuditEventType.SYSTEM_ACCESS,
            username,
            "Accessed: " + resource,
            ipAddress
        );
        
        auditLog.offer(event);
        logger.debug("AUDIT: {} - {} by {} from {}", event.getEventType(), event.getDescription(), username, ipAddress);
    }
    
    /**
     * Get recent audit events
     */
    public java.util.List<AuditEvent> getRecentEvents(int limit) {
        return auditLog.stream()
                .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
                .limit(limit)
                .toList();
    }
    
    /**
     * Audit event class
     */
    public static class AuditEvent {
        private final AuditEventType eventType;
        private final String username;
        private final String description;
        private final String sourceIp;
        private final LocalDateTime timestamp;
        
        public AuditEvent(AuditEventType eventType, String username, String description, String sourceIp) {
            this.eventType = eventType;
            this.username = username;
            this.description = description;
            this.sourceIp = sourceIp;
            this.timestamp = LocalDateTime.now();
        }
        
        // Getters
        public AuditEventType getEventType() { return eventType; }
        public String getUsername() { return username; }
        public String getDescription() { return description; }
        public String getSourceIp() { return sourceIp; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    /**
     * Audit event types
     */
    public enum AuditEventType {
        AUTHENTICATION,
        ALERT_DECRYPTION,
        IP_BLOCKING,
        IP_UNBLOCKING,
        SYSTEM_ACCESS,
        CONFIGURATION_CHANGE
    }
}
