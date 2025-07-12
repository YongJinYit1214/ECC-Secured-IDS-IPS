package com.security.idsips.prevention;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity representing a blocked IP address
 */
@Entity
@Table(name = "blocked_ips")
public class BlockedIp {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String ipAddress;
    
    @Column(nullable = false)
    private LocalDateTime blockedAt;
    
    private LocalDateTime expiresAt;
    
    @Column(nullable = false)
    private String reason;
    
    private String blockedBy;
    
    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private BlockStatus status;
    
    private String alertId; // Reference to the alert that triggered the block
    
    // Constructors
    public BlockedIp() {
        this.blockedAt = LocalDateTime.now();
        this.status = BlockStatus.ACTIVE;
    }
    
    public BlockedIp(String ipAddress, String reason) {
        this();
        this.ipAddress = ipAddress;
        this.reason = reason;
    }
    
    public BlockedIp(String ipAddress, String reason, LocalDateTime expiresAt) {
        this(ipAddress, reason);
        this.expiresAt = expiresAt;
    }
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getIpAddress() {
        return ipAddress;
    }
    
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
    
    public LocalDateTime getBlockedAt() {
        return blockedAt;
    }
    
    public void setBlockedAt(LocalDateTime blockedAt) {
        this.blockedAt = blockedAt;
    }
    
    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }
    
    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }
    
    public String getReason() {
        return reason;
    }
    
    public void setReason(String reason) {
        this.reason = reason;
    }
    
    public String getBlockedBy() {
        return blockedBy;
    }
    
    public void setBlockedBy(String blockedBy) {
        this.blockedBy = blockedBy;
    }
    
    public BlockStatus getStatus() {
        return status;
    }
    
    public void setStatus(BlockStatus status) {
        this.status = status;
    }
    
    public String getAlertId() {
        return alertId;
    }
    
    public void setAlertId(String alertId) {
        this.alertId = alertId;
    }
    
    /**
     * Check if the block is still active
     */
    public boolean isActive() {
        return status == BlockStatus.ACTIVE && 
               (expiresAt == null || LocalDateTime.now().isBefore(expiresAt));
    }
    
    /**
     * Check if the block has expired
     */
    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }
    
    // Enums
    public enum BlockStatus {
        ACTIVE, EXPIRED, REMOVED
    }
    
    @Override
    public String toString() {
        return String.format("BlockedIp{ip='%s', reason='%s', status=%s, blockedAt=%s, expiresAt=%s}", 
                           ipAddress, reason, status, blockedAt, expiresAt);
    }
}
