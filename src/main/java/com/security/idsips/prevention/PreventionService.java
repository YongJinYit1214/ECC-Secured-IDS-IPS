package com.security.idsips.prevention;

import com.security.idsips.detection.SecurityAlert;
import com.security.idsips.service.UserFriendlyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Prevention service for blocking suspicious IPs and managing firewall rules
 */
@Service
public class PreventionService {
    
    private static final Logger logger = LoggerFactory.getLogger(PreventionService.class);
    
    @Autowired
    private BlockedIpRepository blockedIpRepository;

    @Autowired
    private UserFriendlyService userFriendlyService;

    @Value("${idsips.prevention.enabled:true}")
    private boolean preventionEnabled;
    
    @Value("${idsips.prevention.auto-block:true}")
    private boolean autoBlockEnabled;
    
    @Value("${idsips.prevention.block-duration:3600}")
    private int defaultBlockDurationSeconds;
    
    /**
     * Handle security alert and determine if prevention action is needed
     */
    @Async
    public void handleAlert(SecurityAlert alert) {
        if (!preventionEnabled || !autoBlockEnabled) {
            return;
        }
        
        try {
            // Determine if IP should be blocked based on alert severity and type
            if (shouldBlockIp(alert)) {
                blockIp(alert.getSourceIp(), alert.getDescription(), alert.getAlertId(), "SYSTEM");
            }
            
        } catch (Exception e) {
            logger.error("Error handling alert for prevention: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Block an IP address
     */
    public BlockedIp blockIp(String ipAddress, String reason, String alertId, String blockedBy) {
        try {
            // Check if IP is already blocked
            if (isIpBlocked(ipAddress)) {
                logger.info("IP {} is already blocked", ipAddress);
                return blockedIpRepository.findByIpAddress(ipAddress).orElse(null);
            }
            
            // Create block entry
            LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(defaultBlockDurationSeconds);
            BlockedIp blockedIp = new BlockedIp(ipAddress, reason, expiresAt);
            blockedIp.setAlertId(alertId);
            blockedIp.setBlockedBy(blockedBy);
            
            // Save to database
            blockedIp = blockedIpRepository.save(blockedIp);
            
            // Apply firewall rule (simulated)
            applyFirewallRule(ipAddress, true);
            
            logger.info("Blocked IP: {}", blockedIp);

            // User-friendly notification
            userFriendlyService.showBlockedIP(ipAddress, reason);

            return blockedIp;
            
        } catch (Exception e) {
            logger.error("Failed to block IP {}: {}", ipAddress, e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Unblock an IP address
     */
    public boolean unblockIp(String ipAddress, String unblockedBy) {
        try {
            var blockedIpOpt = blockedIpRepository.findByIpAddress(ipAddress);
            if (blockedIpOpt.isPresent()) {
                BlockedIp blockedIp = blockedIpOpt.get();
                blockedIp.setStatus(BlockedIp.BlockStatus.REMOVED);
                blockedIpRepository.save(blockedIp);
                
                // Remove firewall rule (simulated)
                applyFirewallRule(ipAddress, false);
                
                logger.info("Unblocked IP: {} by {}", ipAddress, unblockedBy);
                return true;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.error("Failed to unblock IP {}: {}", ipAddress, e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Check if an IP address is currently blocked
     */
    public boolean isIpBlocked(String ipAddress) {
        return blockedIpRepository.isIpBlocked(ipAddress, LocalDateTime.now());
    }
    
    /**
     * Get all active blocked IPs
     */
    public List<BlockedIp> getActiveBlockedIps() {
        return blockedIpRepository.findByStatusOrderByBlockedAtDesc(BlockedIp.BlockStatus.ACTIVE);
    }
    
    /**
     * Get blocked IP information
     */
    public BlockedIp getBlockedIp(String ipAddress) {
        return blockedIpRepository.findByIpAddress(ipAddress).orElse(null);
    }
    
    /**
     * Determine if IP should be blocked based on alert
     */
    private boolean shouldBlockIp(SecurityAlert alert) {
        // Block for critical and high severity alerts
        if (alert.getSeverity() == SecurityAlert.AlertSeverity.CRITICAL) {
            return true;
        }
        
        if (alert.getSeverity() == SecurityAlert.AlertSeverity.HIGH) {
            // Block for specific alert types
            return alert.getAlertType() == SecurityAlert.AlertType.BRUTE_FORCE ||
                   alert.getAlertType() == SecurityAlert.AlertType.PORT_SCAN ||
                   alert.getAlertType() == SecurityAlert.AlertType.DDoS_ATTACK;
        }
        
        return false;
    }
    
    /**
     * Apply or remove firewall rule (simulated implementation)
     * In a real implementation, this would interface with iptables, Windows Firewall, etc.
     */
    private void applyFirewallRule(String ipAddress, boolean block) {
        try {
            if (block) {
                // Simulate blocking IP
                logger.info("FIREWALL: Blocking IP {}", ipAddress);
                // Example: Runtime.getRuntime().exec("iptables -A INPUT -s " + ipAddress + " -j DROP");
            } else {
                // Simulate unblocking IP
                logger.info("FIREWALL: Unblocking IP {}", ipAddress);
                // Example: Runtime.getRuntime().exec("iptables -D INPUT -s " + ipAddress + " -j DROP");
            }
        } catch (Exception e) {
            logger.error("Failed to apply firewall rule for IP {}: {}", ipAddress, e.getMessage());
        }
    }
    
    /**
     * Scheduled task to clean up expired blocks
     */
    @Scheduled(fixedRate = 300000) // Run every 5 minutes
    public void cleanupExpiredBlocks() {
        if (!preventionEnabled) {
            return;
        }
        
        try {
            List<BlockedIp> expiredBlocks = blockedIpRepository.findExpiredBlocks(LocalDateTime.now());
            
            for (BlockedIp blockedIp : expiredBlocks) {
                blockedIp.setStatus(BlockedIp.BlockStatus.EXPIRED);
                blockedIpRepository.save(blockedIp);
                
                // Remove firewall rule
                applyFirewallRule(blockedIp.getIpAddress(), false);
                
                logger.info("Expired block removed for IP: {}", blockedIp.getIpAddress());
            }
            
            if (!expiredBlocks.isEmpty()) {
                logger.info("Cleaned up {} expired IP blocks", expiredBlocks.size());
            }
            
        } catch (Exception e) {
            logger.error("Error during expired blocks cleanup: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Get prevention statistics
     */
    public PreventionStats getPreventionStats() {
        long activeBlocks = blockedIpRepository.countByStatus(BlockedIp.BlockStatus.ACTIVE);
        long expiredBlocks = blockedIpRepository.countByStatus(BlockedIp.BlockStatus.EXPIRED);
        long removedBlocks = blockedIpRepository.countByStatus(BlockedIp.BlockStatus.REMOVED);
        
        return new PreventionStats(activeBlocks, expiredBlocks, removedBlocks, 
                                 preventionEnabled, autoBlockEnabled);
    }
    
    /**
     * Statistics class for prevention service
     */
    public static class PreventionStats {
        private final long activeBlocks;
        private final long expiredBlocks;
        private final long removedBlocks;
        private final boolean preventionEnabled;
        private final boolean autoBlockEnabled;
        
        public PreventionStats(long activeBlocks, long expiredBlocks, long removedBlocks, 
                             boolean preventionEnabled, boolean autoBlockEnabled) {
            this.activeBlocks = activeBlocks;
            this.expiredBlocks = expiredBlocks;
            this.removedBlocks = removedBlocks;
            this.preventionEnabled = preventionEnabled;
            this.autoBlockEnabled = autoBlockEnabled;
        }
        
        // Getters
        public long getActiveBlocks() { return activeBlocks; }
        public long getExpiredBlocks() { return expiredBlocks; }
        public long getRemovedBlocks() { return removedBlocks; }
        public boolean isPreventionEnabled() { return preventionEnabled; }
        public boolean isAutoBlockEnabled() { return autoBlockEnabled; }
    }
}
