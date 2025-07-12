package com.security.idsips.api.controller;

import com.security.idsips.prevention.BlockedIp;
import com.security.idsips.prevention.PreventionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller for IP blocking and prevention actions
 */
@RestController
@RequestMapping("/api/v1/block")
public class PreventionController {
    
    private static final Logger logger = LoggerFactory.getLogger(PreventionController.class);
    
    @Autowired
    private PreventionService preventionService;
    
    /**
     * Block an IP address immediately
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> blockIp(
            @RequestBody Map<String, String> request,
            Authentication authentication) {
        
        try {
            String ip = request.get("ip");
            String reason = request.get("reason");
            
            if (ip == null || ip.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "IP address is required"));
            }
            
            if (reason == null || reason.isEmpty()) {
                reason = "Manual block by admin";
            }
            
            String blockedBy = authentication.getName();
            BlockedIp blockedIp = preventionService.blockIp(ip, reason, null, blockedBy);
            
            if (blockedIp != null) {
                Map<String, Object> response = new HashMap<>();
                response.put("status", "blocked");
                response.put("ip", ip);
                response.put("reason", reason);
                response.put("timestamp", LocalDateTime.now().toString() + "Z");
                response.put("blocked_by", blockedBy);
                
                logger.info("IP {} blocked by {}: {}", ip, blockedBy, reason);
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(500).body(Map.of("error", "Failed to block IP"));
            }
            
        } catch (Exception e) {
            logger.error("Error blocking IP: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }
    
    /**
     * Unblock an IP address
     */
    @DeleteMapping("/{ip}")
    public ResponseEntity<Map<String, Object>> unblockIp(
            @PathVariable String ip,
            Authentication authentication) {
        
        try {
            String unblockedBy = authentication.getName();
            boolean success = preventionService.unblockIp(ip, unblockedBy);
            
            if (success) {
                Map<String, Object> response = new HashMap<>();
                response.put("status", "unblocked");
                response.put("ip", ip);
                response.put("timestamp", LocalDateTime.now().toString() + "Z");
                response.put("unblocked_by", unblockedBy);
                
                logger.info("IP {} unblocked by {}", ip, unblockedBy);
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.notFound().build();
            }
            
        } catch (Exception e) {
            logger.error("Error unblocking IP {}: {}", ip, e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }
    
    /**
     * Get list of blocked IPs
     */
    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> getBlockedIps() {
        try {
            List<BlockedIp> blockedIps = preventionService.getActiveBlockedIps();
            
            List<Map<String, Object>> response = blockedIps.stream()
                .map(this::convertBlockedIpToResponse)
                .toList();
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error retrieving blocked IPs: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Get specific blocked IP information
     */
    @GetMapping("/{ip}")
    public ResponseEntity<Map<String, Object>> getBlockedIp(@PathVariable String ip) {
        try {
            BlockedIp blockedIp = preventionService.getBlockedIp(ip);
            if (blockedIp != null) {
                Map<String, Object> response = convertBlockedIpToResponse(blockedIp);
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            logger.error("Error retrieving blocked IP {}: {}", ip, e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Check if IP is blocked
     */
    @GetMapping("/{ip}/status")
    public ResponseEntity<Map<String, Object>> checkIpStatus(@PathVariable String ip) {
        try {
            boolean isBlocked = preventionService.isIpBlocked(ip);
            
            Map<String, Object> response = new HashMap<>();
            response.put("ip", ip);
            response.put("blocked", isBlocked);
            response.put("timestamp", LocalDateTime.now().toString() + "Z");
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error checking IP status {}: {}", ip, e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Get prevention statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getPreventionStats() {
        try {
            PreventionService.PreventionStats stats = preventionService.getPreventionStats();
            
            Map<String, Object> response = new HashMap<>();
            response.put("active_blocks", stats.getActiveBlocks());
            response.put("expired_blocks", stats.getExpiredBlocks());
            response.put("removed_blocks", stats.getRemovedBlocks());
            response.put("prevention_enabled", stats.isPreventionEnabled());
            response.put("auto_block_enabled", stats.isAutoBlockEnabled());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error retrieving prevention stats: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }
    
    /**
     * Convert BlockedIp entity to response format
     */
    private Map<String, Object> convertBlockedIpToResponse(BlockedIp blockedIp) {
        Map<String, Object> response = new HashMap<>();
        response.put("ip", blockedIp.getIpAddress());
        response.put("reason", blockedIp.getReason());
        response.put("status", blockedIp.getStatus().toString());
        response.put("blocked_at", blockedIp.getBlockedAt().toString() + "Z");
        response.put("blocked_by", blockedIp.getBlockedBy());
        response.put("alert_id", blockedIp.getAlertId());
        
        if (blockedIp.getExpiresAt() != null) {
            response.put("expires_at", blockedIp.getExpiresAt().toString() + "Z");
        }
        
        response.put("is_active", blockedIp.isActive());
        response.put("is_expired", blockedIp.isExpired());
        
        return response;
    }
}
