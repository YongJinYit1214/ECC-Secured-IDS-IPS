package com.security.idsips.detection;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.idsips.crypto.ECCCryptoService;
import com.security.idsips.prevention.PreventionService;
import com.security.idsips.sensor.NetworkPacket;
import com.security.idsips.service.UserFriendlyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * Main detection engine for analyzing network packets and generating security alerts
 */
@Service
public class DetectionEngine {
    
    private static final Logger logger = LoggerFactory.getLogger(DetectionEngine.class);
    
    @Autowired
    private ResourceLoader resourceLoader;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Autowired
    private ECCCryptoService eccCryptoService;
    
    @Autowired
    private SecurityAlertRepository alertRepository;
    
    @Autowired
    private PreventionService preventionService;

    @Autowired
    private UserFriendlyService userFriendlyService;

    @Value("${idsips.detection.enabled:true}")
    private boolean detectionEnabled;
    
    @Value("${idsips.detection.rules-file:classpath:detection-rules.json}")
    private String rulesFile;
    
    @Value("${idsips.detection.max-alerts-per-minute:100}")
    private int maxAlertsPerMinute;
    
    private List<DetectionRule> detectionRules = new ArrayList<>();
    private final Map<String, AtomicLong> ipConnectionCounts = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lastConnectionTime = new ConcurrentHashMap<>();
    private final AtomicLong alertsThisMinute = new AtomicLong(0);
    private LocalDateTime lastMinuteReset = LocalDateTime.now();
    
    @PostConstruct
    public void init() {
        if (detectionEnabled) {
            loadDetectionRules();
            logger.info("Detection engine initialized with {} rules", detectionRules.size());
        } else {
            logger.info("Detection engine is disabled");
        }
    }
    
    /**
     * Load detection rules from configuration file
     */
    private void loadDetectionRules() {
        try {
            Resource resource = resourceLoader.getResource(rulesFile);
            if (resource.exists()) {
                detectionRules = objectMapper.readValue(resource.getInputStream(), 
                    new TypeReference<List<DetectionRule>>() {});
                logger.info("Loaded {} detection rules from {}", detectionRules.size(), rulesFile);
            } else {
                // Create default rules if file doesn't exist
                createDefaultRules();
                logger.info("Created {} default detection rules", detectionRules.size());
            }
        } catch (IOException e) {
            logger.error("Failed to load detection rules from {}", rulesFile, e);
            createDefaultRules();
        }
    }
    
    /**
     * Create default detection rules
     */
    private void createDefaultRules() {
        detectionRules = new ArrayList<>();
        
        // Port scanning detection rule
        DetectionRule portScanRule = new DetectionRule("RULE_001", "Port Scanning Detection", 
            "Detects potential port scanning activity", 
            SecurityAlert.AlertSeverity.HIGH, SecurityAlert.AlertType.PORT_SCAN);
        
        DetectionRule.RuleConditions portScanConditions = new DetectionRule.RuleConditions();
        portScanConditions.setPortRanges(Arrays.asList(
            new DetectionRule.PortRange(1, 1024),
            new DetectionRule.PortRange(3389, 3389),
            new DetectionRule.PortRange(5900, 5900)
        ));
        portScanRule.setConditions(portScanConditions);
        portScanRule.setThresholds(Map.of("connections_per_minute", 20));
        detectionRules.add(portScanRule);
        
        // Brute force detection rule
        DetectionRule bruteForceRule = new DetectionRule("RULE_002", "Brute Force Detection", 
            "Detects potential brute force attacks", 
            SecurityAlert.AlertSeverity.CRITICAL, SecurityAlert.AlertType.BRUTE_FORCE);
        
        DetectionRule.RuleConditions bruteForceConditions = new DetectionRule.RuleConditions();
        bruteForceConditions.setPortRanges(Arrays.asList(
            new DetectionRule.PortRange(22, 22),   // SSH
            new DetectionRule.PortRange(21, 21),   // FTP
            new DetectionRule.PortRange(3389, 3389) // RDP
        ));
        bruteForceRule.setConditions(bruteForceConditions);
        bruteForceRule.setThresholds(Map.of("failed_attempts", 10));
        detectionRules.add(bruteForceRule);
        
        // Suspicious payload detection rule
        DetectionRule payloadRule = new DetectionRule("RULE_003", "Malicious Payload Detection", 
            "Detects suspicious payload patterns", 
            SecurityAlert.AlertSeverity.HIGH, SecurityAlert.AlertType.MALICIOUS_PAYLOAD);
        
        DetectionRule.RuleConditions payloadConditions = new DetectionRule.RuleConditions();
        payloadConditions.setPayloadPatterns(Arrays.asList(
            ".*<script.*>.*</script>.*",  // XSS
            ".*union.*select.*",          // SQL Injection
            ".*cmd.*exe.*",               // Command injection
            ".*eval\\(.*\\).*"            // Code injection
        ));
        payloadRule.setConditions(payloadConditions);
        detectionRules.add(payloadRule);
    }
    
    /**
     * Analyze a network packet for potential threats
     */
    @Async
    public void analyzePacket(NetworkPacket packet) {
        if (!detectionEnabled) {
            return;
        }
        
        try {
            // Check rate limiting
            if (!checkRateLimit()) {
                return;
            }
            
            // Update connection tracking
            updateConnectionTracking(packet);
            
            // Apply detection rules
            for (DetectionRule rule : detectionRules) {
                if (rule.isEnabled() && matchesRule(packet, rule)) {
                    generateAlert(packet, rule);
                }
            }
            
        } catch (Exception e) {
            logger.error("Error analyzing packet: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Check if packet matches a detection rule
     */
    private boolean matchesRule(NetworkPacket packet, DetectionRule rule) {
        DetectionRule.RuleConditions conditions = rule.getConditions();
        if (conditions == null) {
            return false;
        }
        
        // Check protocol
        if (conditions.getProtocols() != null && !conditions.getProtocols().isEmpty()) {
            if (!conditions.getProtocols().contains(packet.getProtocol())) {
                return false;
            }
        }
        
        // Check port ranges
        if (conditions.getPortRanges() != null && !conditions.getPortRanges().isEmpty()) {
            boolean portMatches = conditions.getPortRanges().stream()
                .anyMatch(range -> range.contains(packet.getDestinationPort()));
            if (!portMatches) {
                return false;
            }
        }
        
        // Check IP patterns
        if (conditions.getSourceIpPatterns() != null) {
            boolean ipMatches = conditions.getSourceIpPatterns().stream()
                .anyMatch(pattern -> Pattern.matches(pattern, packet.getSourceIp()));
            if (!ipMatches) {
                return false;
            }
        }
        
        // Check payload patterns
        if (conditions.getPayloadPatterns() != null && packet.getPayload() != null) {
            boolean payloadMatches = conditions.getPayloadPatterns().stream()
                .anyMatch(pattern -> Pattern.matches(pattern, packet.getPayload()));
            if (!payloadMatches) {
                return false;
            }
        }
        
        // Check packet size
        if (conditions.getPacketSizeMin() != null && packet.getPacketSize() < conditions.getPacketSizeMin()) {
            return false;
        }
        if (conditions.getPacketSizeMax() != null && packet.getPacketSize() > conditions.getPacketSizeMax()) {
            return false;
        }
        
        // Check thresholds (e.g., connection frequency)
        return checkThresholds(packet, rule);
    }
    
    /**
     * Check rule thresholds
     */
    private boolean checkThresholds(NetworkPacket packet, DetectionRule rule) {
        Map<String, Object> thresholds = rule.getThresholds();
        if (thresholds == null || thresholds.isEmpty()) {
            return true;
        }
        
        String sourceIp = packet.getSourceIp();
        
        // Check connections per minute threshold
        if (thresholds.containsKey("connections_per_minute")) {
            int threshold = (Integer) thresholds.get("connections_per_minute");
            AtomicLong count = ipConnectionCounts.get(sourceIp);
            if (count != null && count.get() >= threshold) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate security alert
     */
    private void generateAlert(NetworkPacket packet, DetectionRule rule) {
        try {
            String alertId = "ALERT" + System.currentTimeMillis();
            
            SecurityAlert alert = new SecurityAlert(alertId, packet.getSourceIp(), 
                packet.getDestinationIp(), rule.getSeverity(), rule.getAlertType(), 
                rule.getDescription());
            
            alert.setSourcePort(packet.getSourcePort());
            alert.setDestinationPort(packet.getDestinationPort());
            alert.setProtocol(packet.getProtocol());
            
            // Encrypt sensitive details
            String detailsJson = objectMapper.writeValueAsString(Map.of(
                "rule_id", rule.getRuleId(),
                "packet_details", packet.toString(),
                "payload", packet.getPayload() != null ? packet.getPayload() : ""
            ));
            
            String encryptedDetails = eccCryptoService.encryptWithSystemKey(detailsJson);
            alert.setEncryptedDetails(encryptedDetails);
            
            // Save alert
            alertRepository.save(alert);
            
            // Trigger prevention if needed
            if (rule.getSeverity() == SecurityAlert.AlertSeverity.CRITICAL || 
                rule.getSeverity() == SecurityAlert.AlertSeverity.HIGH) {
                preventionService.handleAlert(alert);
            }
            
            logger.info("Generated alert: {}", alert);

            // User-friendly notification
            userFriendlyService.showSecurityAlert(
                alert.getAlertType().toString(),
                alert.getSeverity().toString(),
                alert.getDescription()
            );
            
        } catch (Exception e) {
            logger.error("Failed to generate alert for rule {}: {}", rule.getRuleId(), e.getMessage(), e);
        }
    }
    
    /**
     * Update connection tracking for rate limiting and pattern detection
     */
    private void updateConnectionTracking(NetworkPacket packet) {
        String sourceIp = packet.getSourceIp();
        
        // Update connection count
        ipConnectionCounts.computeIfAbsent(sourceIp, k -> new AtomicLong(0)).incrementAndGet();
        lastConnectionTime.put(sourceIp, LocalDateTime.now());
        
        // Clean up old entries (older than 1 minute)
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(1);
        lastConnectionTime.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));
        ipConnectionCounts.entrySet().removeIf(entry -> 
            !lastConnectionTime.containsKey(entry.getKey()));
    }
    
    /**
     * Check rate limiting for alert generation
     */
    private boolean checkRateLimit() {
        LocalDateTime now = LocalDateTime.now();
        
        // Reset counter if a minute has passed
        if (now.isAfter(lastMinuteReset.plusMinutes(1))) {
            alertsThisMinute.set(0);
            lastMinuteReset = now;
        }
        
        return alertsThisMinute.incrementAndGet() <= maxAlertsPerMinute;
    }
    
    /**
     * Get current detection statistics
     */
    public Map<String, Object> getDetectionStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("rules_loaded", detectionRules.size());
        stats.put("active_connections", ipConnectionCounts.size());
        stats.put("alerts_this_minute", alertsThisMinute.get());
        stats.put("detection_enabled", detectionEnabled);
        return stats;
    }
}
