package com.security.idsips.detection;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Represents a detection rule for identifying security threats
 */
public class DetectionRule {
    
    @JsonProperty("rule_id")
    private String ruleId;
    
    @JsonProperty("name")
    private String name;
    
    @JsonProperty("description")
    private String description;
    
    @JsonProperty("severity")
    private SecurityAlert.AlertSeverity severity;
    
    @JsonProperty("alert_type")
    private SecurityAlert.AlertType alertType;
    
    @JsonProperty("enabled")
    private boolean enabled = true;
    
    @JsonProperty("conditions")
    private RuleConditions conditions;
    
    @JsonProperty("thresholds")
    private Map<String, Object> thresholds;
    
    // Constructors
    public DetectionRule() {}
    
    public DetectionRule(String ruleId, String name, String description, 
                        SecurityAlert.AlertSeverity severity, SecurityAlert.AlertType alertType) {
        this.ruleId = ruleId;
        this.name = name;
        this.description = description;
        this.severity = severity;
        this.alertType = alertType;
    }
    
    // Getters and Setters
    public String getRuleId() {
        return ruleId;
    }
    
    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public SecurityAlert.AlertSeverity getSeverity() {
        return severity;
    }
    
    public void setSeverity(SecurityAlert.AlertSeverity severity) {
        this.severity = severity;
    }
    
    public SecurityAlert.AlertType getAlertType() {
        return alertType;
    }
    
    public void setAlertType(SecurityAlert.AlertType alertType) {
        this.alertType = alertType;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public RuleConditions getConditions() {
        return conditions;
    }
    
    public void setConditions(RuleConditions conditions) {
        this.conditions = conditions;
    }
    
    public Map<String, Object> getThresholds() {
        return thresholds;
    }
    
    public void setThresholds(Map<String, Object> thresholds) {
        this.thresholds = thresholds;
    }
    
    /**
     * Inner class for rule conditions
     */
    public static class RuleConditions {
        @JsonProperty("source_ip_patterns")
        private List<String> sourceIpPatterns;
        
        @JsonProperty("destination_ip_patterns")
        private List<String> destinationIpPatterns;
        
        @JsonProperty("port_ranges")
        private List<PortRange> portRanges;
        
        @JsonProperty("protocols")
        private List<String> protocols;
        
        @JsonProperty("payload_patterns")
        private List<String> payloadPatterns;
        
        @JsonProperty("packet_size_min")
        private Integer packetSizeMin;
        
        @JsonProperty("packet_size_max")
        private Integer packetSizeMax;
        
        // Getters and Setters
        public List<String> getSourceIpPatterns() {
            return sourceIpPatterns;
        }
        
        public void setSourceIpPatterns(List<String> sourceIpPatterns) {
            this.sourceIpPatterns = sourceIpPatterns;
        }
        
        public List<String> getDestinationIpPatterns() {
            return destinationIpPatterns;
        }
        
        public void setDestinationIpPatterns(List<String> destinationIpPatterns) {
            this.destinationIpPatterns = destinationIpPatterns;
        }
        
        public List<PortRange> getPortRanges() {
            return portRanges;
        }
        
        public void setPortRanges(List<PortRange> portRanges) {
            this.portRanges = portRanges;
        }
        
        public List<String> getProtocols() {
            return protocols;
        }
        
        public void setProtocols(List<String> protocols) {
            this.protocols = protocols;
        }
        
        public List<String> getPayloadPatterns() {
            return payloadPatterns;
        }
        
        public void setPayloadPatterns(List<String> payloadPatterns) {
            this.payloadPatterns = payloadPatterns;
        }
        
        public Integer getPacketSizeMin() {
            return packetSizeMin;
        }
        
        public void setPacketSizeMin(Integer packetSizeMin) {
            this.packetSizeMin = packetSizeMin;
        }
        
        public Integer getPacketSizeMax() {
            return packetSizeMax;
        }
        
        public void setPacketSizeMax(Integer packetSizeMax) {
            this.packetSizeMax = packetSizeMax;
        }
    }
    
    /**
     * Inner class for port range specification
     */
    public static class PortRange {
        @JsonProperty("start")
        private int start;
        
        @JsonProperty("end")
        private int end;
        
        public PortRange() {}
        
        public PortRange(int start, int end) {
            this.start = start;
            this.end = end;
        }
        
        public int getStart() {
            return start;
        }
        
        public void setStart(int start) {
            this.start = start;
        }
        
        public int getEnd() {
            return end;
        }
        
        public void setEnd(int end) {
            this.end = end;
        }
        
        public boolean contains(int port) {
            return port >= start && port <= end;
        }
    }
}
