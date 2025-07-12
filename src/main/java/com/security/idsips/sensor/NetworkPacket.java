package com.security.idsips.sensor;

import java.time.LocalDateTime;

/**
 * Represents a captured network packet with relevant metadata
 */
public class NetworkPacket {
    private String sourceIp;
    private String destinationIp;
    private int sourcePort;
    private int destinationPort;
    private String protocol;
    private int packetSize;
    private String payload;
    private LocalDateTime timestamp;
    private String rawData;
    
    public NetworkPacket() {
        this.timestamp = LocalDateTime.now();
    }
    
    public NetworkPacket(String sourceIp, String destinationIp, int sourcePort, 
                        int destinationPort, String protocol, int packetSize) {
        this();
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.packetSize = packetSize;
    }
    
    // Getters and Setters
    public String getSourceIp() {
        return sourceIp;
    }
    
    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }
    
    public String getDestinationIp() {
        return destinationIp;
    }
    
    public void setDestinationIp(String destinationIp) {
        this.destinationIp = destinationIp;
    }
    
    public int getSourcePort() {
        return sourcePort;
    }
    
    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }
    
    public int getDestinationPort() {
        return destinationPort;
    }
    
    public void setDestinationPort(int destinationPort) {
        this.destinationPort = destinationPort;
    }
    
    public String getProtocol() {
        return protocol;
    }
    
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
    
    public int getPacketSize() {
        return packetSize;
    }
    
    public void setPacketSize(int packetSize) {
        this.packetSize = packetSize;
    }
    
    public String getPayload() {
        return payload;
    }
    
    public void setPayload(String payload) {
        this.payload = payload;
    }
    
    public LocalDateTime getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
    
    public String getRawData() {
        return rawData;
    }
    
    public void setRawData(String rawData) {
        this.rawData = rawData;
    }
    
    @Override
    public String toString() {
        return String.format("NetworkPacket{%s:%d -> %s:%d, protocol=%s, size=%d, time=%s}", 
                           sourceIp, sourcePort, destinationIp, destinationPort, 
                           protocol, packetSize, timestamp);
    }
}
