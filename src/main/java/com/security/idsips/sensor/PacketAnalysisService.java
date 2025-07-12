package com.security.idsips.sensor;

import com.security.idsips.detection.DetectionEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service for analyzing captured network packets
 */
@Service
public class PacketAnalysisService {
    
    private static final Logger logger = LoggerFactory.getLogger(PacketAnalysisService.class);
    
    @Autowired
    private DetectionEngine detectionEngine;
    
    // Statistics tracking
    private final AtomicLong totalPacketsAnalyzed = new AtomicLong(0);
    private final ConcurrentHashMap<String, AtomicLong> protocolStats = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> portStats = new ConcurrentHashMap<>();
    
    /**
     * Analyze a network packet asynchronously
     */
    @Async
    public void analyzePacket(NetworkPacket packet) {
        try {
            // Update statistics
            updateStatistics(packet);
            
            // Log packet for debugging (in production, this should be more selective)
            logger.debug("Analyzing packet: {}", packet);
            
            // Send packet to detection engine for threat analysis
            detectionEngine.analyzePacket(packet);
            
        } catch (Exception e) {
            logger.error("Error analyzing packet: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Update packet analysis statistics
     */
    private void updateStatistics(NetworkPacket packet) {
        totalPacketsAnalyzed.incrementAndGet();
        
        // Update protocol statistics
        if (packet.getProtocol() != null) {
            protocolStats.computeIfAbsent(packet.getProtocol(), k -> new AtomicLong(0)).incrementAndGet();
        }
        
        // Update destination port statistics
        if (packet.getDestinationPort() > 0) {
            String portKey = String.valueOf(packet.getDestinationPort());
            portStats.computeIfAbsent(portKey, k -> new AtomicLong(0)).incrementAndGet();
        }
    }
    
    /**
     * Get total packets analyzed
     */
    public long getTotalPacketsAnalyzed() {
        return totalPacketsAnalyzed.get();
    }
    
    /**
     * Get protocol statistics
     */
    public ConcurrentHashMap<String, AtomicLong> getProtocolStats() {
        return new ConcurrentHashMap<>(protocolStats);
    }
    
    /**
     * Get port statistics
     */
    public ConcurrentHashMap<String, AtomicLong> getPortStats() {
        return new ConcurrentHashMap<>(portStats);
    }
    
    /**
     * Reset all statistics
     */
    public void resetStatistics() {
        totalPacketsAnalyzed.set(0);
        protocolStats.clear();
        portStats.clear();
        logger.info("Packet analysis statistics reset");
    }
}
