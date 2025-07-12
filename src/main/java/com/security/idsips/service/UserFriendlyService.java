package com.security.idsips.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.awt.*;
import java.io.IOException;
import java.net.URI;

/**
 * Service to provide user-friendly features like auto-opening dashboard
 */
@Service
public class UserFriendlyService {
    
    private static final Logger logger = LoggerFactory.getLogger(UserFriendlyService.class);
    
    @Value("${idsips.user.auto-open-dashboard:false}")
    private boolean autoOpenDashboard;
    
    @Value("${idsips.user.show-welcome-message:true}")
    private boolean showWelcomeMessage;
    
    @Value("${server.port:8080}")
    private int serverPort;
    
    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        if (showWelcomeMessage) {
            showWelcomeMessage();
        }
        
        if (autoOpenDashboard) {
            openDashboard();
        }
    }
    
    private void showWelcomeMessage() {
        logger.info("========================================");
        logger.info("🛡️  ECC-IDS-IPS Security System ACTIVE");
        logger.info("   Real-Time Network Protection");
        logger.info("========================================");
        logger.info("");
        logger.info("🌐 Dashboard: http://localhost:{}", serverPort);
        logger.info("🔑 Login: admin / admin123");
        logger.info("");
        logger.info("🔍 Monitoring for:");
        logger.info("   • Port scanning attacks (50+ connections/min)");
        logger.info("   • Brute force attempts (25+ failed attempts)");
        logger.info("   • Malicious payloads (SQL injection, XSS)");
        logger.info("   • Data exfiltration (8KB+ packets)");
        logger.info("   • DDoS attacks (500+ connections from 50+ sources)");
        logger.info("   • Lateral movement (network reconnaissance)");
        logger.info("   • Cryptocurrency mining");
        logger.info("   • Known malicious IPs");
        logger.info("");
        logger.info("⚠️  Keep this application running for continuous protection!");
        logger.info("========================================");
    }
    
    private void openDashboard() {
        try {
            // Wait a moment for the server to fully start
            Thread.sleep(3000);
            
            String url = "http://localhost:" + serverPort;
            
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
                logger.info("🌐 Dashboard opened automatically: {}", url);
            } else {
                logger.info("🌐 Please open your browser to: {}", url);
            }
        } catch (Exception e) {
            logger.warn("Could not auto-open dashboard: {}", e.getMessage());
            logger.info("🌐 Please manually open your browser to: http://localhost:{}", serverPort);
        }
    }
    
    public void showSecurityAlert(String alertType, String severity, String description) {
        if (showWelcomeMessage) {
            logger.warn("🚨 SECURITY ALERT: {} [{}] - {}", alertType, severity, description);
        }
    }
    
    public void showBlockedIP(String ipAddress, String reason) {
        if (showWelcomeMessage) {
            logger.warn("🚫 BLOCKED IP: {} - {}", ipAddress, reason);
        }
    }
}
