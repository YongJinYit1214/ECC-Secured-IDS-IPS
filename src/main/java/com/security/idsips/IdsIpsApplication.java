package com.security.idsips;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main application class for ECC-Secured IDS/IPS System
 * 
 * This application provides:
 * - Network traffic monitoring and analysis
 * - ECC-encrypted alert and log management
 * - Intrusion detection and prevention capabilities
 * - Secure admin dashboard with REST API
 */
@SpringBootApplication
@EnableAsync
@EnableScheduling
public class IdsIpsApplication {

    public static void main(String[] args) {
        // Add Bouncy Castle as security provider for ECC support
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        SpringApplication.run(IdsIpsApplication.class, args);
    }
}
