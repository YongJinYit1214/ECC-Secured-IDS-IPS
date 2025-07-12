package com.security.idsips.api.controller;

import com.security.idsips.api.dto.LoginRequest;
import com.security.idsips.api.dto.LoginResponse;
import com.security.idsips.security.CustomUserDetailsService;
import com.security.idsips.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

/**
 * Authentication controller for login and token management
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    
    @Autowired
    private CustomUserDetailsService userDetailsService;
    
    @Autowired
    private JwtUtil jwtUtil;
    
    /**
     * Authenticate admin user
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            // Validate credentials
            if (userDetailsService.validateCredentials(loginRequest.getUsername(), loginRequest.getPassword())) {
                // Generate JWT token
                String token = jwtUtil.generateToken(loginRequest.getUsername());
                Long expiresIn = jwtUtil.getExpirationTime();
                
                LoginResponse response = new LoginResponse(token, expiresIn);
                
                logger.info("User {} logged in successfully", loginRequest.getUsername());
                return ResponseEntity.ok(response);
            } else {
                logger.warn("Failed login attempt for user: {}", loginRequest.getUsername());
                return ResponseEntity.status(401).body("Invalid credentials");
            }
            
        } catch (Exception e) {
            logger.error("Login error: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
    
    /**
     * Validate token endpoint (optional)
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                if (jwtUtil.validateToken(token)) {
                    String username = jwtUtil.extractUsername(token);
                    return ResponseEntity.ok().body("Token is valid for user: " + username);
                }
            }
            return ResponseEntity.status(401).body("Invalid token");
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid token");
        }
    }
}
