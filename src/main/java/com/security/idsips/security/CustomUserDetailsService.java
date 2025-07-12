package com.security.idsips.security;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom User Details Service for authentication
 * In a production system, this would connect to a database
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    private final PasswordEncoder passwordEncoder;

    @Value("${idsips.security.users.admin.username:admin}")
    private String adminUsername;

    @Value("${idsips.security.users.admin.password:admin123}")
    private String adminPassword;

    @Value("${idsips.security.users.operator.username:operator}")
    private String operatorUsername;

    @Value("${idsips.security.users.operator.password:operator123}")
    private String operatorPassword;

    // In-memory users for demo purposes
    // In production, this would be replaced with database access
    private final Map<String, String> users = new HashMap<>();
    
    public CustomUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        // Initialize with default admin user
        // Password will be encoded when first accessed
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Initialize default users if not already done
        if (users.isEmpty()) {
            initializeUsers();
        }
        
        String password = users.get(username);
        if (password == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        
        return User.builder()
                .username(username)
                .password(password)
                .authorities(Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .build();
    }
    
    /**
     * Initialize default users
     */
    private void initializeUsers() {
        // Admin user from configuration
        users.put(adminUsername, passwordEncoder.encode(adminPassword));

        // Operator user from configuration
        users.put(operatorUsername, passwordEncoder.encode(operatorPassword));
    }
    
    /**
     * Validate user credentials
     */
    public boolean validateCredentials(String username, String password) {
        try {
            UserDetails userDetails = loadUserByUsername(username);
            return passwordEncoder.matches(password, userDetails.getPassword());
        } catch (UsernameNotFoundException e) {
            return false;
        }
    }
}
