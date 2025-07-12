package com.security.idsips.api.dto;

/**
 * Login response DTO
 */
public class LoginResponse {
    
    private String token;
    private Long expiresIn;
    
    // Constructors
    public LoginResponse() {}
    
    public LoginResponse(String token, Long expiresIn) {
        this.token = token;
        this.expiresIn = expiresIn;
    }
    
    // Getters and Setters
    public String getToken() {
        return token;
    }
    
    public void setToken(String token) {
        this.token = token;
    }
    
    public Long getExpiresIn() {
        return expiresIn;
    }
    
    public void setExpiresIn(Long expiresIn) {
        this.expiresIn = expiresIn;
    }
}
