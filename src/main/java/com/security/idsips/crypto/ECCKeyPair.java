package com.security.idsips.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Wrapper class for ECC key pairs
 */
public class ECCKeyPair {
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    
    public ECCKeyPair(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
    
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
