package com.security.idsips.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ECC Crypto Service
 */
@SpringBootTest
@TestPropertySource(properties = {
    "idsips.security.ecc.algorithm=secp256r1"
})
class ECCCryptoServiceTest {
    
    private ECCCryptoService eccCryptoService;
    
    @BeforeEach
    void setUp() {
        eccCryptoService = new ECCCryptoService();
        eccCryptoService.init();
    }
    
    @Test
    void testKeyPairGeneration() throws Exception {
        ECCKeyPair keyPair = eccCryptoService.generateKeyPair();
        
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getPrivateKey());
        assertEquals("EC", keyPair.getPublicKey().getAlgorithm());
        assertEquals("EC", keyPair.getPrivateKey().getAlgorithm());
    }
    
    @Test
    void testSystemKeyGeneration() {
        String publicKeyBase64 = eccCryptoService.getSystemPublicKeyBase64();
        String publicKeyPEM = eccCryptoService.getSystemPublicKeyPEM();
        
        assertNotNull(publicKeyBase64);
        assertNotNull(publicKeyPEM);
        assertTrue(publicKeyPEM.contains("-----BEGIN PUBLIC KEY-----"));
        assertTrue(publicKeyPEM.contains("-----END PUBLIC KEY-----"));
    }
    
    @Test
    void testEncryptionDecryption() throws Exception {
        String plaintext = "This is a test message for ECC encryption";
        
        // Test encryption and decryption with system key
        String encrypted = eccCryptoService.encryptWithSystemKey(plaintext);
        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);
        
        String decrypted = eccCryptoService.decryptWithSystemKey(encrypted);
        assertEquals(plaintext, decrypted);
    }
    
    @Test
    void testEncryptionWithDifferentKeys() throws Exception {
        String plaintext = "Test message";
        
        // Generate two different key pairs
        ECCKeyPair keyPair1 = eccCryptoService.generateKeyPair();
        ECCKeyPair keyPair2 = eccCryptoService.generateKeyPair();
        
        // Encrypt with first key pair's public key
        String encrypted = eccCryptoService.encrypt(plaintext, keyPair1.getPublicKey());
        
        // Decrypt with first key pair's private key
        String decrypted = eccCryptoService.decrypt(encrypted, keyPair1.getPrivateKey());
        assertEquals(plaintext, decrypted);
        
        // Attempting to decrypt with wrong private key should fail
        assertThrows(Exception.class, () -> {
            eccCryptoService.decrypt(encrypted, keyPair2.getPrivateKey());
        });
    }
    
    @Test
    void testDigitalSignature() throws Exception {
        String data = "Data to be signed";
        ECCKeyPair keyPair = eccCryptoService.generateKeyPair();
        
        // Sign data
        String signature = eccCryptoService.sign(data, keyPair.getPrivateKey());
        assertNotNull(signature);
        
        // Verify signature
        boolean isValid = eccCryptoService.verify(data, signature, keyPair.getPublicKey());
        assertTrue(isValid);
        
        // Verify with wrong data should fail
        boolean isInvalid = eccCryptoService.verify("Wrong data", signature, keyPair.getPublicKey());
        assertFalse(isInvalid);
    }
    
    @Test
    void testKeyParsing() throws Exception {
        ECCKeyPair keyPair = eccCryptoService.generateKeyPair();
        
        // Convert keys to Base64
        String publicKeyBase64 = java.util.Base64.getEncoder().encodeToString(keyPair.getPublicKey().getEncoded());
        String privateKeyBase64 = java.util.Base64.getEncoder().encodeToString(keyPair.getPrivateKey().getEncoded());
        
        // Parse keys back
        var parsedPublicKey = eccCryptoService.parsePublicKey(publicKeyBase64);
        var parsedPrivateKey = eccCryptoService.parsePrivateKey(privateKeyBase64);
        
        assertNotNull(parsedPublicKey);
        assertNotNull(parsedPrivateKey);
        
        // Test that parsed keys work for encryption/decryption
        String plaintext = "Test with parsed keys";
        String encrypted = eccCryptoService.encrypt(plaintext, parsedPublicKey);
        String decrypted = eccCryptoService.decrypt(encrypted, parsedPrivateKey);
        
        assertEquals(plaintext, decrypted);
    }
    
    @Test
    void testLargeDataEncryption() throws Exception {
        // Test with larger data
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("This is line ").append(i).append(" of test data. ");
        }
        String largeData = sb.toString();
        
        String encrypted = eccCryptoService.encryptWithSystemKey(largeData);
        String decrypted = eccCryptoService.decryptWithSystemKey(encrypted);
        
        assertEquals(largeData, decrypted);
    }
}
