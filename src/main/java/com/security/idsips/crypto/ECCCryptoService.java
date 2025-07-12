package com.security.idsips.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * ECC Cryptographic Service for encryption, decryption, and key management
 */
@Service
public class ECCCryptoService {
    
    private static final Logger logger = LoggerFactory.getLogger(ECCCryptoService.class);
    
    @Value("${idsips.security.ecc.algorithm:secp256r1}")
    private String eccCurve;

    @Value("${idsips.security.ecc.aes-key-length:16}")
    private int aesKeyLength;

    @Value("${idsips.security.ecc.ephemeral-key-length:91}")
    private int ephemeralKeyLength;
    
    private ECCKeyPair systemKeyPair;
    
    /**
     * Initialize the service and generate system key pair
     */
    @PostConstruct
    public void init() {
        try {
            this.systemKeyPair = generateKeyPair();
            logger.info("ECC Crypto Service initialized with curve: {}", eccCurve);
        } catch (Exception e) {
            logger.error("Failed to initialize ECC Crypto Service", e);
            throw new RuntimeException("ECC initialization failed", e);
        }
    }
    
    /**
     * Generate a new ECC key pair
     */
    public ECCKeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(eccCurve);
        keyGen.initialize(ecSpec, new SecureRandom());
        
        KeyPair keyPair = keyGen.generateKeyPair();
        return new ECCKeyPair(keyPair.getPublic(), keyPair.getPrivate());
    }
    
    /**
     * Get the system's public key as Base64 encoded string
     */
    public String getSystemPublicKeyBase64() {
        if (systemKeyPair == null) {
            init();
        }
        return Base64.toBase64String(systemKeyPair.getPublicKey().getEncoded());
    }
    
    /**
     * Get the system's public key in PEM format
     */
    public String getSystemPublicKeyPEM() {
        String base64Key = getSystemPublicKeyBase64();
        return "-----BEGIN PUBLIC KEY-----\n" + 
               formatBase64(base64Key) + 
               "\n-----END PUBLIC KEY-----";
    }
    
    /**
     * Encrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme)
     */
    public String encrypt(String plaintext, PublicKey publicKey) throws Exception {
        // Generate ephemeral key pair
        ECCKeyPair ephemeralKeyPair = generateKeyPair();
        
        // Perform ECDH key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
        keyAgreement.init(ephemeralKeyPair.getPrivateKey());
        keyAgreement.doPhase(publicKey, true);
        
        // Derive AES key from shared secret
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] aesKey = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(sharedSecret), aesKeyLength);
        
        // Encrypt with AES
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(plaintext.getBytes());
        
        // Combine ephemeral public key + encrypted data
        byte[] ephemeralPublicKey = ephemeralKeyPair.getPublicKey().getEncoded();
        byte[] result = new byte[ephemeralPublicKey.length + encryptedData.length];
        System.arraycopy(ephemeralPublicKey, 0, result, 0, ephemeralPublicKey.length);
        System.arraycopy(encryptedData, 0, result, ephemeralPublicKey.length, encryptedData.length);
        
        return Base64.toBase64String(result);
    }
    
    /**
     * Decrypt data using ECIES
     */
    public String decrypt(String encryptedData, PrivateKey privateKey) throws Exception {
        byte[] data = Base64.decode(encryptedData);
        
        // Extract ephemeral public key (first ephemeralKeyLength bytes for configured curve)
        byte[] ephemeralPublicKeyBytes = Arrays.copyOf(data, ephemeralKeyLength);
        byte[] encryptedBytes = Arrays.copyOfRange(data, ephemeralKeyLength, data.length);
        
        // Reconstruct ephemeral public key
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PublicKey ephemeralPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(ephemeralPublicKeyBytes));
        
        // Perform ECDH key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(ephemeralPublicKey, true);
        
        // Derive AES key from shared secret
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] aesKey = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(sharedSecret), aesKeyLength);
        
        // Decrypt with AES
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = cipher.doFinal(encryptedBytes);
        
        return new String(decryptedData);
    }
    
    /**
     * Encrypt using system's public key
     */
    public String encryptWithSystemKey(String plaintext) throws Exception {
        if (systemKeyPair == null) {
            init();
        }
        return encrypt(plaintext, systemKeyPair.getPublicKey());
    }
    
    /**
     * Decrypt using system's private key
     */
    public String decryptWithSystemKey(String encryptedData) throws Exception {
        if (systemKeyPair == null) {
            init();
        }
        return decrypt(encryptedData, systemKeyPair.getPrivateKey());
    }
    
    /**
     * Sign data using ECDSA
     */
    public String sign(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.toBase64String(signatureBytes);
    }
    
    /**
     * Verify signature using ECDSA
     */
    public boolean verify(String data, String signatureBase64, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        signature.initVerify(publicKey);
        signature.update(data.getBytes());
        byte[] signatureBytes = Base64.decode(signatureBase64);
        return signature.verify(signatureBytes);
    }
    
    /**
     * Parse public key from Base64 string
     */
    public PublicKey parsePublicKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.decode(base64Key);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }
    
    /**
     * Parse private key from Base64 string
     */
    public PrivateKey parsePrivateKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.decode(base64Key);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }
    
    /**
     * Format Base64 string for PEM format (64 characters per line)
     */
    private String formatBase64(String base64) {
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < base64.length(); i += 64) {
            formatted.append(base64, i, Math.min(i + 64, base64.length()));
            if (i + 64 < base64.length()) {
                formatted.append("\n");
            }
        }
        return formatted.toString();
    }
}
