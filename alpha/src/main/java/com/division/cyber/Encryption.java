package com.division.cyber;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class Encryption {
    public static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int KEY_LENGTH_BIT = 256;

    public static String encrypt(String key, String data) throws Exception {
        byte[] keyBytes = generateKeyBytes(key);
        byte[] iv = generateRandomBytes(IV_LENGTH_BYTE);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedData = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, encryptedData, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(encryptedData);
    }

    private static byte[] generateKeyBytes(String key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedkey = digest.digest(key.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = new byte[KEY_LENGTH_BIT / 8];
        System.arraycopy(hashedkey, 0, keyBytes, 0, keyBytes.length);
        return keyBytes;
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new java.security.SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static void main(String[] args) throws Exception {
        try {
            String key = "MySecretKey";
            String data = "Hello, World!";

            String encryptedData = encrypt(key, data);
            System.out.println("Encrypted data: " + encryptedData);
        } catch (Error e) {
            e.printStackTrace();
        }
    }
}