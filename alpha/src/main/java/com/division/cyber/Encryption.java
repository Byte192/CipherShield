package com.division.cyber;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

public class Encryption {
    public static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int KEY_LENGTH_BIT = 256;

    public static void encrypt(String key, File file) throws Exception {
        byte[] keyBytes = generateKeyBytes(key);
        byte[] iv = generateRandomBytes(IV_LENGTH_BYTE);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        Path filePath = file.toPath();
        byte[] fileBytes = Files.readAllBytes(filePath);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        try (FileOutputStream outputStream = new FileOutputStream(file)){
            outputStream.write(iv);
            outputStream.write(encryptedBytes);
        }
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
            File file = new File("/home/gravity/Downloads/CipherShield/alpha/src/main/java/com/division/cyber/randomcode.py");

            encrypt(key, file);
            System.out.println("File encrypted successfully.");
        } catch (Error e) {
            e.printStackTrace();
        }
    }
}