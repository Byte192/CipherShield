package com.division.cyber;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class Decryption {
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int KEY_LENGTH_BIT = 256;

    public static String decrypt(String key, String encryptedData) throws Exception {
        byte[] keyBytes = generateKeyBytes(key);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] iv = new byte[IV_LENGTH_BYTE];
        byte[] encryptedContent = new byte[encryptedBytes.length - IV_LENGTH_BYTE];

        System.arraycopy(encryptedBytes, 0, iv, 0, IV_LENGTH_BYTE);
        System.arraycopy(encryptedBytes, IV_LENGTH_BYTE, encryptedContent, 0, encryptedContent.length);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedContent);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] generateKeyBytes(String key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedkey = digest.digest(key.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = new byte[KEY_LENGTH_BIT / 8];
        System.arraycopy(hashedkey, 0, keyBytes, 0, keyBytes.length);
        return keyBytes;
    }

    public static void main(String[] args) {
        try {
            String key = "MySecretKey";
            String encryptedData = "QFHZX7fQMz73Ip8+vj7lKBFyfBxa06u51srh7kYEsZP4LHdQd6l/pxc=";

            String decryptedData = decrypt(key, encryptedData);
            System.out.println("Decrypted data: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
