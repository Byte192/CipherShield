package com.division.cyber;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public class Decryption {
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int KEY_LENGTH_BIT = 256;

    public static void decryptFile(String key, File encryptedFile) throws Exception {
        byte[] keyBytes = generateKeyBytes(key);

        File decryptedFile = new File(encryptedFile.getParent(), "decrypted_" + encryptedFile.getName());

        try (FileInputStream inputStream = new FileInputStream(encryptedFile);
             FileOutputStream outputStream = new FileOutputStream(decryptedFile)) {

            byte[] iv = new byte[IV_LENGTH_BYTE];
            inputStream.read(iv);

            byte[] encryptedContent = new byte[inputStream.available()];
            inputStream.read(encryptedContent);

            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

            byte[] decryptedBytes = cipher.doFinal(encryptedContent);

            outputStream.write(decryptedBytes);
        }

        // Delete the original encrypted file
        if (encryptedFile.delete()) {
            // Rename the decrypted file to the original file name
            decryptedFile.renameTo(encryptedFile);
            System.out.println("File decrypted successfully.");
        } else {
            System.out.println("Failed to delete the original encrypted file.");
        }
    }

    private static byte[] generateKeyBytes(String key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = digest.digest(key.getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(hashedKey, KEY_LENGTH_BIT / 8);
    }

    public static void main(String[] args) {
        try {
            String key = "MySecretKey";
            File encryptedFile = new File("/home/gravity/Downloads/CipherShield/alpha/src/main/java/com/division/cyber/randomcode.py");

            decryptFile(key, encryptedFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}



