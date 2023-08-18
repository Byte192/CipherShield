package com.division.cyber.Cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * The Decryption class provides methods for decrypting files encrypted using
 * AES-GCM encryption.
 * It reads an encrypted file, decrypts its content using the provided key, and
 * writes the decrypted content to a new file.
 * The original encrypted file is then deleted, and the decrypted file is
 * renamed to match the original file name.
 */
public class Decryption {
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int KEY_LENGTH_BIT = 256;

    /**
     * Decrypts an encrypted file using the provided key.
     *
     * @param key           The decryption key.
     * @param encryptedFile The file to be decrypted.
     * @throws Exception If an error occurs during the decryption process.
     */
    public static void decryptFile(String key, File encryptedFile) throws Exception {
        byte[] keyBytes = generateKeyBytes(key);

        // Create a new file to store the decrypted content
        File decryptedFile = new File(encryptedFile.getParent(), "decrypted_" + encryptedFile.getName());

        try (FileInputStream inputStream = new FileInputStream(encryptedFile);
                FileOutputStream outputStream = new FileOutputStream(decryptedFile)) {

            // Read the initialization vector (IV) from the encrypted file
            byte[] iv = new byte[IV_LENGTH_BYTE];
            inputStream.read(iv);

            // Read the encrypted content from the file
            byte[] encryptedContent = new byte[inputStream.available()];
            inputStream.read(encryptedContent);

            // Initialize the cipher for decryption
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

            // Decrypt the content
            byte[] decryptedBytes = cipher.doFinal(encryptedContent);

            // Write the decrypted content to the new file
            outputStream.write(decryptedBytes);
        }

        // Delete the original encrypted file and rename the decrypted file
        if (encryptedFile.delete()) {
            decryptedFile.renameTo(encryptedFile);
            System.out.println("File decrypted successfully.");
        } else {
            System.out.println("Failed to delete the original encrypted file.");
        }
    }

    /**
     * Generates key bytes from the provided key using SHA-256 hash function.
     *
     * @param key The key for key generation.
     * @return The generated key bytes.
     * @throws Exception If an error occurs during key generation.
     */
    private static byte[] generateKeyBytes(String key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = digest.digest(key.getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(hashedKey, KEY_LENGTH_BIT / 8);
    }

    public static void main(String[] args) {
        try {
            // Example usage:
            String key = "MySecretKey";
            File encryptedFile = new File("/path/to/encrypted/file");

            decryptFile(key, encryptedFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
