package com.division.cyber.Cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

/**
 * The Encryption class provides methods for encrypting files using the AES-GCM
 * encryption algorithm.
 * It generates a random initialization vector (IV) and uses a derived
 * encryption key for the encryption process.
 */
public class Encryption {

    /** The encryption algorithm and mode to be used. */
    public static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";

    /** The length of the authentication tag (in bits) used for GCM. */
    private static final int TAG_LENGTH_BIT = 128;

    /** The length of the initialization vector (IV) in bytes. */
    private static final int IV_LENGTH_BYTE = 12;

    /** The desired length of the encryption key in bits. */
    private static final int KEY_LENGTH_BIT = 256;

    /**
     * Encrypts the contents of a file using AES-GCM encryption.
     *
     * @param key  The encryption key (passphrase) used for encryption.
     * @param file The file to be encrypted.
     * @throws Exception If an error occurs during encryption.
     */
    public static void encrypt(String key, File file) throws Exception {
        // Generate encryption key bytes from the provided key
        byte[] keyBytes = generateKeyBytes(key);

        // Generate a random initialization vector (IV)
        byte[] iv = generateRandomBytes(IV_LENGTH_BYTE);

        // Initialize the AES-GCM cipher with the key and IV
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        // Read the contents of the file to be encrypted
        Path filePath = file.toPath();
        byte[] fileBytes = Files.readAllBytes(filePath);

        // Perform the encryption and write the encrypted data to the file
        byte[] encryptedBytes = cipher.doFinal(fileBytes);
        try (FileOutputStream outputStream = new FileOutputStream(file)) {
            outputStream.write(iv);
            outputStream.write(encryptedBytes);
        }
    }

    /**
     * Generates encryption key bytes from the provided key using a SHA-256 hash.
     *
     * @param key The encryption key (passphrase).
     * @return The generated encryption key bytes.
     * @throws Exception If a hashing error occurs.
     */
    private static byte[] generateKeyBytes(String key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = digest.digest(key.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = new byte[KEY_LENGTH_BIT / 8];
        System.arraycopy(hashedKey, 0, keyBytes, 0, keyBytes.length);
        return keyBytes;
    }

    /**
     * Generates random bytes for use as an initialization vector (IV).
     *
     * @param length The length of the random byte array.
     * @return The generated random bytes.
     */
    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new java.security.SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static void main(String[] args) throws Exception {
        try {
            String key = "MySecretKey";
            File file = new File(
                    "/home/gravity/Downloads/CipherShield/alpha/src/main/java/com/division/cyber/randomcode.py");

            encrypt(key, file);
            System.out.println("File encrypted successfully.");
        } catch (Error e) {
            e.printStackTrace();
        }
    }
}
