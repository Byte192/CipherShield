package com.division.cyber.KeyManagement;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.Base64;
import java.util.Scanner;

/**
 * The KeyEncryption class generates a 256-bit AES encryption key
 * and encrypts it using the AES/GCM/NoPadding encryption algorithm.
 */
public class KeyEncryption {

    /**
     * Generates a new 256-bit AES encryption key.
     *
     * @return The generated encryption key as a byte array.
     */
    public static byte[] generateAESKey() {
        byte[] aeskey = new byte[256 / 8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(aeskey);
        return aeskey;
    }

    /**
     * Encrypts an AES encryption key using the AES/GCM/NoPadding algorithm
     * and saves the encrypted key in a database.
     *
     * @param keyToEncrypt  The key to be encrypted.
     * @param encryptionKey The encryption key used for encryption.
     * @param id            The id/name under which the encrypted key will be saved.
     * @throws Exception If an error occurs during encryption or database operation.
     */
    public static void encryptAndSaveKey(byte[] keyToEncrypt, byte[] encryptionKey, String id) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(encryptionKey, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] encryptedKey = cipher.doFinal(keyToEncrypt);
        String encryptedKeyBase64 = Base64.getEncoder().encodeToString(encryptedKey);

        // Save the encrypted key in the database
        saveEncryptedKeyToDatabase(id, encryptedKeyBase64);
    }

    /**
     * Saves the encrypted key in a database.
     *
     * @param id           The id/name under which the encrypted key will be saved.
     * @param encryptedKey The encrypted key as a Base64-encoded string.
     * @throws Exception If a database error occurs.
     */
    private static void saveEncryptedKeyToDatabase(String id, String encryptedKey) throws Exception {
        // Replac with your databas connection details
        String jdbcUrl = "jdbc:sqlite:alpha/src/main/java/com/division/cyber/KeyManagement/Keys.db";
        String username = "your_username";
        String password = "your_password";

        try (Connection connection = DriverManager.getConnection(jdbcUrl, username, password)) {
            String insertSql = "INSERT INTO encryption_keys (id, encrypted_key) VALUES (?, ?)";
            try (PreparedStatement preparedStatement = connection.prepareStatement(insertSql)) {
                preparedStatement.setString(1, id);
                preparedStatement.setString(2, encryptedKey);
                preparedStatement.executeUpdate();
            }
        }
    }

    public static void main(String[] args) {
        try {
            try (Scanner scanner = new Scanner(System.in)) {
                System.out.print("Enter the id/name to save the key under: ");
                String id = scanner.nextLine();

                // Generate a new AES encryption key
                byte[] aesKey = generateAESKey();

                // Encryption key for encrypting the AES key
                byte[] encryptionKey = generateAESKey();

                // Encrypt the AES key and save it in the database
                encryptAndSaveKey(aesKey, encryptionKey, id);
            }
            System.out.println("AES Key encrypted and saved successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
