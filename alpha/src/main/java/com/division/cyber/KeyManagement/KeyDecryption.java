package com.division.cyber.KeyManagement;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * The KeyDecryption class decrypts an AES encryption key
 * that was previously encrypted using the KeyEncryption class.
 */
public class KeyDecryption {

    /**
     * Decrypts an AES encryption key using the AES/GCM/NoPadding algorithm.
     *
     * @param encryptedKey  The encrypted key as a Base64-encoded string.
     * @param decryptionKey The decryption key used for decryption.
     * @return The decrypted AES key as a byte array.
     * @throws Exception If an error occurs during decryption.
     */
    public static byte[] decryptKey(String encryptedKey, byte[] decryptionKey) throws Exception {
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKey);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(decryptionKey, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        return cipher.doFinal(encryptedKeyBytes);
    }

    public static void main(String[] args) {
        try {
            // Encrypted AES key from the KeyEncryption class
            String encryptedKey = "SVxj9krgVNWwrooKcjPlYDJFX6Scve6BypGXV+O0CTpl21zAyPuFwm5qV0Lhrbm0";

            // Decryption key for decrypting the AES key
            byte[] decryptionKey = "BD461013D977EAF6FDD07F87D3F9075BFE5CE95A0E32D34E73DC71E7E0043C19".getBytes();

            // Decrypt the AES key
            byte[] decryptedKey = decryptKey(encryptedKey, decryptionKey);

            System.out.println("Decrypted AES Key: " + bytesToHexString(decryptedKey));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Converts a byte array to a hexadecimal string representation.
     *
     * @param bytes The byte array to convert.
     * @return The hexadecimal string representation of the byte array.
     */
    private static String bytesToHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }
}
