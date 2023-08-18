package com.division.cyber.KeyManagement;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * The KeyGen class provides methods for generating encryption keys.
 * It uses a cryptographically secure random number generator (RNG)
 * to ensure the generated keys are secure and unpredictable.
 */

public class KeyGen {
    /**
     * Generates a new encryption key of the specified key length in bits.
     *
     * @param keyLengthBit The desired key length in bits (e.g., 128, 256).
     * @return The generated encryption key as a byte array.
     * @throws NoSuchAlgorithmException If a secure random number generator is not
     *                                  available.
     */
    public static byte[] generateEncryptionKey(int keyLengthBit) throws NoSuchAlgorithmException {
        // Initialize a secure random number generator
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();

        // Generate a random key of the specified length
        byte[] key = new byte[keyLengthBit / 8];
        secureRandom.nextBytes(key);

        return key;
    }

    public static void main(String[] args) throws Exception {
        try {
            int keyLengthBit = 256;
            byte[] encryptionKey = generateEncryptionKey(keyLengthBit);
            System.out.println("Generated Encryption Key: " + bytesToHexString(encryptionKey));

        } catch (NoSuchAlgorithmException e) {
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
