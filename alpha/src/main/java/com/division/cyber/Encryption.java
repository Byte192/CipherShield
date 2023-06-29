package com.division.cyber;

import java.security.Key;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
    private static final String ENCRYPTIO_ALGORITHM = "RC4";

    public static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTIO_ALGORITHM);
        Key secretKey = new SecretKeySpec(key, ENCRYPTIO_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        try {
            byte[] key = "MySecretKey".getBytes();
            byte[] data = "Hello, World!".getBytes();

            byte[] encryptedData = encrypt(key, data);
            System.out.println("Encrypted data: " + Arrays.toString(encryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
