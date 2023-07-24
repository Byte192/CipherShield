package com.division.cyber;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;

public class EncryptionTest {

    @Test
    public void testEncryptionAndDecryption() throws Exception {
        // Test data
        String testData = "This is a test file";
        String key = "MySecretKey";
        File file = new File("testText.txt");

        // Write test data to file
        Files.write(file.toPath(), testData.getBytes());

        // Make a copy of the file before encryption
        File copyFile = new File("testText_copy.text");

        // Encrypt the file
        Encryption.encrypt(key, file);

        // Decrypt the file
        Decryption.decryptFile(key, file);

        // Read decrypted file content
        byte[] decryptedData = Files.readAllBytes(file.toPath());

        // Read copy file content
        byte[] copyData = Files.readAllBytes(copyFile.toPath());

        // Clean up the test files
        Files.deleteIfExists(file.toPath());
        Files.deleteIfExists(copyFile.toPath());

        // Compare decrypted data with the original copy
        Assertions.assertTrue(Arrays.equals(copyData, decryptedData));
    }
}
