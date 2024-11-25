package com.example.encryptdecript;

import javafx.application.Platform;
import javafx.scene.control.TextField;
import javafx.scene.control.PasswordField;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CipherControllerTest {

    @Test
    void testEncryptionDecryption() throws Exception {
 
        Platform.startup(() -> {});

        TextField mockFilePathField = new TextField();
        PasswordField mockPasswordField = new PasswordField();


        CipherController cipherController = new CipherController();

  
        setPrivateField(cipherController, "filePathField", mockFilePathField);
        setPrivateField(cipherController, "passwordField", mockPasswordField);

        File tempFile = File.createTempFile("testfile", ".txt");
        String originalContent = "This is a test file for encryption and decryption.";
        try (FileWriter writer = new FileWriter(tempFile)) {
            writer.write(originalContent);
        }

        mockFilePathField.setText(tempFile.getAbsolutePath());
        mockPasswordField.setText("strongpassword123");


        cipherController.encryptFile();
        Thread.sleep(2000); 

        File encryptedFile = cipherController.getEncryptedFileName(tempFile);
        assertTrue(encryptedFile.exists(), "El archivo cifrado debería existir");

        mockFilePathField.setText(encryptedFile.getAbsolutePath());

        cipherController.decryptFile();
        Thread.sleep(2000); 

 
        File decryptedFile = cipherController.getDecryptedFileName(encryptedFile);
        assertTrue(decryptedFile.exists(), "El archivo descifrado debería existir");

        String decryptedContent = new String(Files.readAllBytes(decryptedFile.toPath()), StandardCharsets.UTF_8);
        assertTrue(originalContent.equals(decryptedContent), "El contenido descifrado debería coincidir con el original");


        tempFile.delete();
        encryptedFile.delete();
        decryptedFile.delete();
    }


    private static void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        var field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}
