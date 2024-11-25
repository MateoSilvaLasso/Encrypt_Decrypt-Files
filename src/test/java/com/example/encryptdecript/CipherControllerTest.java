package com.example.encryptdecript;

import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.control.TextField;
import javafx.scene.control.PasswordField;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;

import static org.junit.jupiter.api.Assertions.*;

class CipherControllerTest {

    private CipherController controller;

    @BeforeEach
    void setUp() throws Exception {
        new Thread(() -> Platform.startup(() -> {})).start();

        FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/example/encryptdecript/principal-view.fxml"));
        Parent root = loader.load();
        controller = loader.getController();

        controller.filePathField = new TextField();
        controller.passwordField = new PasswordField();
    }

    @Test
    void testValidateInputs() throws Exception {
        controller.filePathField.setText("");
        controller.passwordField.setText("");
        assertFalse(controller.validateInputs());

        controller.filePathField.setText("nonexistent_file.txt");
        controller.passwordField.setText("password123");
        assertFalse(controller.validateInputs());

        File tempFile = new File("tempFile.txt");
        tempFile.createNewFile();
        tempFile.deleteOnExit();

        controller.filePathField.setText(tempFile.getAbsolutePath());
        controller.passwordField.setText("password123");
        assertTrue(controller.validateInputs());
    }

    @Test
    void testEncryptAndDecryptFile() throws Exception {
        File inputFile = new File("src/test/resources/testFile.txt");

        if (!inputFile.exists()) {
            inputFile.getParentFile().mkdirs();
            try (FileWriter writer = new FileWriter(inputFile)) {
                writer.write("Este es un archivo de prueba para cifrado.");
            }
        }

        assertTrue(inputFile.exists(), "El archivo de entrada no existe.");

        File encryptedFile = new File("src/test/resources/testFile.txt.encrypted");
        File decryptedFile = new File("src/test/resources/testFile.txt.decrypted");

        if (encryptedFile.exists()) encryptedFile.delete();
        if (decryptedFile.exists()) decryptedFile.delete();

        controller.filePathField.setText(inputFile.getAbsolutePath());
        controller.passwordField.setText("securePassword123");

        controller.encryptFile();
        Thread.sleep(1000);

        assertTrue(encryptedFile.exists(), "El archivo cifrado no fue creado.");

        controller.filePathField.setText(encryptedFile.getAbsolutePath());
        controller.decryptFile();
        Thread.sleep(1000);

        assertTrue(decryptedFile.exists(), "El archivo descifrado no fue creado.");
    }
}
