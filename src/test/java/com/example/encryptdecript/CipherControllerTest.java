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
        // Inicializar JavaFX
        new Thread(() -> Platform.startup(() -> {})).start();

        // Cargar el archivo FXML y el controlador
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/example/encryptdecript/principal-view.fxml"));
        Parent root = loader.load();
        controller = loader.getController();

        // Simular campos de texto
        controller.filePathField = new TextField();
        controller.passwordField = new PasswordField();
    }

    @Test
    void testValidateInputs() throws Exception {
    // Caso: campos vacíos
    controller.filePathField.setText("");
    controller.passwordField.setText("");
    assertFalse(controller.validateInputs());

    // Caso: archivo inexistente
    controller.filePathField.setText("nonexistent_file.txt");
    controller.passwordField.setText("password123");
    assertFalse(controller.validateInputs());

    // Caso: archivo válido
    File tempFile = new File("tempFile.txt");
    tempFile.createNewFile(); // Crear el archivo físico
    tempFile.deleteOnExit(); // Asegurar que se elimine después del test

    controller.filePathField.setText(tempFile.getAbsolutePath());
    controller.passwordField.setText("password123");
    assertTrue(controller.validateInputs());
}


@Test
void testEncryptAndDecryptFile() throws Exception {
    // Ruta fija para el archivo de entrada
    File inputFile = new File("src/test/resources/testFile.txt");

    // Crear el archivo de entrada si no existe
    if (!inputFile.exists()) {
        inputFile.getParentFile().mkdirs(); // Crear directorio si no existe
        try (FileWriter writer = new FileWriter(inputFile)) {
            writer.write("Este es un archivo de prueba para cifrado.");
        }
    }

    assertTrue(inputFile.exists(), "El archivo de entrada no existe.");

    // Ruta fija para los archivos cifrado y descifrado
    File encryptedFile = new File("src/test/resources/testFile.txt.encrypted");
    File decryptedFile = new File("src/test/resources/testFile.txt.decrypted");

    // Asegurarse de eliminar archivos anteriores si existen
    if (encryptedFile.exists()) encryptedFile.delete();
    if (decryptedFile.exists()) decryptedFile.delete();

    // Configurar campos del controlador
    controller.filePathField.setText(inputFile.getAbsolutePath());
    controller.passwordField.setText("securePassword123");

    // Ejecutar cifrado
    controller.encryptFile();

    // Esperar un breve tiempo para que el hilo termine
    Thread.sleep(1000);

    // Verificar que el archivo cifrado exista
    assertTrue(encryptedFile.exists(), "El archivo cifrado no fue creado.");

    // Configurar para descifrado
    controller.filePathField.setText(encryptedFile.getAbsolutePath());
    controller.decryptFile();

    // Esperar un breve tiempo para que el hilo termine
    Thread.sleep(1000);

    // Verificar que el archivo descifrado exista
    assertTrue(decryptedFile.exists(), "El archivo descifrado no fue creado.");
}



}
