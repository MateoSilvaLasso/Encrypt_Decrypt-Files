package com.example.encryptdecript;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.control.PasswordField;
import javafx.stage.FileChooser;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public class CipherController {
    @FXML
    private TextField filePathField;

    @FXML
    private PasswordField passwordField;

    @FXML
    private ProgressBar progressBar;

    @FXML
    private Label statusLabel;

    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;

    @FXML
    private void browseFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Seleccionar Archivo");
        File selectedFile = fileChooser.showOpenDialog(null);

        if (selectedFile != null) {
            filePathField.setText(selectedFile.getAbsolutePath());
            statusLabel.setText("Archivo seleccionado: " + selectedFile.getName());
        }
    }

    @FXML
    private void encryptFile() {
        if (!validateInputs()) return;

        Thread thread = new Thread(() -> {
            try {
                File inputFile = new File(filePathField.getText());
                File outputFile = new File(filePathField.getText() + ".encrypted");


                byte[] salt = generateRandomBytes(SALT_LENGTH);
                byte[] iv = generateRandomBytes(IV_LENGTH);


                SecretKey key = generateKey(passwordField.getText(), salt); //aqui es para meterle salt a la contraseña que meta el cliente y sea mas seguro

                // Calcular hash del archivo original
                byte[] hash = calculateFileHash(inputFile);

                // Cifrar el archivo
                encryptFileWithKey(inputFile, outputFile, key, iv, salt, hash);

                updateUI("Archivo cifrado exitosamente!", 1.0);
                Thread.sleep(500);
                progressBar.setProgress(0.0);

            } catch (Exception e) {
                updateUI("Error al cifrar: " + e.getMessage(), 0.0);
                e.printStackTrace();
            }
        });
        thread.start();
    }

    @FXML
    private void decryptFile() {
        if (!validateInputs()) return;

        Thread thread = new Thread(() -> {
            try {
                File inputFile = new File(filePathField.getText());
                File outputFile = new File(filePathField.getText() + ".decrypted");


                try (DataInputStream dis = new DataInputStream(new FileInputStream(inputFile))) {
                    byte[] salt = new byte[SALT_LENGTH];
                    byte[] iv = new byte[IV_LENGTH];
                    byte[] storedHash = new byte[32]; // SHA-256 = 32 bytes

                    dis.read(salt);
                    dis.read(iv);
                    dis.read(storedHash);


                    SecretKey key = generateKey(passwordField.getText(), salt);

                    // Descifrar el archivo
                    decryptFileWithKey(inputFile, outputFile, key, iv, SALT_LENGTH + IV_LENGTH + 32);

                    // aqui comprobamos si el has del archivo es el mismo o no, si no lo es, la contraseña es incorrecta
                    byte[] newHash = calculateFileHash(outputFile);
                    if (!Arrays.equals(storedHash, newHash)) {
                        outputFile.delete();
                        throw new Exception("El hash no coincide. La contraseña es incorrecta.");
                    }

                    updateUI("Archivo descifrado exitosamente!", 1.0);
                    Thread.sleep(500);
                    progressBar.setProgress(0.0);
                }
            } catch (Exception e) {
                updateUI("Error al descifrar: " + e.getMessage(), 0.0);
                e.printStackTrace();
            }
        });
        thread.start();
    }

    private boolean validateInputs() {
        if (filePathField.getText().isEmpty()) {
            updateUI("Por favor seleccione un archivo", 0.0);
            return false;
        }
        if (passwordField.getText().isEmpty()) {
            updateUI("Por favor ingrese una contraseña", 0.0);
            return false;
        }
        File file = new File(filePathField.getText());
        if (!file.exists()) {
            updateUI("El archivo no existe", 0.0);
            return false;
        }
        return true;
    }

    private void updateUI(String message, double progress) {
        javafx.application.Platform.runLater(() -> {
            statusLabel.setText(message);
            progressBar.setProgress(progress);
        });
    }

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private SecretKey generateKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private byte[] calculateFileHash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        return digest.digest();
    }

    private void encryptFileWithKey(File inputFile, File outputFile, SecretKey key, byte[] iv, byte[] salt, byte[] hash)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             DataOutputStream dos = new DataOutputStream(fos)) {


            dos.write(salt);
            dos.write(iv);
            dos.write(hash);

            byte[] buffer = new byte[8192];
            int bytesRead;
            long totalBytes = inputFile.length();
            long processedBytes = 0;

            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    dos.write(output);
                }
                processedBytes += bytesRead;
                updateUI("Cifrando archivo...", (double) processedBytes / totalBytes);
            }

            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                dos.write(outputBytes);
            }
        }
    }

    private void decryptFileWithKey(File inputFile, File outputFile, SecretKey key, byte[] iv, int headerLength)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Saltar el header (salt + IV + hash)
            fis.skip(headerLength);

            byte[] buffer = new byte[8192];
            int bytesRead;
            long totalBytes = inputFile.length() - headerLength;
            long processedBytes = 0;

            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    fos.write(output);
                }
                processedBytes += bytesRead;
                updateUI("Descifrando archivo...", (double) processedBytes / totalBytes);
            }

            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                fos.write(outputBytes);
            }
        }
    }
}