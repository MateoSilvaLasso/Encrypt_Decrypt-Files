package com.example.encryptdecript;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.control.PasswordField;
import javafx.stage.FileChooser;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

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

                SecretKey key = generateKey(passwordField.getText(), salt);

                byte[] hash = calculateFileHash(inputFile);

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

                try (FileInputStream fis = new FileInputStream(inputFile)) {
                    byte[] salt = new byte[SALT_LENGTH];
                    byte[] iv = new byte[IV_LENGTH];

                    if (fis.read(salt) != SALT_LENGTH) {
                        throw new IOException("No se pudo leer el salt del archivo cifrado.");
                    }
                    if (fis.read(iv) != IV_LENGTH) {
                        throw new IOException("No se pudo leer el IV del archivo cifrado.");
                    }

                    SecretKey key = generateKey(passwordField.getText(), salt);

                    long headerLength = SALT_LENGTH + IV_LENGTH;

                    decryptFileWithKey(inputFile, outputFile, key, iv, headerLength);

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
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

            fos.write(salt);
            fos.write(iv);

            byte[] buffer = new byte[8192];
            int bytesRead;
            long totalBytes = inputFile.length();
            long processedBytes = 0;

            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
                processedBytes += bytesRead;
                updateUI("Cifrando archivo...", (double) processedBytes / totalBytes);
            }

            cos.flush();
        }

        try (FileOutputStream fos = new FileOutputStream(outputFile, true)) {
            fos.write(hash);
        }
    }

    private void decryptFileWithKey(File inputFile, File outputFile, SecretKey key, byte[] iv, long headerLength)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        final int HASH_SIZE = 32;

        try (RandomAccessFile raf = new RandomAccessFile(inputFile, "r")) {
            long fileLength = raf.length();

            raf.seek(fileLength - HASH_SIZE);
            byte[] storedHash = new byte[HASH_SIZE];
            raf.readFully(storedHash);

            try (FileInputStream fis = new FileInputStream(inputFile);
                 CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(outputFile)) {

                fis.skip(headerLength);

                byte[] buffer = new byte[8192];
                int bytesRead;
                long encryptedDataSize = fileLength - headerLength - HASH_SIZE;
                long processedBytes = 0;

                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    processedBytes += bytesRead;
                    updateUI("Descifrando archivo...", (double) processedBytes / encryptedDataSize);
                }
            }

            byte[] computedHash = calculateFileHash(outputFile);

            if (!Arrays.equals(storedHash, computedHash)) {
                outputFile.delete();
                throw new Exception("El hash no coincide. La contraseña es incorrecta o el archivo está corrupto.");
            }
        }
    }
}
