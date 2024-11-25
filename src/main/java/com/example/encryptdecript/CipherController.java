package com.example.encryptdecript;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.application.Platform;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Controller class for handling file encryption and decryption operations.
 * This class interacts with the JavaFX UI components defined in the corresponding FXML file.
 */
public class CipherController {
    @FXML
    public TextField filePathField;

    @FXML
    public PasswordField passwordField;

    @FXML
    private ProgressBar progressBar;

    @FXML
    private Label statusLabel;

    @FXML
    private Button downloadButton;

    private File lastProcessedFile;

    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;

    /**
     * Initializes the controller. This method is automatically called after the FXML elements are injected.
     * It ensures that the download button is disabled by default.
     */
    @FXML
    public void initialize() {
        if (downloadButton == null) {
            System.out.println("downloadButton is not being injected correctly.");
        } else {
            downloadButton.setDisable(true);
            System.out.println("downloadButton has been injected correctly.");
        }
    }

    /**
     * Enables or disables the download button on the JavaFX Application Thread.
     *
     * @param enable If true, enables the button; if false, disables it.
     */
    private void enableDownloadButton(boolean enable) {
        Platform.runLater(() -> downloadButton.setDisable(!enable));
    }

    /**
     * Opens a file chooser dialog for the user to select a file.
     * Updates the file path text field and the status label with the selected file's name.
     */
    @FXML
    private void browseFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File");
        File selectedFile = fileChooser.showOpenDialog(null);

        if (selectedFile != null) {
            filePathField.setText(selectedFile.getAbsolutePath());
            statusLabel.setText("Selected file: " + selectedFile.getName());
        }
    }

    /**
     * Encrypts the selected file using the provided password.
     * The encrypted file is saved with the suffix "_encrypted" before the original file extension.
     * After successful encryption, the download button is enabled.
     */
    @FXML
    public void encryptFile() {
        enableDownloadButton(false);
        if (!validateInputs()) return;

        Thread thread = new Thread(() -> {
            try {
                File inputFile = new File(filePathField.getText());
                File outputFile = getEncryptedFileName(inputFile);

                byte[] salt = generateRandomBytes(SALT_LENGTH);
                byte[] iv = generateRandomBytes(IV_LENGTH);

                SecretKey key = generateKey(passwordField.getText(), salt);

                byte[] hash = calculateFileHash(inputFile);

                encryptFileWithKey(inputFile, outputFile, key, iv, salt, hash);

                lastProcessedFile = outputFile;
                System.out.println("lastProcessedFile: " + lastProcessedFile.getAbsolutePath());
                updateUI("File encrypted successfully!", 1.0);
                Thread.sleep(500);
                Platform.runLater(() -> progressBar.setProgress(0.0));
                enableDownloadButton(true);

            } catch (Exception e) {
                if (e instanceof BadPaddingException) {
                    updateUI("Encryption error: The password is too weak or invalid.", 0.0);
                } else {
                    updateUI("Encryption error: " + e.getMessage(), 0.0);
                }
            }
        });
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Decrypts the selected encrypted file using the provided password.
     * The decrypted file is saved with the suffix "_decrypted" before the original file extension.
     * After successful decryption, the download button is enabled.
     */
    @FXML
    public void decryptFile() {
        enableDownloadButton(false);
        if (!validateInputs()) return;

        Thread thread = new Thread(() -> {
            try {
                File inputFile = new File(filePathField.getText());

                File outputFile;
                try {
                    outputFile = getDecryptedFileName(inputFile);
                } catch (IllegalArgumentException e) {
                    updateUI("Wrong password.", 0.0);
                    return;
                }

                byte[] salt = new byte[SALT_LENGTH];
                byte[] iv = new byte[IV_LENGTH];

                try (FileInputStream fis = new FileInputStream(inputFile)) {
                    if (fis.read(salt) != SALT_LENGTH) {
                        throw new IOException("Could not read the salt from the encrypted file.");
                    }
                    if (fis.read(iv) != IV_LENGTH) {
                        throw new IOException("Could not read the IV from the encrypted file.");
                    }

                    SecretKey key = generateKey(passwordField.getText(), salt);

                    long headerLength = SALT_LENGTH + IV_LENGTH;

                    decryptFileWithKey(inputFile, outputFile, key, iv, headerLength);

                    lastProcessedFile = outputFile;
                    System.out.println("lastProcessedFile: " + lastProcessedFile.getAbsolutePath());
                    updateUI("File decrypted successfully!", 1.0);
                    Thread.sleep(500);
                    Platform.runLater(() -> progressBar.setProgress(0.0));
                    enableDownloadButton(true);
                }
            } catch (BadPaddingException e) {
                updateUI("Decryption error: The password is incorrect or the file is corrupted.", 0.0);
            } catch (Exception e) {
                updateUI("Decryption error: " + e.getMessage(), 0.0);
            }
        });
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Allows the user to download the last processed file (encrypted or decrypted).
     * Automatically assigns a unique filename if a file with the same name already exists by appending "_1", "_2", etc.
     */
    @FXML
    private void downloadFile() {
        if (lastProcessedFile == null || !lastProcessedFile.exists()) {
            updateUI("No file to download. Please perform encryption or decryption first.", 0.0);
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save File");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All Files", "*.*")
        );

        fileChooser.setInitialFileName(lastProcessedFile.getName());

        File selectedFile = fileChooser.showSaveDialog(null);
        if (selectedFile == null) {
            updateUI("No download location selected.", 0.0);
            return;
        }

        File uniqueFile = getUniqueFile(selectedFile);

        try {
            Files.copy(lastProcessedFile.toPath(), uniqueFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            updateUI("File downloaded successfully as " + uniqueFile.getName() + "!", 1.0);
        } catch (IOException e) {
            updateUI("Error downloading the file: " + e.getMessage(), 0.0);
        }
    }

    /**
     * Validates the user inputs before performing encryption or decryption.
     * Ensures that a file is selected and a password is entered.
     *
     * @return true if the inputs are valid; false otherwise.
     */
    public boolean validateInputs() {
        if (filePathField.getText().isEmpty()) {
            updateUI("Please select a file.", 0.0);
            return false;
        }

        String password = passwordField.getText();
        if (password.isEmpty()) {
            updateUI("Please enter a password.", 0.0);
            return false;
        }

        File file = new File(filePathField.getText());
        if (!file.exists()) {
            updateUI("The selected file does not exist.", 0.0);
            return false;
        }

        return true;
    }

    /**
     * Updates the UI with a status message and progress.
     * This method ensures that UI updates are performed on the JavaFX Application Thread.
     *
     * @param message  The message to display.
     * @param progress The progress value (0.0 to 1.0).
     */
    private void updateUI(String message, double progress) {
        Platform.runLater(() -> {
            statusLabel.setText(message);
            progressBar.setProgress(progress);
        });
    }

    /**
     * Generates a byte array of random bytes with the specified length.
     *
     * @param length The number of random bytes to generate.
     * @return A byte array containing random bytes.
     */
    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates a secret key from the provided password and salt using PBKDF2 with HmacSHA256.
     *
     * @param password The password provided by the user.
     * @param salt     The random salt.
     * @return A SecretKey object suitable for AES encryption/decryption.
     * @throws Exception If an error occurs during key generation.
     */
    private SecretKey generateKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    /**
     * Calculates the SHA-256 hash of the given file.
     *
     * @param file The file to hash.
     * @return A byte array containing the SHA-256 hash of the file.
     * @throws Exception If an error occurs during hashing.
     */
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

    /**
     * Encrypts a file with the provided key, IV, and salt, and appends the hash at the end.
     *
     * @param inputFile  The original file to encrypt.
     * @param outputFile The encrypted file to generate.
     * @param key        The secret key for encryption.
     * @param iv         The initialization vector.
     * @param salt       The salt used for key derivation.
     * @param hash       The SHA-256 hash of the original file.
     * @throws Exception If an error occurs during encryption.
     */
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
                updateUI("Encrypting file...", (double) processedBytes / totalBytes);
            }

            cos.flush();
        }

        try (FileOutputStream fos = new FileOutputStream(outputFile, true)) {
            fos.write(hash);
        }
    }

    /**
     * Decrypts an encrypted file with the provided key and IV, and validates the hash.
     *
     * @param inputFile    The encrypted file to decrypt.
     * @param outputFile   The decrypted file to generate.
     * @param key          The secret key for decryption.
     * @param iv           The initialization vector.
     * @param headerLength The length of the header (salt + IV) in bytes.
     * @throws Exception If an error occurs during decryption or hash validation.
     */
    private void decryptFileWithKey(File inputFile, File outputFile, SecretKey key, byte[] iv, long headerLength)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        final int HASH_SIZE = 32; // SHA-256 = 32 bytes

        try (RandomAccessFile raf = new RandomAccessFile(inputFile, "r")) {
            long fileLength = raf.length();

            if (fileLength < headerLength + HASH_SIZE) {
                throw new IOException("The encrypted file is too short to contain the header and hash.");
            }

            raf.seek(fileLength - HASH_SIZE);
            byte[] storedHash = new byte[HASH_SIZE];
            raf.readFully(storedHash);

            long encryptedDataSize = fileLength - headerLength - HASH_SIZE;
            System.out.println("Encrypted Data Size: " + encryptedDataSize + " bytes");

            try (FileInputStream fis = new FileInputStream(inputFile);
                 LimitedInputStream limitedFis = new LimitedInputStream(fis, encryptedDataSize);
                 CipherInputStream cis = new CipherInputStream(limitedFis, cipher);
                 FileOutputStream fos = new FileOutputStream(outputFile)) {

                long skipped = fis.skip(headerLength);
                System.out.println("Skipped bytes: " + skipped);

                byte[] buffer = new byte[8192];
                int bytesRead;
                long processedBytes = 0;

                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    processedBytes += bytesRead;
                    updateUI("Decrypting file...", (double) processedBytes / encryptedDataSize);
                }

                System.out.println("Processed Bytes: " + processedBytes);
            }

            byte[] computedHash = calculateFileHash(outputFile);

            System.out.println("Stored Hash: " + bytesToHex(storedHash));
            System.out.println("Computed Hash: " + bytesToHex(computedHash));

            if (!Arrays.equals(storedHash, computedHash)) {
                outputFile.delete();
                throw new Exception("Hash mismatch. The password is incorrect or the file is corrupted.");
            } else {
                System.out.println("Hashes match. File integrity verified.");
            }
        }
    }

    /**
     * Generates an encrypted file name by appending "_encrypted" before the original file extension.
     *
     * @param originalFile The original file to encrypt.
     * @return A new File object with the modified name.
     */
    public File getEncryptedFileName(File originalFile) {
        String originalName = originalFile.getName();
        int dotIndex = originalName.lastIndexOf('.');

        if (dotIndex > 0 && dotIndex < originalName.length() - 1) {
            String name = originalName.substring(0, dotIndex);
            String extension = originalName.substring(dotIndex);
            return new File(originalFile.getParent(), name + "_encrypted" + extension);
        } else {
            return new File(originalFile.getParent(), originalName + "_encrypted");
        }
    }

    /**
     * Generates a decrypted file name by replacing "_encrypted" with "_decrypted" before the original file extension.
     *
     * @param encryptedFile The encrypted file.
     * @return A new File object with the modified name.
     * @throws IllegalArgumentException If the file name does not contain the "_encrypted" suffix.
     */
    public File getDecryptedFileName(File encryptedFile) throws IllegalArgumentException {
        String encryptedName = encryptedFile.getName();
        int suffixIndex = encryptedName.lastIndexOf("_encrypted");

        if (suffixIndex > 0) {
            String name = encryptedName.substring(0, suffixIndex);
            String extension = "";

            int dotIndex = encryptedName.lastIndexOf('.');
            if (dotIndex > suffixIndex) {
                extension = encryptedName.substring(dotIndex);
            }

            return new File(encryptedFile.getParent(), name + "_decrypted" + extension);
        } else {
            throw new IllegalArgumentException("The encrypted file name does not contain the '_encrypted' suffix.");
        }
    }

    /**
     * Inner class to limit the reading of CipherInputStream to a specific number of bytes.
     */
    private class LimitedInputStream extends FilterInputStream {
        private long remaining;

        /**
         * Constructs a LimitedInputStream.
         *
         * @param in    The underlying input stream.
         * @param limit The maximum number of bytes to read.
         */
        public LimitedInputStream(InputStream in, long limit) {
            super(in);
            this.remaining = limit;
        }

        @Override
        public int read() throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            int result = super.read();
            if (result != -1) {
                remaining--;
            }
            return result;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            len = (int) Math.min(len, remaining);
            int result = super.read(b, off, len);
            if (result != -1) {
                remaining -= result;
            }
            return result;
        }
    }

    /**
     * Helper method to convert a byte array to its hexadecimal string representation.
     *
     * @param bytes The byte array to convert.
     * @return A string containing the hexadecimal representation of the byte array.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Generates a unique file by appending a number if the file already exists.
     *
     * @param file The desired file.
     * @return A unique File object with an appended number if necessary.
     */
    private File getUniqueFile(File file) {
        if (!file.exists()) {
            return file;
        }

        String name = file.getName();
        String parent = file.getParent();
        int dotIndex = name.lastIndexOf('.');

        String baseName = (dotIndex == -1) ? name : name.substring(0, dotIndex);
        String extension = (dotIndex == -1) ? "" : name.substring(dotIndex);

        int count = 1;
        File uniqueFile;
        do {
            String newName = baseName + "_" + count + extension;
            uniqueFile = new File(parent, newName);
            count++;
        } while (uniqueFile.exists());

        return uniqueFile;
    }
}