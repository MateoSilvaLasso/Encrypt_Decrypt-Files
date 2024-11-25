# **Encrypt/Decrypt Files Project**

## **Team Members**
- **Mateo Silva**
- **Ana Sofia Londoño**
- **Sara Cardona**

## **Project Overview**
This project implements a secure file encryption and decryption application as part of a cybersecurity initiative. The main functionality revolves around securely encrypting files using AES (Advanced Encryption Standard) with a 256-bit key derived from a password via PBKDF2, and validating file integrity with a SHA-256 hash. The decryption process verifies the integrity of the file by comparing the computed and stored hashes.

The project serves as an educational application of cryptographic principles, focusing on:
1. Strong encryption techniques.
2. Secure key derivation methods.
3. Data integrity validation through hashing.

This project adheres to cybersecurity best practices and demonstrates robust handling of sensitive data.

---

## **Features**

### **1. Encrypt File**
- **Input**: A file and a password provided by the user.
- **Process**:
  - Derive a secure 256-bit key from the password using PBKDF2 with a random salt.
  - Encrypt the file contents using AES-256 in CBC mode with a randomly generated IV (Initialization Vector).
  - Compute the SHA-256 hash of the original file and append it to the encrypted file for later integrity verification.
- **Output**: The encrypted file is saved with the `.encrypted` extension in the same directory as the input file.

### **2. Decrypt File**
- **Input**: An encrypted file and the correct password.
- **Process**:
  - Extract the salt, IV, and SHA-256 hash from the encrypted file.
  - Derive the 256-bit key from the provided password using PBKDF2 and the extracted salt.
  - Decrypt the file using AES-256 in CBC mode and the derived key.
  - Compute the SHA-256 hash of the decrypted file and compare it with the extracted hash.
- **Output**: The decrypted file is saved with the `.decrypted` extension. If the hashes match, the decryption is deemed successful.

### **3. Input Validation**
- Ensures that:
  - The file path is not empty and points to an existing file.
  - The password is not empty.

### **4. Error Handling**
- Clear error messages for invalid file paths, incorrect passwords, or file corruption.
- Ensures the integrity of the cryptographic processes.

---

## **Technical Stack**
- **Programming Language**: Java
- **Framework**: JavaFX (for the graphical user interface)
- **Cryptographic Library**: Java Cryptography Architecture (JCA)

---

## **Architecture**

### **Core Components**
1. **CipherController**:
   - Manages encryption and decryption workflows.
   - Handles user inputs and updates the UI dynamically.

2. **Validation Module**:
   - Ensures user inputs (file path and password) are valid before proceeding with encryption or decryption.

3. **File Handling**:
   - Reads and writes files securely, ensuring proper cleanup of resources.
   - Includes robust error handling for file I/O operations.

4. **Cryptographic Functions**:
   - Key derivation using PBKDF2 with HMAC-SHA256.
   - Encryption and decryption using AES-256 in CBC mode.
   - File hashing using SHA-256 for integrity validation.

---

## **How to Use the Program**

### **1. Encrypt a File**
1. Open the application.
2. Browse to select the file you wish to encrypt.
3. Enter a secure password.
4. Click the "Encrypt" button.
5. The encrypted file will be saved with the `.encrypted` extension.

### **2. Decrypt a File**
1. Open the application.
2. Browse to select the `.encrypted` file.
3. Enter the correct password.
4. Click the "Decrypt" button.
5. The decrypted file will be saved with the `.decrypted` extension. If the file's integrity is intact, a success message will be displayed.

---

## **Challenges Encountered**
1. **Thread Management**:
   - Ensuring encryption and decryption operations ran smoothly on separate threads without blocking the UI.
2. **JavaFX Initialization in Tests**:
   - Setting up the JavaFX application thread for integration testing.
3. **Error Propagation**:
   - Ensuring meaningful error messages were displayed for issues like incorrect passwords or file corruption.

---

## **Lessons Learned**
- The importance of securely managing cryptographic keys and sensitive data.
- Best practices for using the Java Cryptography Architecture (JCA).
- Handling multithreading in JavaFX to keep the UI responsive during computationally intensive tasks.
- The value of validating user inputs to prevent runtime errors.

---

## **Conclusion**
This project demonstrates the application of strong encryption and integrity validation mechanisms to protect sensitive data. By leveraging industry-standard algorithms such as AES, PBKDF2, and SHA-256, the program provides a robust and secure solution for file encryption and decryption. Through this project, we gained practical experience in implementing cryptographic principles and tackling real-world programming challenges in cybersecurity.

---

## **How to Run the Program**
1. Clone the repository from GitHub.
2. Open the project in your preferred IDE.
3. Build the project using Maven.
4. Run the application.



