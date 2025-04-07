package in.co.demo.RsaSharedSecret;

import java.security.KeyPair;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MainClass {
	
	public static void main(String[] args) {
        try {
            // Step 1: Generate RSA key pairs for Alice and Bob
            KeyPair aliceKeyPair = SharedSecretOfRsa.generateRSAKeyPair();
            KeyPair bobKeyPair = SharedSecretOfRsa.generateRSAKeyPair();

            // Step 2: Alice generates a random AES key to share with Bob
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256); // 256-bit AES key
            SecretKey aesKey = keyGenerator.generateKey();
            System.out.println("AES Key (Base64): " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

            // Step 3: Alice encrypts the AES key with Bob's public RSA key
            String encryptedAESKey = SharedSecretOfRsa.encryptAESKey(bobKeyPair.getPublic(), aesKey);
            System.out.println("Encrypted AES Key (Base64): " + encryptedAESKey);

            // Step 4: Bob decrypts the AES key with his private RSA key
            SecretKey decryptedAESKey = SharedSecretOfRsa.decryptAESKey(bobKeyPair.getPrivate(), encryptedAESKey);
            System.out.println("Decrypted AES Key (Base64): " + Base64.getEncoder().encodeToString(decryptedAESKey.getEncoded()));

            // Step 5: Symmetric Communication (AES encryption/decryption)
            String originalMessage = "Hello, Bob! This is a secure message.";
            System.out.println("\nOriginal Message: " + originalMessage);

            // Alice encrypts the message using the AES key
            String encryptedMessage = SharedSecretOfRsa.encryptMessage(originalMessage, aesKey);
            System.out.println("Encrypted Message (Base64): " + encryptedMessage);

            // Bob decrypts the message using the AES key
            String decryptedMessage = SharedSecretOfRsa.decryptMessage(encryptedMessage, decryptedAESKey);
            System.out.println("Decrypted Message: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
