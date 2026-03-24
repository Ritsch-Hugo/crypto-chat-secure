import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class Interceptor {

    private static final String HASH_ALGO = "SHA-256";
    private static final String CIPHER_ALGO = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_SIZE_BYTES = 16; // 128 bits
    private static final int IV_SIZE_BYTES = 16;

    private final SecretKey aesKey;

    public Interceptor(String password) {
        try {
            this.aesKey = deriveKeyFromPassword(password);
            System.out.println("[Interceptor] AES key derived from password");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize interceptor", e);
        }
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting handshake");
            System.out.println("[Interceptor] No custom handshake yet in step 3.2");
            System.out.println("[Interceptor] Handshake complete!");
        } catch (Exception e) {
            throw new IOException("Handshake failed", e);
        }
    }

    public String beforeSend(String plainText) {
        try {
            System.out.println("[Interceptor] Encrypting message: " + plainText);

            byte[] iv = new byte[IV_SIZE_BYTES];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

            byte[] ciphertext = cipher.doFinal(plainText.getBytes("UTF-8"));

            byte[] ivPlusCiphertext = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, ivPlusCiphertext, 0, iv.length);
            System.arraycopy(ciphertext, 0, ivPlusCiphertext, iv.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(ivPlusCiphertext);

        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String afterReceive(String encryptedText) {
        try {
            System.out.println("[Interceptor] Decrypting message...");

            byte[] ivPlusCiphertext = Base64.getDecoder().decode(encryptedText);

            if (ivPlusCiphertext.length < IV_SIZE_BYTES + 1) {
                throw new IllegalArgumentException("Message too short");
            }

            byte[] iv = Arrays.copyOfRange(ivPlusCiphertext, 0, IV_SIZE_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(ivPlusCiphertext, IV_SIZE_BYTES, ivPlusCiphertext.length);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

            byte[] plaintext = cipher.doFinal(ciphertext);
            return new String(plaintext, "UTF-8");

        } catch (Exception e) {
            return "[Decryption failed: " + e.getClass().getSimpleName() + " - " + e.getMessage() + "]";
        }
    }

    private SecretKey deriveKeyFromPassword(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGO);
        byte[] hash = digest.digest(password.getBytes("UTF-8"));

        byte[] keyBytes = Arrays.copyOf(hash, AES_KEY_SIZE_BYTES);
        return new SecretKeySpec(keyBytes, "AES");
    }
}