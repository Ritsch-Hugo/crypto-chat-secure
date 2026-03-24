import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

/*
======================================================
PROJET CRYPTO - EVOLUTION DE L'INTERCEPTOR
======================================================

Ce fichier regroupe les différentes étapes du projet :

- STEP 3.1 : chiffrement ROT13
- STEP 3.2 : chiffrement AES-CBC avec mot de passe
- STEP 3.3 : chiffrement AES-GCM

Les anciennes étapes sont conservées ci-dessous sous forme
de blocs commentés complets afin de montrer l’évolution
du projet et des choix de sécurité.

Le code ACTIF utilisé actuellement est situé après ces
blocs commentés.
*/


/*
======================================================
STEP 3.1 - ROT13 (VERSION INITIALE INSECURE)
======================================================

Principe :
- Le message est transformé avec ROT13 avant envoi.
- Le destinataire applique ROT13 à nouveau pour retrouver
  le message initial.

Problème :
- Ce n’est pas un vrai chiffrement.
- Un attaquant MITM peut retrouver le message très facilement.

Code utilisé à cette étape :

import java.io.*;

public class Interceptor {

    public Interceptor(String password) {
        System.out.println("[Interceptor] ROT13 mode");
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        System.out.println("[Interceptor] No handshake in step 3.1");
    }

    public String beforeSend(String plainText) {
        return rot13(plainText);
    }

    public String afterReceive(String encryptedText) {
        return rot13(encryptedText);
    }

    private String rot13(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                result.append((char) ((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                result.append((char) ((c - 'A' + 13) % 26 + 'A'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}
*/


/*
======================================================
STEP 3.2 - AES-CBC (CONFIDENTIALITE SANS INTEGRITE)
======================================================

Principe :
- Une clé AES est dérivée à partir d’un mot de passe
  via SHA-256.
- Le message est chiffré en AES/CBC/PKCS5Padding.
- L’IV est généré aléatoirement puis concaténé au
  ciphertext avant encodage Base64.

Amélioration :
- Le serveur ne peut plus lire directement le message.

Problème :
- AES-CBC seul ne garantit pas l’intégrité.
- Un MITM peut modifier le ciphertext.
- Le message peut parfois être déchiffré en texte altéré
  sans qu’aucune alerte ne soit levée.

Code utilisé à cette étape :

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class Interceptor {

    private static final String HASH_ALGO = "SHA-256";
    private static final String CIPHER_ALGO = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_SIZE_BYTES = 16;
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
        System.out.println("[Interceptor] No custom handshake yet in step 3.2");
    }

    public String beforeSend(String plainText) {
        try {
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
*/


/*
======================================================
STEP 3.3 - AES-GCM (OBJECTIF DE CETTE ETAPE)
======================================================

Principe :
- On garde une clé AES dérivée du mot de passe.
- On remplace AES-CBC par AES-GCM.
- AES-GCM fournit :
  * confidentialité
  * intégrité
  * authentification

Conséquence :
- Si un attaquant modifie le message, le destinataire
  détecte immédiatement l’altération.
- Le message n’est plus accepté silencieusement.

Le code ACTIF correspondant à cette étape se trouve
juste en dessous.
*/


public class Interceptor {

    private static final String HASH_ALGO = "SHA-256";
    private static final int AES_KEY_SIZE_BYTES = 16;

    private static final String GCM_ALGO = "AES/GCM/NoPadding";
    private static final int GCM_IV_SIZE = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private final SecretKey aesKey;

    public Interceptor(String password) {
        try {
            this.aesKey = deriveKeyFromPassword(password);
            System.out.println("[Interceptor] AES-GCM key initialized");
        } catch (Exception e) {
            throw new RuntimeException("Initialization failed", e);
        }
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        System.out.println("[Interceptor] No handshake implemented (step 3.3)");
    }

    public String beforeSend(String plainText) {
        try {
            byte[] iv = new byte[GCM_IV_SIZE];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(GCM_ALGO);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

            byte[] ciphertext = cipher.doFinal(plainText.getBytes("UTF-8"));

            byte[] result = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(result);

        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String afterReceive(String encryptedText) {
        try {
            byte[] input = Base64.getDecoder().decode(encryptedText);

            if (input.length < GCM_IV_SIZE + 1) {
                return "[Decryption failed]";
            }

            byte[] iv = Arrays.copyOfRange(input, 0, GCM_IV_SIZE);
            byte[] ciphertext = Arrays.copyOfRange(input, GCM_IV_SIZE, input.length);

            Cipher cipher = Cipher.getInstance(GCM_ALGO);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

            byte[] plaintext = cipher.doFinal(ciphertext);
            return new String(plaintext, "UTF-8");

        } catch (AEADBadTagException e) {
            return "[SECURITY ERROR: Message tampered!]";
        } catch (Exception e) {
            return "[Decryption failed]";
        }
    }

    private SecretKey deriveKeyFromPassword(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGO);
        byte[] hash = digest.digest(password.getBytes("UTF-8"));
        byte[] keyBytes = Arrays.copyOf(hash, AES_KEY_SIZE_BYTES);
        return new SecretKeySpec(keyBytes, "AES");
    }
}