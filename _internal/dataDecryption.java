package _internal;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.annotation.Resource;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class dataDecryption {
    private static final String ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/NoPadding";
    private static final String PASSWORD = "Demo@123";

    public static void main(String[] args) {
        decryptData("Input encrypted data here");
    }

    static Object decryptData(String encryptedDataBase64) {
        try {
            if (encryptedDataBase64 == null) {
                throw new IllegalArgumentException("Encrypted data is required");
            }
            byte[] encryptedData = Base64.getDecoder().decode(encryptedDataBase64);
            PrivateKey key = loadPrivateKey();
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedData = cipher.doFinal(encryptedData);
            ObjectMapper mapper = new ObjectMapper();
            return new String(decryptedData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Error while decrypting data", e);
            return null;
        }
    }

    static PublicKey loadPublicKey() throws Exception {
        Resource resource = new ClassPathResource("public.key.enc");
        try (InputStream inputStream = resource.getInputStream()) {
            byte[] encryptedKeyBytes = inputStream.readAllBytes();
            byte[] keyBytes = decryptFile(encryptedKeyBytes, PASSWORD);
            String keyString = new String(keyBytes, StandardCharsets.UTF_8)
                    .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decodedKey = Base64.getDecoder().decode(keyString);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePublic(spec);
        }
    }

    static PrivateKey loadPrivateKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Resource resource = new ClassPathResource("private.key.enc");
        try (InputStream inputStream = resource.getInputStream()) {
            byte[] encryptedKeyBytes = inputStream.readAllBytes();
            byte[] keyBytes = decryptFile(encryptedKeyBytes, PASSWORD);
            String keyString = new String(keyBytes, StandardCharsets.UTF_8)
                    .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decodedKey = Base64.getDecoder().decode(keyString);

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        }
    }

    static byte[] decryptFile(byte[] encryptedFilePath, String password) throws Exception {
        byte[] fileBytes = encryptedFilePath;

        byte[] salt = Arrays.copyOfRange(fileBytes, 0, 16);
        byte[] iv = Arrays.copyOfRange(fileBytes, 16, 32);
        byte[] encryptedData = Arrays.copyOfRange(fileBytes, 32, fileBytes.length);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        SecretKeySpec secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES_ALGORITHM);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] paddedData = cipher.doFinal(encryptedData);
        return removePadding(paddedData);
    }

    static byte[] removePadding(byte[] data) {
        int paddingLength = data[data.length - 1];
        if (paddingLength < 1 || paddingLength > 16) {
            throw new IllegalArgumentException("Invalid padding length");
        }
        for (int i = data.length - paddingLength; i < data.length; i++) {
            if (data[i] != paddingLength) {
                throw new IllegalArgumentException("Invalid padding byte");
            }
        }
        return Arrays.copyOfRange(data, 0, data.length - paddingLength);
    }
}
