package Deepti;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class A128CBC_HS256 {

    private static final String SHARED_SYMMETRIC_KEY = "a3730a502c3b5574f616ac3a61f221b1695006a4765b086902373df280de17c2"; // 256-bit key
    private static final String HMAC_KEY = "a3b5574f616ac3a61f221b1695006a47"; // 128-bit key for HMAC

    public static void main(String[] args) throws Exception {
        A128CBC_HS256 client = new A128CBC_HS256();
        String payload = "{\"mid\":\"YOUTUBE001\",\"channel\":\"api\",\"account_number\":\"04762020001837\",\"mobile_number\":\"9131445536\",\"terminalId\":\"YOUTUBE786\",\"name\":\"Shankar Hotel\",\"bank_name\":\"Canara Bank\",\"mcc\":\"6012\",\"ifsc_code\":\"CNRB0000000\",\"sid\":\"YOUTUBE787\",\"additionalNo\":\"9425415918\",\"checksum\":\"ytydtdgdggdg1200345\"}";

        String encrypted = client.encrypt(payload);
        System.out.println("Encrypted: " + encrypted);

        String decrypted = client.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
    }

    public String encrypt(String input) throws Exception {
        byte[] keyBytes = digest(SHARED_SYMMETRIC_KEY);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = generateIV();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        byte[] ivAndEncryptedBytes = combine(iv, encryptedBytes);

        // HMAC calculation
        byte[] hmacKeyBytes = digest(HMAC_KEY);
        byte[] hmac = calculateHMAC(ivAndEncryptedBytes, hmacKeyBytes);
         
        byte[] result = combine(ivAndEncryptedBytes, hmac);
        return Base64.getEncoder().encodeToString(result);
    }

    public String decrypt(String input) throws Exception {
        byte[] inputBytes = Base64.getDecoder().decode(input);
        byte[] iv = new byte[16];
        byte[] encryptedBytes = new byte[inputBytes.length - 48]; // 16 bytes IV + 32 bytes HMAC
        byte[] hmac = new byte[32];

        System.arraycopy(inputBytes, 0, iv, 0, 16);
        System.arraycopy(inputBytes, 16, encryptedBytes, 0, inputBytes.length - 48);
        System.arraycopy(inputBytes, inputBytes.length - 32, hmac, 0, 32);

        byte[] keyBytes = digest(SHARED_SYMMETRIC_KEY);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        // Verify HMAC
        byte[] hmacKeyBytes = digest(HMAC_KEY);
        byte[] ivAndEncryptedBytes = combine(iv, encryptedBytes);
        byte[] calculatedHmac = calculateHMAC(ivAndEncryptedBytes, hmacKeyBytes);

        if (!MessageDigest.isEqual(hmac, calculatedHmac)) {
            throw new SecurityException("HMAC verification failed");
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private byte[] digest(String key) throws NoSuchAlgorithmException {
        byte[] val = new byte[key.length() / 2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(key.substring(index, index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }

    private byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private byte[] combine(byte[] iv, byte[] encryptedBytes) {
        byte[] result = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, result, iv.length, encryptedBytes.length);
        return result;
    }

    private byte[] calculateHMAC(byte[] data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(data);
    }
}

