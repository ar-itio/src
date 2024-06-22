package Deepti;
import javax.crypto.*;

import java.security.*;
import java.util.Base64;

public class EnDe {
    public static void main(String[] args) {
        try {
            String VPA_RSA_MODULUS = "xTSiS4+I/x9awUXcF66Ffw7tracsQfGCn6g6k/hGkLquHYMFTCYk4mOB5NwLwqczwvl8HkQfDShGcvrm47XHKUzA8iadWdA5n4toBECzRxiCWCHm1KEg59LUD3fxTG5ogGiNxDj9wSguCIzFdUxBYq5ot2J4iLgGu0qShml5vwk=";
            String VPA_RSA_EXPONENT = "AQAB";

            EncryptionDecryption demoApplication = new EncryptionDecryption(); // Creating an instance of DemoApplication class
            PublicKey publicKey = demoApplication.readPublicKeyFromMod(VPA_RSA_MODULUS, VPA_RSA_EXPONENT);

            String merchantCode = "KOiT8PZPnWnsoOioeNxG1pzbbtED0DO51zp1RQ5Hrx3Z2RPkTvmM/Q1qZQkp05/LmzX/VGo6eGCGhvDcHuKWyNlotaNBDadz25/PmpAWGX92WWR8lXjafD2nWamNImWZjg4ke1ltywmvnUR222iSiHcH5h0VCs6qR8wrDFgGaWs=";

            // Generate a random symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // You can adjust the key size as needed
            SecretKey secretKey = keyGen.generateKey();

            // Encrypt the merchant code using AES
            byte[] encryptedMerchantCode = encryptAES(merchantCode, secretKey);
            System.out.println("Encrypted MerchantCode: " + Base64.getEncoder().encodeToString(encryptedMerchantCode));

            // Encrypt the symmetric key using RSA
            byte[] encryptedSymmetricKey = encryptRSA(secretKey.getEncoded(), publicKey);
            System.out.println("Encrypted Symmetric Key: " + Base64.getEncoder().encodeToString(encryptedSymmetricKey));
        } catch (Exception e) {
            System.out.println("Failed to encrypt MerchantCode: " + e.getMessage());
        }
    }

    public static byte[] encryptAES(String data, SecretKey secretKey)
            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data.getBytes());
    }

    public static byte[] encryptRSA(byte[] data, PublicKey publicKey)
            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }
}
