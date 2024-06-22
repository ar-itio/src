package Deepti;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class EncryptionDecryption {
	 public static void main(String[] args) {
		 
	        try {
	            String VPA_RSA_MODULUS = "xTSiS4+I/x9awUXcF66Ffw7tracsQfGCn6g6k/hGkLquHYMFTCYk4mOB5NwLwqczwvl8HkQfDShGcvrm47XHKUzA8iadWdA5n4toBECzRxiCWCHm1KEg59LUD3fxTG5ogGiNxDj9wSguCIzFdUxBYq5ot2J4iLgGu0qShml5vwk=";
	            String VPA_RSA_PRIVATE_KEY_D = "g1WAWI4pEK9TA7CA2Yyy/2FzzNiu0uQCuE2TZYRNiomo96KQXpxwqAzZLw+VDXfJMypwDMAVZe/SqzSJnFEtZxjdxaEo3VLcZ1mnbIL0vS7D6iFeYutF9kF231165qGd3k2tgymNMMpY7oYKjS11Y6JqWDU0WE5hjS2X35iG6mE=";
	            String VPA_RSA_EXPONENT = "AQAB";


	            EncryptionDecryption demoApplication = new EncryptionDecryption(); // Creating an instance of DemoApplication class
	            PublicKey publicKey =demoApplication.readPublicKeyFromMod(VPA_RSA_MODULUS, VPA_RSA_EXPONENT);
	            PrivateKey privateKey = demoApplication.readPrivateKeyFromMod(VPA_RSA_MODULUS, VPA_RSA_PRIVATE_KEY_D);
	            String upiToken = String.valueOf(System.currentTimeMillis());
	            String originalMessage = "1234567";
	            byte[] encryptedMessage = EncryptionDecryption.encrypt(originalMessage, publicKey);
	            System.out.println("Encrypted message: " + Base64.getEncoder().encodeToString(encryptedMessage));

	            String decryptedMessage = EncryptionDecryption.decrypt(encryptedMessage, privateKey);
	            System.out.println("Decrypted message: " + decryptedMessage);
	        } catch (Exception e) {
	            System.out.println("Failed to generate/verify token: " + e.getMessage());
	        }

	        // SpringApplication.run(DemoApplication.class, args);
	    }

	    public PublicKey readPublicKeyFromMod(String VPA_RSA_MODULUS, String VPA_RSA_EXPONENT) {
	        byte[] modulusBytes = Base64.getDecoder().decode(VPA_RSA_MODULUS);
	        byte[] exponentBytes = Base64.getDecoder().decode(VPA_RSA_EXPONENT);
	        BigInteger modulus = new BigInteger(1, modulusBytes);
	        BigInteger publicExponent = new BigInteger(1, exponentBytes);
	        PublicKey publicKey = null;
	        RSAPublicKeySpec rsaPubKey = new RSAPublicKeySpec(modulus, publicExponent);
	        KeyFactory factory;
	        try {
	            factory = KeyFactory.getInstance("RSA");
	            publicKey = factory.generatePublic(rsaPubKey);
	        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
	            e.printStackTrace();
	        }
	        return publicKey;
	    }

	    public PrivateKey readPrivateKeyFromMod(String VPA_RSA_MODULUS, String VPA_RSA_PRIVATE_KEY_D) {
	        byte[] modulusBytes = Base64.getDecoder().decode(VPA_RSA_MODULUS);
	        byte[] dBytes = Base64.getDecoder().decode(VPA_RSA_PRIVATE_KEY_D);
	        BigInteger modulus = new BigInteger(1, modulusBytes);
	        BigInteger d = new BigInteger(1, dBytes);
	        PrivateKey privateKey = null;
	        RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, d);
	        KeyFactory factory;
	        try {
	            factory = KeyFactory.getInstance("RSA");
	            privateKey = factory.generatePrivate(privateSpec);
	        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
	            e.printStackTrace();
	        }
	        return privateKey;
	    }

	    public static byte[] encrypt(String data, PublicKey publicKey)
	            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException,
	            NoSuchAlgorithmException {
	        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	        return cipher.doFinal(data.getBytes());
	    }

	    public static String decrypt(byte[] data, PrivateKey privateKey)
	            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
	            IllegalBlockSizeException {
	        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	        cipher.init(Cipher.DECRYPT_MODE, privateKey);
	        return new String(cipher.doFinal(data));
	    }
}
