package Deepti;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class UpdateDumyUtiil {
	public static String encrypt(String keyString, String plaintext) throws Exception {
	    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(keyString.toCharArray(), new byte[] { 
	            73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 
	            100, 101, 118 }, 1000, 384);
	    SecretKey secretKey = factory.generateSecret(pbeKeySpec);
	    byte[] key = new byte[32];
	    byte[] iv = new byte[16];
	    System.arraycopy(secretKey.getEncoded(), 0, key, 0, 32);
	    System.arraycopy(secretKey.getEncoded(), 32, iv, 0, 16);
	    SecretKeySpec secret = new SecretKeySpec(key, "AES");
	    IvParameterSpec ivSpec = new IvParameterSpec(iv);
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    cipher.init(1, secret, ivSpec);
	    String serialized = Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes("UTF-16LE")));
	    return serialized;
	}

    public static String decrypt(String keyString, String encryptedData) throws Exception {
        if (encryptedData.startsWith("Bearer "))
            encryptedData = encryptedData.substring(7);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(keyString.toCharArray(), new byte[]{
                73, 118, 97, 110, 32, 77, 101, 100, 118, 101,
                100, 101, 118}, 1000, 384);
        SecretKey secretKey = factory.generateSecret(pbeKeySpec);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        System.arraycopy(secretKey.getEncoded(), 0, key, 0, 32);
        System.arraycopy(secretKey.getEncoded(), 32, iv, 0, 16);
        SecretKeySpec secret = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes, "UTF-16LE");
    }
    
    
    
    public static void main(String[] args) {
        try {
            String key = "8E51856A1358FD3BD3B3D59EF15175EE2A4C6AC6005C5EA793992EF0F0448027";
            String data = "";
            
            String encryptedData = encrypt(key, data);
            System.out.println(encryptedData);
            
            String decryptedData = decrypt(key, "");
            System.out.println(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
