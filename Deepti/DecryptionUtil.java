package Deepti;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class DecryptionUtil {
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
            String key = "BD94314FB0FD3A510071EC7B7C6D04ADD6E66FE47CAAFF36D1C8A88347D07507";
            String encryptedData = "6OcaYydzOYb9adgFHkIwxrulsGVEUckzyvj1JCeMFrPqr5A379djMzaVtbM2Jzqzzpjv9+/1Vb9y01o+CJabIR/v/TWHBpWVQz6xJVy3Qo7q00RI/a5HPsa+vhf5tgvNWkZ37ESN1M1cYKglj5q7xLx9uaonZ9sKhAzD7h6f+YkDLiGy7H5ZATC09vGYnE+yMEK++4Ogtwq9HfNSG+jHcmYlZtmi7uTYJ8WKLQg5QkRbw0focHXUzyC6BImv6RO1SmirlxiPHcnQtrhktWqxGuQwA8waHP7mP/siTZS6UBCPzO5AzneN+jxPyMVhUoCwQh/drJc8hVxDtAfuyLtX2fYBQUsgwA7auMTEwpzBJxcdW/WNPslW5DgwF8g/3xrx4Nijo7zWTZH3ZaPKI6ZMxsJv/GyCZlM7PNAKVTiRtzKO12/IKBIUBj8CJL2ELDtWJ2K03ePywAnmvO5FnA236wDDKt1wWrh0HYz5pFuEa4Gb24K+lYzTLBHCEwhC/Ic7/gvNf6dVIojuzYSErpQMlXDS/zDPux8Go0CcZO/gWDGnUMR/XMeLMNe8krHMUOT7MJA/LU26EJjc3uPjQqf3GNzw8XgkHQMtSyvetWU1tIyb9VYOyUqHv2m2Y3wN/ZfT/afNU2sYLPPfd6A/Y6WxugRwIuDwcmTNk0aTtortTV+ewX9YeS180fErV7ghZXUITg5pDF6ReoisajwHR+wEcMr8tXPOS49dOLLbB+8O+PeVG+zENCbLh3GXSNDyu0o5G9yAMXR8Cy85CFttuLCdn/kczm2kSulhgu07ODLKlb7jh8C7/ObxOqskwOSdKh11";

            String decryptedData = DecryptionUtil.decrypt(key, encryptedData);
            System.out.println("Decrypted data: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
