
package Deepti;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Callback {
    public static void main(String[] args) {
        String encryptedValue = "tbVIbUzK3SqBaISl3UBrAyRAai1BnN+lzGiLDX1FgIwktHtcpXVe2UYrggQQIet2j5kzFK/lWGfu3fM3kCTHWyWFYTLITxfWAnw3pdo5nhVeeI+ZFYAitXm/gcjsLcSaWxKIOqE705rJumcZtIeeW1BpnHIyE1haY58rnb/UN1b7svcxeDMo4Xq393/1aWwnM6o+/D1XAcm9UxA17in/hEziGvQNdQqP71p2fjn/nLDpflAb6KEcjdV3yKK7TLBQ4LahhkZktq+8F2QVmlBkoqinExvmo3V8rEIrusZNdStjXBYxegbiRcqPgd8lcNccw+J33bAyHT2vxIEMsAWFc6VB7flX2JRYzF3pWhuZ424ONSlTI/QqcHX4DgifmuImUopkt4rcWl/B4jpMIVKyQ4XhD4Jb5pn9pT9W/83xDUyLURPixK77vDLzOFYjXPJaAQbqkQ1ncuyG/Gqo0/ucW76cZuTLwUn+tle8Hkd3+68d01TJ9Sj4/shOFCZkBr3z9bAV8aiZ7FmqZ8BUQFU8nGwOthx6LayUi8fVfYHmHlPvu6PheOP4ApTj2W/Z0QKu/NdeRmj90agn90WjD9FVqmNaapsQFUgyhXa72I8KvY1QcpsQNX8/ow6aFcrzjm0qi9c1fx3aYiMsiDqUc/g2dsuBNB2UzOvnr4KZ6A6hyCBbPqkdPVo9fK6Bdo1EC72oNi8274fRHuHtCo3CY3FeW+D4yGby4m9G9UvSxDcvKfLsPHFXz30dL8jl4eFP3qo1VI707q7fD1RzC4Ag1dxgcycd8Vtx9c8TtriajpsHjY/yieah18jJ2vhFJORyPEIuyytFWwCIyIj7i4P7ug8v6zsi23jEDe3bxX7b37LQ2DCqG8UMLMVSTYet0DYNet13ahVeTf5zorH3B6z2ivlLOB/rVG+ay1rQ5RV5+Z2T3XmWOMXpg7MVgzq9DbzpvJwBxWmzPhGkJ+5uUdjSyIGdFVCC7MlCX5iaiQRnYCGy8Yvds6kFRwpn+zx6RE6DjNA597lYfIg9ZUEiBgP5iz2NIQ4LlSwHac3oJ4xL5HGKu96eBVwmjYH3qoirYpNbsbP57ZNACAvkq8JSRGRwiQ66bWkrPgoP5NCuuZENS0ETvDPu9nHyXq++Nt59cc3SfiqK2be2Tu7GBHSkBLCLZFI86zpDTWMbR6YvoY91EDk+K7QPi3CUkkbBN704hyJp6Qu/EpfjEbzXn6RCxxS+fetJek03xcKG67z0qvj0luacE8Vzqp6vveXin6xUHLyBqXBfq5fyWItVMzfkbh0Mxkm0Xw==";
        
        // Convert encrypted value from Base64 to byte array
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedValue);
        
        // Convert Key and IV from Base64 to byte array
        byte[] key = Base64.getDecoder().decode("dxW/a/raDOtWV9T/8UL8OLVig0am9k4kBMw4x9rddfg=");
        byte[] iv = Base64.getDecoder().decode("aibKcM9Jq6i8NIt+ACg8LQ==");

        // Decrypt the value
        String decryptedValue = decrypt(encryptedBytes, key, iv);
        System.out.println("Decrypted value: " + decryptedValue);

        // Example plaintext to encrypt
        String plaintext = "{\"Failure\":\"99\"}";
        byte[] encryptedResult = encrypt(plaintext, key, iv);
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedResult);
        System.out.println("Encrypted value: " + encryptedBase64);
    }

    public static String decrypt(byte[] cipherText, byte[] key, byte[] iv) {
        try {
            // Initialize cipher
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            // Decrypt the ciphertext
            byte[] decryptedBytes = cipher.doFinal(cipherText);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] encrypt(String plaintext, byte[] key, byte[] iv) {
        try {
            // Initialize cipher
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            // Encrypt the plaintext
            return cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
