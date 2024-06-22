package Deepti;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtil {
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
            String data = "{\r\n"
            		+ "    \"header\": {\r\n"
            		+ "        \"BankCode\": \" Ed1KSj7NVFXqWDVg3jridTOjU0yfwWpzJyu61ql49+wP8TdZEWE44nNalCvDIqGb6CknbU36eP3cdNeATS9HS/SxpRIfLATBp42DZnze/TCPwdhEgCx0sVfb7//6F6+r0TFBqlxnMitTeUQpL4sgaE6+ELHsk5P5yQa/c9qa1bc=\",\r\n"
            		+ "        \"Channel\": \"Tv2ole6TXZuuhInzHAOwkD3bVY/TBMbC9aqDcRzGG4HBYiYJYBzk/izuGqgAmJsKRpAU8s0y6QS8N/ExAmI9S8/+f8scLpRXKdSnuxoYbbg+bZ2kdBWPMbg+8c5EX6CYq58ORkUW4q7/wxppbPu2GV9HbucAjtX1oWwuUsN9Ztc=\",\r\n"
            		+ "        \"deviceInfo\": {\r\n"
            		+ "            \"geocode\": \"uQxXnxaqJvFy7L346cRbPLXCqQ60bQfmD9quZ3muojsOh1ljo9S0HuMSQlOi2sRS5qC8gXLGxrxLW84USnVE+j0Xn7iVjF7lUmiKNS3cMKG15cJ9ReGja3l2UiShj/7ji47rSZ4f4LzYM8Nr9WV6D5lMo20Mr/8nNc8cU23NGvA=\",\r\n"
            		+ "            \"location\": \" j6nxba0mvMLi/nzuV/chKxlgtD8tzWXIbiOKQv0zcHRPxIOZuymTOxyJiyI7WYRPv7TwY0uBCdOMBoFXEHwnatCaGqmZR7MWTe1rWWl3KebvUMyP5sudAb3nqbB1n97xNfsMd1ATAF5afI4NfO5wUAc1PygE8QNVybfLjPRzQxk=\",\r\n"
            		+ "            \"ip\": \"VmfcAqswL16rOb5FuX6xUsIFrkj5Sr7hP3her20E/ABDSSP1xR8RrOldafVnKTUnDlE8dHEjd46yN3uDgq9FZHCc3yKyXbobJCTCe5amyhll0wXBLmXQTOQCrsIC1ihB+n0Zi9hchL9lwJNDC7JnigDqc5PS3bNvoPms3WJzGSM=\",\r\n"
            		+ "            \"type\": \"WVW+ow5rNgTjc4yN67J85Sl4RivAdjKYrlnocNvw8BI3NxVF9cQ+yrydhgKLZfm6wzXpctHOXlUpwnXOsbx34CY850OwQJ9P0vH4mvabVuPsMLEGFKiAfFNZliPsMLJDFk8acrZObeOcAkbepw4PqEMgb7WtcygzImx2+2wY2yE=\",\r\n"
            		+ "            \"id\": \"Xb+tUSmQcZonMySiL22TnlmDbMYYEaG2oU9L/G1+UQ7AVMgSkEkMj0fO7mtANftHPv++uVF5t2sYfNvYG/hwOLzRQIE89xMQhgwq0S+/LQzefoVzcn/YDztuCZie41sYpi2uqDbuP75DIDzNWkaTztFHE7xD+54FhPe5UP49e7w=\",\r\n"
            		+ "            \"os\": \"vZwFQiieTjsVz11MAdC4kstuK86sgUWDTH30RvwuVADXqwv6uW257R1T9ftKHB0CHbwM6OApO27lJhVFLgp0szRfv7N7gGtVa9y65KT/VtorrvEI3ZsT4MWnH5yVye0mcx/CS/nxypCwqdAXHPsVJvichUBsJESNH2e/HUNLYXo=\",\r\n"
            		+ "            \"app\": \" tAXnNmK+vM+reGphrzURnlpAma8ghdOpf77jQwlCsXdq+6y04j/EPPSVP08uQrDbYg4G0XLV8ytOPRuHHaZEAUdC/hjikgzfVwxL+DYunWAeWia/ul7U/K7qDtFIm2/ad9N+x9CignTcUXv3FIdY2Hx4dXf53Ard+SHm8WyfyKE=\",\r\n"
            		+ "            \"capability\": \" bWqTBo4u6H7SFeaMhlKtplaFkRVjFwM2fCR38+UnhwxskAYG/pgJ1z0UnHlxJsYoWBG1YBXBaz4QSPevsLV8KvoSFSoVzoRh6rcM1J0STW8C+SYJupFSSKZpSiNPwiwTD8s+3kMDYZb+CIYYCRESkotJuUuVBPvI5G2a0z85yB4=\"\r\n"
            		+ "        }\r\n"
            		+ "    },\r\n"
            		+ "    \"transactionInfo\": {\r\n"
            		+ "        \"transactionid\": \"12345678865987\",\r\n"
            		+ "        \"transactiondatetime\": \"2024-05-07 12:22:08 678\",\r\n"
            		+ "        \"attributes\": {\r\n"
            		+ "            \"create\": \"submerchant\",\r\n"
            		+ "            \"vpa\": \"Letspe123@AuBank\",\r\n"
            		+ "            \"returnqr\": \"N\"\r\n"
            		+ "        }\r\n"
            		+ "    }\r\n"
            		+ "}\r\n"
            		+ ""
            		+ ";";
            
            String encryptedData = encrypt(key, data);
            System.out.println(encryptedData);
            
            String decryptedData = decrypt(key, "phCD0YLrsO/wD48nrzVoA+GGuRZUZRUQnDLcmHyikd5nt2hGgKE+cSQixnxRcBcpHc05+k7yGNK7D8Wipz8O5A8XY4vlY1hmx8xbf/tN3KfUqYQ4j91tGr8jFYSdoSTPaHZo+DlYVqHnEWrVRtW3r4MWFoxCqkm+WEz08n2qCp1nwGZMZ4PghTPkI1yMOX0ToiWOWSNy4TorqwUMQp6lnp8fv4dP9OCh4VQbeDmwBEsvEc6bswyZ73yCFi90wTj0em3QimVbdgqHjBTrWv4s2nwdaCGVbfBLpQ1ExipcplHlKLgcwCvHyKGSSMJ7mryDxEk+LYClFYDO/vMREd4DG27h0CJF8NXgVLo+2uSjyGG4BJrickjX+HopjMvAZAzk1L6o+4ZYK1+xnu/zPXuSlm3oCKlLIDrvn1g8jpnD6gIMViGUSmctIMnWj3sCaWbtXCDdZqYnUW1cz9g35St9olquBeCpCIt88FWe2XJ/eFT8yrYBcqy8aXCvvsdEFh9aFNI24A13ym45x/7tY39EgAggRaYqBLSDrKc0gzuYzqzo6YrqCW5YhZ7VIw1MgxMwwSs3Ia6s3vOTkUsdxmvLsGxZSvc30bpStHJshXA3/L2aixyPVFIetIBeI+qwIQj+u83ogRxsyqEEENrDqZiI0d052nu5Wxzo7msEAB962RTgJB7vmDymmDwW6mJdUf+6yfP96NWpmHJtV4uy8/BWLxuiUu0kY2EE84LYVSFclmM32aJ312yCRlqLyeBrlPZ9nmWLZGHZUyrFxHH6vKWupi2zridES8NSd51eKXQvyLFW5T3PErQ0SQ+od4HvgLMp");
            System.out.println("Decrypted data: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
