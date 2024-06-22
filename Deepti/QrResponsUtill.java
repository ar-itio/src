package Deepti;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class QrResponsUtill {
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
            		+ "        \"MerchantCode\": \"S1hxXW8uOwNnhZ5WoS4GSGBUlmr6Qt8ww50JZlFfa6hgBINtcCHmmisAYnQL8pPEYaeLdT35ZZGUsChbyoH2aTWU53SQcAgME0GPf5/nZCe3vcdSMDUrv8eRy8J3v/+b+nbpUfWGuI251+uYclnowFd9xDZPi8KxP4JlX9Y1918=\",\r\n"
            		+ "        \"SubMerchantCode\": \"VLPIcm2bhOQspKf9iZVQ7Ujbq5nWzopKHMb7LkIUDmZaRw52toi3pjeg3X29CDjaubiVs4gT556yKRcUS2ODXVZE0DOI/Io1VyfMT53BHVsf4Ux0zbpBZcoCpxZdOhd0d8PL7ZD9yWlH9VQxp0gbX8P5CCvUyr64WNj93ieLIaM=\",\r\n"
            		+ "        \"StoreCode\": \"JhnmHPew2jGgQb8/1x0lwyOTdhXWsEYh6mt5qOsv99AviZ6i2GJW9Xlzzij0SVaO827RlrKzOjelJ9dlRO9hCYCKxABQSpM9YcBgshD9XBz9PogmnmJ359MdwRIVAB1YB5hRruz1kqX2bDmvgE7iTWTlMh2jbI5CDaNyXKteOa0=\",\r\n"
            		+ "        \"TerminalCode\": \"XclutYrX/WTidDhV4lH0Tu/ruVzkdrQJ95RDjzUEIM4LMr5M5RezdUTcmbrc/gDST5s9CTDgYzWXLdHXeNSwq2gfRaG+a5gjWLFyteZqi/wiF92Gxzt7YW1bjc48zmvp+/g4rryKGl0oQDxKjyj1L/RuAyuWITTGFkayEpyCbgg=\",\r\n"
            		+ "        \"TellerCode\": \"GSCyqHXjqSxl5/UIREIrHlKBBQduPJijc0pf/SvrFk4J5wFGrlFbrWtthuV1BlsquKb+64Gy29MfkS3HKviXfRqU9+S0/hMFWITlisxLZrUh+PFd5EElK7ZmbYlEPEUG3ALTydsJr4OaQkOZER5At8IgwJbneW84rDM40cshFM4=\",\r\n"
            		+ "        \"Channel\": \"NV7w70YxOLUiygSB1FPekiJYEXvl0LrAPUnjLQqq1XloxC6Aky6OKepTBqcLbN/1Qib4GERjMvVKYwKlL/ZTNFDKj9kPJpv1GTeWx3X65s6daa10v1pcdUiqlTxeNsI2gyKqWZ+utyKxOG5KKQhpeoRB00IvTzxNxOetcCMAPYk=\",\r\n"
            		+ "        \"deviceInfo\": {\r\n"
            		+ "            \"mobile\": \"NWQrXCfb3fsqMBT0L10EecLWf5CoyXQ8VueQUoNW8SF+A7FLDOjGGttjMjkR/QFyAXxdYzXOjHkr6lebM4yTBy2Ko8aPI+97yOUTTRoG9aizdP6JIiEV7/EbU9kJye2eVAyY7VTOwjUH+zmkXU1f6dqhrj01Xqrg0oN8fKLkpO0=\",\r\n"
            		+ "            \"geocode\": \" bmTuJwfaM89rtYav0zT7CbhApMG/IZNPPYRaK0uLnOC0E4P5hHE2hQGkTdJ4NPkwqMDK4R6fxQN+oUb43jzEcXzhwqK0sAcSURf9i4qga/gerZf3wFH5o6jptT2NVMA8Eq6vqt1l9jGmCe2Ss2X0znsK/wK8S2IMxLjA/nEYcrQ=\",\r\n"
            		+ "            \"location\": \"Ep1E0U7BWHOX/D5vwpimh+03zeykpHPvTwFKdf0MgvM8grYjZsrf/ncSgQq078rjfhrJ/+rvL3ejYU0g8pDNTtzt4mx7FYdTuChEjgbpjktNj/X9QAMYz/o96Y59oGf3Ee4yQRKC+4W3sobg6mA9kkerb5OKwO3soVki58a0DJI=\",\r\n"
            		+ "            \"ip\": \"vPzPmuCyFt98iS9MB5D/wgPEZPj9wBwwRT1oOvpBfNbI6lnLMGOnfhe/Euarg0SvCBNlzUvmhBk+MXJ3W/q3aAOrbXJs3yakiqGIMrjliSBerVYZzt8Q3q/VtrOC6iPr5PSpVixcQBHgFnON4fI2YuNfpAVUPZxhkduFk34pIIE=\",\r\n"
            		+ "            \"type\": \"URb72digWi0p22Vz8s/Y+c/9sn66U6wGDn2cyKOiM8AtBJuNsYlUEliEJUlxJxXQjeEfHZLYV6Ej+k9sQSZbmTp/eekEpfUHao/aLwICRwHhsjDX3f0hqGSY0HwCv0O/Ki3ItTtc/M3RCi6n+8FQZHcj9uXO5XNqmhonKR32nPU=\",\r\n"
            		+ "            \"id\": \"RkUugnPXPp7ojvqYZwHPPweyILaGKF3vdXZx1GJl/JwG6Znmh232CProYLO69Q1ITI32wo4Cmi3rIEXHx7vMFK3EPUscKdwtzZJkHeIAVO/SKaRJ9wO5yRFsVSFiZCA68ou3SaRJh/a+1LKlC5jLP5jh0QVms9jesdMGrzExHY0=\",\r\n"
            		+ "            \"os\": \"sjjWOXqb/EQlXtLktBTchwtomZzksIBcjrIFl9NA6/iqdBXaTQP9QJoiDiVkphmjLi6mF3ulrof/o0Jq17MJ+HYR2SVxqwDPdmjL4qpcB7UjP/LYPCqLQOkGP3Kr5n4sr3qaEk3H5SNUBUsCtfFQgTD08qK1KfKVG1nz7QPnn+Q=\",\r\n"
            		+ "            \"app\": \"rf7LErGYvb2LNPuPV2SZmY/EbOQvjH9fuMm/nQ/Y+lL5JDJRkLpQvjEZjjFeOiVfHKfJ9LMZjrUwSyCFPaCuglI9zQ+j617Toeh5eGMkRJo7Nat7x4OXG3EY2n5yGpBfPi4Hu8d5Af316UIwVLfI6fHZKfAhiB3TSHLwT0KNVOo=\",\r\n"
            		+ "            \"capability\": \"Qdv2/eBNqHMsZcPi7UaVRavH1HxGjcRp6lzEOJJiEBLKE9Zezg1BVf1bJxwrBUCaT84oI08Dvo4Ri+5IVUvt2/amyI1y+gYOQOiSuuDU3+NIL8DvyTmoRDYtqkA4fKHcdduj+wFKOjSM6HmUQKaS/HfQKOhma8bdZFLCZUG0Tqs=\"\r\n"
            		+ "        }\r\n"
            		+ "    },\r\n"
            		+ "    \"transactionInfo\": {\r\n"
            		+ "        \"transactionid\": \"12345678865987\",\r\n"
            		+ "        \"transactiondatetime\": \"2024-05-06 15:00:41\",\r\n"
            		+ "        \"attributes\": {\r\n"
            		+ "            \"amount\": 10.00,\r\n"
            		+ "            \"minamount\": 5.00,\r\n"
            		+ "            \"sign\": \"N\",\r\n"
            		+ "            \"mode\": \"01\",\r\n"
            		+ "            \"qrmedium\": \"04\",\r\n"
            		+ "            \"payeeName\": \"deepti\",\r\n"
            		+ "            \"vpa\": \"Letspe123@AuBank\",\r\n"
            		+ "            \"refid\": \"RAPI0001b1901\",\r\n"
            		+ "            \"refurl\": null,\r\n"
            		+ "            \"refurlcategory\": \"category\",\r\n"
            		+ "            \"mcc\": \"0000\",\r\n"
            		+ "            \"merchantGenre\": \"OFFLINE\",\r\n"
            		+ "            \"qrversion\": \"01\",\r\n"
            		+ "            \"currency\": \"INR\",\r\n"
            		+ "            \"merchantid\": 12345,\r\n"
            		+ "            \"storeid\": null,\r\n"
            		+ "            \"terminalid\": null,\r\n"
            		+ "            \"Tip\": null,\r\n"
            		+ "            \"invoiceno\": null,\r\n"
            		+ "            \"invoicedate\": null,\r\n"
            		+ "            \"qrcreatets\": \"2024-05-06 15:00:41\",\r\n"
            		+ "            \"qrexpirets\": null,\r\n"
            		+ "            \"amtsplit\": null,\r\n"
            		+ "            \"merchantpincode\": null,\r\n"
            		+ "            \"merchanttier\": null,\r\n"
            		+ "            \"qrtxntype\": null,\r\n"
            		+ "            \"payerconsent\": null,\r\n"
            		+ "            \"mandatename\": null,\r\n"
            		+ "            \"mandatetype\": null,\r\n"
            		+ "            \"validitystartdate\": null,\r\n"
            		+ "            \"validityenddate\": null,\r\n"
            		+ "            \"amtrule\": null,\r\n"
            		+ "            \"mandaterecur\": null,\r\n"
            		+ "            \"mandaterecurvalue\": null,\r\n"
            		+ "            \"mandaterecurtype\": null,\r\n"
            		+ "            \"mandaterevoke\": null,\r\n"
            		+ "            \"mandateshare\": null,\r\n"
            		+ "            \"mandateblock\": null,\r\n"
            		+ "            \"mandateumn\": null,\r\n"
            		+ "            \"mandateskip\": null,\r\n"
            		+ "            \"query\": null,\r\n"
            		+ "            \"purpose\": \"00\",\r\n"
            		+ "            \"remarks\": null\r\n"
            		+ "        }\r\n"
            		+ "    }\r\n"
            		+ "}"
            		+ "}"
            		+ ";";
            
            String encryptedData = encrypt(key, data);
            //System.out.println(encryptedData);
            
            String decryptedData = decrypt(key, "tbVIbUzK3SqBaISl3UBrAyRAai1BnN+lzGiLDX1FgIwktHtcpXVe2UYrggQQIet2j5kzFK/lWGfu3fM3kCTHWyWFYTLITxfWAnw3pdo5nhVeeI+ZFYAitXm/gcjsLcSaWxKIOqE705rJumcZtIeeWxV5stlDbGI/4NdU+eyuiIimfFFW8KhBdXORbmnudmL0/zT9r7Ra5wo9roPRrSrxCc4TAJSLBl7+9x7VCwdcgJAS3myG44Ze/FgY97IvwguA77o5n6eqUPMA82R0iT0N2VxmUYar82S26Z9Ld980xu2/W4X6iSCOhkomjlh3uDtCyKdZKeH+TEtC1tif2JkgfTkOOwGx8LBrxuJiK3xYRF9RD6Tk43jOaZf//zMVvcxjHuGWdYbrkf/dB1WrevSZm3ZjWdxR4gsqklseWRxAB8MuMoj/ga+45sqBqaV27YBQsHHrbIe+sIhGgBy3uCLZN+wNvBVJ4AgUZwH/20IyGe8zV+Do+1rlsQfiORsWPJyhgzff6q3Tleza0DoorlJwI07y1V3SqBl7ahaEeAczU+9LuFxoCkfhoZlzys1wFCmxt+0QY1h31An40jTFQvUp4bmiDtUlrDp+LiDTX4CWh3o/2nhbuCopSSgQQXheocLP/hWMfhINxylF999Iv1TTL0/WfWDoM8AzugwtmEHBrLraM3FfPRAo5RiObXcS1Ia97IRYVSjCwqV0kI5dvTXuagOZhs46gV4atQsdrq1+Tr+ft/QEH8XekucPCLF4x5YDMczvbq72JqHJYlMCsXzqPDpl78aE4Akz+bxrcyggmcDKkP0KCrrhZrLrcsjortr/fpQgki+lsOzADIBeYX9Z6zowhrIYipAKHmvLPoh9jDYCr0+o334nFme0xQVQXJ6k8c4cItzBdtPLQNKR9UKRRt7uj1EWdl0cN3NxMWIITo42U55hX19SUOuNbrSZrneVSJv+Cegdnch3n91ODneytCgcjiWOWXE2svZxF7ajQnT6vZsVLHWnFKUHxFtN88mq0kA1tNekh9RQWvAvxf6DCsXNHzexwCBtw337A9kmHDZWmnk/5iH0jPePoTRbotvQe7GgYlO7e0rV4GAma7vhrH745sYNpS4AlAP8WLIG1ybd0p99jP1WvNNfFtEKcZ/l0EsU2POaBvF8aw0fTQJU9eUsaDbl4Oa8q0leZv0KfbVdu/XSxOF0PPblcHK/we6Lu/BY4sCiVR7OnEIeWbp7Fd+dtz/Npf7C7VKrqed1to/7AYR4CTDTdzxmMFVzZe1BC3mqNMMcyLwhV1x8l2aGXf9LMkpdRZ955n9xQT9U4D8=");
           System.out.println(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
