package Deepti;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class JWETest1 {

    private static final String CLIENT_PRIVATE_KEY =
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCOYTIUTU4bxS7N" +
            "x7k9QE3NY6Z7xQhAykXNYmGk6LfO5fmUXuQ9s9CpefywLTRAgCBy/IJFZLgjVHD9" +
            "F1bhaJdaYdPC3FOkHUTIr7g/BN4fskvO7aJnuArkC8rXvXU+LiQPwqUFN4HclN4X" +
            "GGMacUGzFiIy972cYLF8rjNktRDATnuzWHWjyi8CEJgoFZSeqOHz8U4Kq2EBT1oU" +
            "3/q3Cfpx3UOpPv3mrEBgS7vft0Np06kSHcl7ekLd3veVby7Xz55O4jvfS0ZuCs+8" +
            "JpbXhlORm0ysM8WNKQICUn/dplHhXfIrtizefhDEGw9HeqssKv0ceXGTvBR8vJ8s" +
            "5YCJ/pmNAgMBAAECggEAFAqYawUqrnwGB49KgtWvXe7d+2QTslMGmk9z4Suk2+nB" +
            "ROJKjGjoQULbj8z9IusmJilnCO+Rf9+d+/IyF46KZ32HulEbMOmxyfH6JFzCC4Ik" +
            "a59FkgX0+n6yccXIYBVMnC9Q3Tgf/nWyAVw8bvdsQRInhDcdKIrv0NYQg+d80STF" +
            "OsGArNcx+xdpPUMuVHlZ9eG24QQHiDc5I031J7ecMRJmJ0C+JKQowH08WaBifCuG" +
            "G9M35hIuvb0d1Z5LF8MRXvGj0Vwn1Sk1slLlEFUedG3BKrj5sVnrzDYcfTPjRCDk" +
            "FwrdyBXKqgUiCkAfPhu4nCx893x2NcYFc8cfUK7foQKBgQDFyxSH7J39PYIiMae9" +
            "lK9gpWOqA7yn6lb2tp3VXQW8fzLj7XqGvl6rC9GCXkLpdEzTbospHqWbWVVVCY60" +
            "JXccWotr8AlGfYI6f00wRRAl9M9Eb+xwE7YGAPhWIFVubz4KvgPsJG+U+4SNavyG" +
            "lxZ8DoWkPJgCVVjJyMoP9HoVxQKBgQC4R3xAICEZXfOMHeD9JnSmirKxzIUWtrW/" +
            "vE2CzBQP+U8t0dUFiRbK5gezuTaFEXish9AhLFkV97T3MX1HVCCyhI8f/syGmtaY" +
            "FMngleXMG/HeGMD7OFtWMPmSPWcTdDq0ggLRZHUj5wIfa0P2u1lqt9basG5BxHrq" +
            "dZoXXvt5KQKBgB+W/rFyzgzbHQSfD55Mt/HkmFVYAXKED92Zbv3bvIXNfvA+Rnps" +
            "vyvsWErNCTzF8Vs3ZYxss6BrFSDexObqsOpbX7cegCy88Oas3EQgU6LsRYo1ofqI" +
            "e2LcFs2SnnJj2/HVRUUa0KNnxFTdyHUqflHT8+42K0T8IpEfu33u2uzNAoGASdYC" +
            "t+LnwDU/x22VX3lQFgbO0KTE0rQEoL1/RSAmDbxz+ETyGJS0ODnw7hcQ/EJi2qZU" +
            "Q2Z0j3O/46fFrZXMwBqTClvacTiLMUZrGPyWpbCwua+raz1Kg39+EBVgPpA8kWTi" +
            "YinhMbB2zkX5Zlvs2PCuOtOkad+i7FyQkDqzgfkCgYAGYK5gySyJQI1n5AhAeKeF" +
            "tCTncH9//gFrhzSqkvpfgdJ+Z4dawFgCbgzemSzYorI3FYKlP9Ma7s5e9YzWPMh+" +
            "oLaearrayzS6MbEifRecc1+twLxqrbqwXTmxmywSU0ouZpCczqHk0+6Sm4S9dTt7" +
            "Ev6QpSq6BEuJ3uml7xgFlw==";

    public static void main(String[] args) {
        String input = "{\n" +
                "    \"Request\": {\n" +
                "        \"body\": {\n" +
                "            \"encryptData\": {\n" +
                "                \"mid\": \"YOUTUBE001\",\n" +
                "                \"channel\": \"api\",\n" +
                "                \"account_number\": \"04762020001837\",\n" +
                "                \"mobile_number\": \"9131445536\",\n" +
                "                \"terminalId\": \"YOUTUBE786\",\n" +
                "                \"name\": \"Shankar Hotel\",\n" +
                "                \"bank_name\": \"Canara Bank\",\n" +
                "                \"mcc\": \"6012\",\n" +
                "                \"ifsc_code\": \"CNRB0000000\",\n" +
                "                \"sid\": \"YOUTUBE787\",\n" +
                "                \"additionalNo\": \"9425415918\",\n" +
                "                \"checksum\": \"ytydtdgdggdg1200345\"\n" +
                "            }\n" +
                "        }\n" +
                "    }\n" +
                "}";

        String signature = sign(input);
        System.out.println("Signature: " + signature);
    }

    public static String sign(String input) {
        try {
            String realPK = CLIENT_PRIVATE_KEY.replaceAll("\\s+", "");

            byte[] decodedKey = Base64.getDecoder().decode(realPK);

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            PrivateKey privateKey = kf.generatePrivate(spec);

            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);

            privateSignature.update(input.getBytes(StandardCharsets.UTF_8));
            byte[] signature = privateSignature.sign();

            return Base64.getEncoder().encodeToString(signature);
        } catch (Exception e) {
            throw new RuntimeException("Error signing the payload: " + e.getMessage(), e);
        }
    }
}
