package Deepti;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.jar.JarException;

import org.apache.commons.codec.DecoderException;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.JoseException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import kong.unirest.HttpResponse;
import kong.unirest.Unirest;

public class JWETest {

  
  private static final String DATA_TO_ENCRYPT = "{\n"
      + "                \"Authorization\":\"Basic U1lFREFQSUFVVEg6MmE4OGE5MWE5MmE2NGEx\",\n"
      + "                \"txnPassword\":\"2a88a91a92a64a1a1a3\",\n"
      + "                \"srcAcctNumber\":\"2774201000198\",\n"
      + "                \"destAcctNumber\":\"9833111000032\",\n"
      + "                \"customerID\":\"13961989\",\n"
      + "                \"txnAmount\":\"1\",\n"
      + "                \"benefName\":\"test\"\n"
      + "            }";
  

  public static final String CLIENT_PRIVATE_KEY = 
  "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\n" +
  "ElJYe8JTWmeM+Lzx9cftsvQITq9mAw==".replaceAll("\n", "");

  /** Client's public-key/certificate */
  private static final String CLIENT_PUBLIC_CERT = "MIIFYDCCA0gCCQCLcG3dN8mSYTANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJJTjESMBAGA1UECAwJVEVMQU5HQU5BMRIwEAYDVQQHDAlIWURFUkFCQUQxEDAOBgNVBAoMB1RCT0NXV0IxFDASBgNVBAsMC0xBQk9VUiBERVBUMRMwEQYDVQQDDApUQk8gU0VSVkVSMB4XDTIzMDIyMTE5Mzg0M1oXDTI0MDIyMTE5Mzg0M1owcjELMAkGA1UEBhMCSU4xEjAQBgNVBAgMCVRFTEFOR0FOQTESMBAGA1UEBwwJSFlERVJBQkFEMRAwDgYDVQQKDAdUQk9DV1dCMRQwEgYDVQQLDAtMQUJPVVIgREVQVDETMBEGA1UEAwwKVEJPIFNFUlZFUjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMQtk6PBJzBnd1jpbaoa+xz//xLeOJ4VLgV6pqPJmiXBRkMW07sMAd63j0dblSV+LTR5nzUL5+mB4FCG3EBm2blZF4a0d9D6QhsbmkFU4uT56hZttEW667z1tWRKz9TFOcgXFgnhPuROlVAYw6kymthXMLbo0q45gGaofL3aISD2JI1Tfrd7cHZAVcNA9nrQ+cc63bPEXuoggjO2mGg7X0xKrpvieGGzk7TsIWgPWc9XndEdTJvxyWo+PGuIboXjlzcpYAraldA5M0jyjcGDauQavYA0HwuYIpjmGJwDdfe/wf228nyvNLs3qd1/9z65B1g323u2CWcgvL7EmIgHPjqh6gWmp5pkLS+T1Ex+I4pTpw7VGpLTDtHNPGetF/hz7mqm1s0jnL/xRnCqDcQXx0Xhu8f1Mglu9hBQwQ/ktg6OpYBEL6T1M9Iz08HCaF1FZ5lX6IYc52Yn00f5fVQmitdaerdWBcaEryt8+CJh3dQhHdQvj1i5ubibvnKAnoNUi7lP7ROxsWkLxIZiXFFvMhswL0RkzYO3XLd5z7gsGuK8O5JBtHxQLIdwe2t3D+Hlbm85ij8B1JTcxBNRtFM88MKNY4GQZpuryR7S/q9Sfdax3jRvt0DgvamCC35/d/eOpyLicPILb8h3lcVEyw39HaYfwTMvnyG9QUZbJpopRuZjAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAGUNoHAtxzprDAmC4pXCKi7BxelXF2YX8Tr3SIxufd8FAsugujuKpXKBpKRKIwbVLYy9/kfHUX6lh3j67OZ4RRf4NJJrPjpKatKJKZcf4g69CzzxQj5O2rRqHuxw6fbSTc/QTdYNlvQjBQFlqsfqliqms/9hagm1r2FQXBITYYe/PJINxUAa4bVAgR7FoKTga+KIl27+UeD0015/DjRIUNpjhfmJhpbOvno+UarGEfx6fZbXtW9iDEWzS4LTnBS0VR5kj5LaBDBuqW4ov73usejSMQ//hn94krF1X1doFk95e3e6jd+WNFAxEfXtXtk1v8JN2HA1nwnn6vVxeFhvXUBbYmD/5ZnygDVJmyW5BqMqUiL+ST+IprdgD3fXfntCeMjN7kSvY4C1KzUpfnPZM1Eh0y/2gGPXwMqwY5a2XbXYSgavB2TV917POsAXelQWTfzdximTDHDeQRQ3voyOcxtUGwqFJuAdW2R/kaTCRuTIiXwMjx9vRp1qKDuqKUgIdqmQuIFQ3Fx45pDo7fR62FfcFNwkXLb55OfTRFsAxeVaD+x+IyCrA3lXAyQ7b5nZEjEmLQnWQVau9qsiJ/GXOpPigiAB2PUuXD74djzHHmF5IOfieUl0ZMgMR5DzZduzq08n3xArlLur9u/RiSZZ5jxMdSvmuh+/E22aLPuGeVDg";
      
     

  /* App Key obtained from Developer Portal during API Subscription */
  private static final String API_KEY = "c0fd59e3eadecbfd1148077ab1321c0c";//"dcf7b96c52d73411e47ed24a249221e0";

  /* App Secret for the App Key */
  private static final String API_SECRET = "844e18f5eda1da9f3b7b2dd78c5af304";//"451a65004ac58632f442eac0f890e62d";

  
  
  private static final String REQ_BODY = "{\n"
      + "    \"Request\":{\n"
      + "        \"body\":{\n"
      + "            \"srcAccountDetails\":{\n"
      + "                \"identity\":\"B001\",\n"
      + "                \"currency\":\"INR\",\n"
      + "                \"branchCode\":\"2774\"\n"
      + "            },\n"
      + "            \"destAccountDetails\":{\n"
      + "                \"identity\":\"B001\",\n"
      + "                \"currency\":\"INR\"\n"
      + "            },\n"
      + "            \"txnCurrency\":\"INR\",\n"
      + "            \"narration\":\"TC INTFR TC1 CA TO CA SAME CUSTOMER\",\n"
      + "            \"valueDate\":\"09-46-2022\",\n"
      + "            \"paymentMode\":\"N\",\n"
      + "            \"standingInstDetails\":{\n"
      + "                \"frequency\":\"1\"\n"
      + "            },\n"
      + "            \"encryptData\":\"%s\"\n"
      + "        }\n"
      + "    }\n"
      + "}";

  /* UNENCRYPTED PAYLOAD */

  private static final String PAY_LOAD_PLAIN = "{\n"
      + "    \"Request\":{\n"
      + "        \"body\":{\n"
      + "            \"srcAccountDetails\":{\n"
      + "                \"identity\":\"B001\",\n"
      + "                \"currency\":\"INR\",\n"
      + "                \"branchCode\":\"2774\"\n"
      + "            },\n"
      + "            \"destAccountDetails\":{\n"
      + "                \"identity\":\"B001\",\n"
      + "                \"currency\":\"INR\"\n"
      + "            },\n"
      + "            \"txnCurrency\":\"INR\",\n"
      + "            \"narration\":\"TC INTFR TC1 CA TO CA SAME CUSTOMER\",\n"
      + "            \"valueDate\":\"09-46-2022\",\n"
      + "            \"paymentMode\":\"N\",\n"
      + "            \"standingInstDetails\":{\n"
      + "                \"frequency\":\"1\"\n"
      + "            },\n"
      + "            \"encryptData\":{\n"
      + "                \"Authorization\":\"Basic U1lFREFQSUFVVEg6MmE4OGE5MWE5MmE2NGEx\",\n"
      + "                \"txnPassword\":\"2a88a91a92a64a1a1a3\",\n"
      + "                \"srcAcctNumber\":\"2774201000198\",\n"
      + "                \"destAcctNumber\":\"9833111000032\",\n"
      + "                \"customerID\":\"13961989\",\n"
      + "                \"txnAmount\":\"1\",\n"
      + "                \"benefName\":\"test\"\n"
      + "            }\n"
      + "        }\n"
      + "    }\n"
      + "}";

  
  // static String SHARED_SYMMETRIC_KEY =
  // "f2b0be3685954bf45ca797a1cb547924cdaa8514b93d25860570115bdebe2177";
  /*Symmetric (Shared) Key used for encryption and decryption */
  static String SHARED_SYMMETRIC_KEY = "2457bf1dc01659e2cd0af14dced615376aaab76f40c0e89d641421f807112b84";

  public static void main(String[] args)
      throws NoSuchAlgorithmException, JarException, InvalidKeySpecException, BindException, IOException {
    JWETest client = new JWETest();
    String encrypted = client.encrypt(DATA_TO_ENCRYPT);
    System.out.println("Checking decryption..");
    client.decrypt(encrypted);
    String payload = String.format(REQ_BODY, encrypted);
    System.out.println(payload);
    com.google.gson.JsonObject json = JsonParser.parseString(PAY_LOAD_PLAIN).getAsJsonObject();
    //JSONObject json = new JSONObject(PAY_LOAD_PLAIN);
    String sign = client.sign(json.toString());
    System.out.println("Signaure: \n" + sign);
    String response = client.invokeUniRequest(payload, sign);
    JsonObject responseObj = JsonParser.parseString(response).getAsJsonObject();
    System.out.println(responseObj);
    if (responseObj.get("Response") != null) {
    String encr = responseObj.getAsJsonObject("Response").getAsJsonObject("body").get("encryptData").toString();
    client.decrypt(encr.replaceAll("\"", ""));
    } else {
      System.err.println(responseObj);
    }
  }

  /* Method to encrypt the given input per JWE specification */
  private String encrypt(String input) throws NoSuchAlgorithmException, UnsupportedEncodingException, JoseException,
      InvalidKeySpecException, BindException {
    System.out.println("String to encrypt:"+input);
    JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
    jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);
    jwe.setKey(new AesKey(digest()));
    // jwe.setCompressionAlgorithmHeaderParameter(CompressionAlgorithmIdentifiers.DEFLATE);
    jwe.setPayload(input);
    String encrypted = jwe.getCompactSerialization();
    System.out.println(encrypted);
    return encrypted;
  }

  /* Method to decrypt the given input per JWE specification */
  private void decrypt(String input) throws JoseException, NoSuchAlgorithmException, UnsupportedEncodingException,
      InvalidKeySpecException, DecoderException {
    System.out.println("String to decrypt:" + input);
    JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setCompactSerialization(input);
    AesKey aes = new AesKey(digest());
    jwe.setKey(aes);
    String plaintext = jwe.getPlaintextString();
    // And do whatever you need to do with the clear text message.
    System.out.println("Decrypted Text: " + plaintext);

  }

  /**
   * Method responsible for calling the specificed API and return the API response
   */
  private String invokeUniRequest(String payload, String signature) {
    // Unirest.setTimeouts(0, 0);
    HttpResponse<String> response = Unirest.post(API_GW_URL)
        .header("x-client-id", API_KEY)
        .header("x-client-secret", API_SECRET)
        .header("x-api-interaction-id", "fccfdade-2a4c-4616-b76e-4837f5ea4ae2")
        .header("x-timestamp", "1675780846")
        .header("x-client-certificate", CLIENT_PUBLIC_CERT)
        .header("x-signature", signature)
            //"Bo8bumksbX1oPK8ZuXQD98ilFN5Mr4okjDcipVADXntorqdPGvPRvHONbcIfjXZY3p6HLf+s8TuEPZmP4dLngM8zZ/FaAA7JP5Gzk7euTlte96gqSX/+UAGKA13DMxQJHDcARfA2zKMjSeZ2J4y1jGgjVyuYuOtj4I/56X2Ul/E0USe3tEAFfZfonGmWPrhk3BxGjKq8dR+6895yhSQsqUSARvsBmZm4ZYaMhXN81Ke/0g5Y5LepGrjitPb2CxUtESuRSz3NnrdXtw4ELKs7dOmi21BWdY90dVgh2CZWiOPZXHcI/PcSDftlv6Xndlxh3DG+qJuZu1AUvBTB3tM4fg==")
        .header("Content-Type", "application/json")
        .header("Cookie",
            "1122; TS01ea60e3=01aee67679c686b25f6fff23b7e82ee443fbcf7777927798d6167f014830f9fe80355ed560765eed2826bf9854c1f19b829f27dc2d; TS01ea60e3028=0192426cf8e858e9bfb109d227872f0e0517dd288d0a90c12f79c8fa30dbee07ff9189200d1d4ec8fcc47d9958f1016e268bb37d2f")
        .header("X-Forwarded-For", "weasdwd")
        .body(payload)
        .asString();
    return response.getBody();

  }

  public String sign(String input) {
    String realPK = CLIENT_PRIVATE_KEY.replaceAll("-----END RSA PRIVATE KEY-----", "")
        .replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
        .replaceAll("\n", "");
    byte[] b1 = Base64.getDecoder().decode(realPK);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
    try {
      KeyFactory kf = KeyFactory.getInstance("RSA");

      Signature privateSignature = Signature.getInstance("SHA256withRSA");
      privateSignature.initSign(kf.generatePrivate(spec));
      privateSignature.update(input.getBytes("UTF-8"));
      byte[] s = privateSignature.sign();
      return Base64.getEncoder().encodeToString(s);
    } catch (InvalidKeyException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (SignatureException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (UnsupportedEncodingException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return null;
  }

  /* utility function to convert a given symmetric key into binary format */
  private byte[] digest()
      throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, DecoderException {
    byte[] val = new byte[SHARED_SYMMETRIC_KEY.length() / 2];
    for (int i = 0; i < val.length; i++) {
      int index = i * 2;
      int j = Integer.parseInt(SHARED_SYMMETRIC_KEY.substring(index, index + 2), 16);
      val[i] = (byte) j;
    }
    return val;
  }
    
}
