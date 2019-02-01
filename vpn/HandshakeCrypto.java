import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;


public class HandshakeCrypto {
    public static byte[] encrypt(byte[] plaintext, Key key) throws Exception{
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        return encryptCipher.doFinal(plaintext);
        }


    public static byte[] decrypt(byte[] ciphertext, Key key) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws Exception{
        FileInputStream ca = new FileInputStream(certfile);
        CertificateFactory factory =CertificateFactory.getInstance("X509");
        X509Certificate cert_ca =(X509Certificate)factory.generateCertificate(ca);
        return cert_ca.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws Exception{
// Read file to a byte array.
        String privateKeyFileName = keyfile ;
        Path path = Paths.get(privateKeyFileName);
        byte[] privKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
