
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;


public class SessionKey{
    private int length; //length of the key

    private SecretKey secret_key;
    
    private byte[] key;

    public SessionKey(int keylength) {

        try{
            KeyGenerator key_generator = KeyGenerator.getInstance("AES");
            length= keylength;
            SecureRandom secureRandom = new SecureRandom();
            key_generator.init(length, secureRandom);
            secret_key = key_generator.generateKey();
            key= secret_key.getEncoded();
           // System.out.println(key);
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }

    }

    public SessionKey(String encodedkey) {

        byte[] key = Base64.getDecoder().decode(encodedkey);
        secret_key= new SecretKeySpec(key, 0, key.length,"AES");
    }

    public SecretKey getSecretKey(){

        return secret_key;
    }

    public String encodeKey(){

        return Base64.getEncoder().encodeToString(  secret_key.getEncoded() );
    }
}
