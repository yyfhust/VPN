
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.InputStream;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class SessionDecrypter {

    private SessionKey sessionkey;  //
    private byte[] Iv; //initialisation vector
    private Cipher cipher;

    public SessionDecrypter(String key, String iv) throws Exception{
        sessionkey= new SessionKey(key);
        Iv= Base64.getDecoder().decode(iv);
        IvParameterSpec myParams = new IvParameterSpec(Iv);
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sessionkey.getSecretKey(), myParams);
    }

    public CipherInputStream openCipherInputStream(InputStream input){
        CipherInputStream input_stream= new CipherInputStream(input,cipher);
        return input_stream;
    }


}
