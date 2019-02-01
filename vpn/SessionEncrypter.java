
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;


import javax.crypto.spec.IvParameterSpec;

import java.io.OutputStream;

import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {

    private SessionKey sessionkey;  //
    private byte[] Iv; //initialisation vector
    private Cipher cipher;

    public SessionEncrypter (Integer keylength) throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        Iv=new byte[16];
        secureRandom.nextBytes(Iv);

        sessionkey=new SessionKey(keylength);
        IvParameterSpec myParams = new IvParameterSpec(Iv);
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionkey.getSecretKey(), myParams);
    }

    public SessionEncrypter(String keystring,String iv) throws Exception{
        Iv= Base64.getDecoder().decode(iv);
        sessionkey= new SessionKey(keystring);
        IvParameterSpec myParams = new IvParameterSpec(Iv);
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionkey.getSecretKey(), myParams);
    }

    public byte[] encodeKey(){
        return sessionkey.getSecretKey().getEncoded();
    }
    public byte[] encodeIV(){
        return Iv;
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) throws Exception{
        CipherOutputStream out_stream = new CipherOutputStream(output,cipher);
        return out_stream;
    }

}

