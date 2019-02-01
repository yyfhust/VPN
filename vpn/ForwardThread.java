/**
 * ForwardThread handles the TCP forwarding between a socket input stream (source)
 * and a socket output stream (destination). It reads the input stream and forwards
 * everything to the output stream. If some of the streams fails, the forwarding
 * is stopped and the parent thread is notified to close all its connections.
 */
 
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
 
public class ForwardThread extends Thread {
    private static final int READ_BUFFER_SIZE = 8192;

    InputStream mInputStream = null;
    OutputStream mOutputStream = null;

    ForwardServerClientThread mParent = null;

    private String sessionkey_string;
    private String sessioniv_string;

    private boolean flag1;

    /**
     * Creates a new traffic forward thread specifying its input stream,
     * output stream and parent thread
     */

    public ForwardThread(ForwardServerClientThread aParent, InputStream aInputStream, OutputStream aOutputStream, String key, String iv, boolean flag) throws Exception {
        mInputStream = aInputStream;
        mOutputStream = aOutputStream;
        mParent = aParent;

        sessionkey_string = key;
        sessioniv_string = iv;

        flag1=flag;
    }



    /**
     * Runs the thread. Until it is possible, reads the input stream and puts read
     * data in the output stream. If reading can not be done (due to exception or
     * when the stream is at his end) or writing is failed, exits the thread.
     */
    public void run() {

        if ( (mParent.decide()==true && flag1== false) || (mParent.decide()==false && flag1 == true) ) {  //client forwarder  to encrypt

                try {
                    SessionEncrypter session_encrypt = new SessionEncrypter(sessionkey_string, sessioniv_string);
                    CipherOutputStream outstream = session_encrypt.openCipherOutputStream(mOutputStream);


                    byte[] buffer = new byte[READ_BUFFER_SIZE];
                    try {
                        while (true) {
                            int bytesRead = mInputStream.read(buffer);
                            if (bytesRead == -1)
                                break; // End of stream is reached --> exit the thread
                            outstream.write(buffer, 0, bytesRead);
                        }
                    } catch (IOException e) {
                        // Read/write failed --> connection is broken --> exit the thread
                    }
                }catch(Exception e){

                }

                // Notify parent thread that the connection is broken and forwarding should stop
                mParent.connectionBroken();
            }



        else{ //server forwarder   to decrypt

                try {
                    SessionDecrypter session_decrypt = new SessionDecrypter(sessionkey_string, sessioniv_string);
                    CipherInputStream instream = session_decrypt.openCipherInputStream(mInputStream);

                    byte[] buffer = new byte[READ_BUFFER_SIZE];
                    try {
                        while (true) {
                            int bytesRead = instream.read(buffer);
                            if (bytesRead == -1)
                                break; // End of stream is reached --> exit the thread
                            mOutputStream.write(buffer, 0, bytesRead);
                        }
                    } catch (IOException e) {
                        // Read/write failed --> connection is broken --> exit the thread
                    }

                    // Notify parent thread that the connection is broken and forwarding should stop
                } catch(Exception e){
                }
            mParent.connectionBroken();
        }


        }

    }
