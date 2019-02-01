/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;

 
public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    private X509Certificate ctr_us;
    private X509Certificate ctr_ca;

    byte[] sessionkey_encrypted;
    byte[] sessioniv_encrypted;


    byte[] sessionkey;
    byte[] sessioniv;

    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */


        String ca =    arguments.get("cacert");
        FileInputStream ca_file = new FileInputStream(ca);
        CertificateFactory factory =CertificateFactory.getInstance("X509");
        ctr_ca =(X509Certificate)factory.generateCertificate(ca_file);

        try{
            ctr_ca.verify(ctr_ca.getPublicKey());
            ctr_ca.verify(ctr_ca.getPublicKey());
        }catch (SignatureException e){
            System.out.println("Certificate CA verification fail, please input again: ");
            System.out.println(e.getMessage());
            return;
        }


       // System.out.println("ca: "+ctr_ca.getSubjectDN().getName());



        //step1 :receive client hello
        HandshakeMessage fromclient =new HandshakeMessage();
        fromclient.recv(clientSocket);
        if (fromclient.getParameter("MessageType").equals("ClientHello")) {
            ctr_us = decodeCertificate(fromclient.getParameter("Certificate"));
            try{
                ctr_us.verify(ctr_ca.getPublicKey());
                ctr_us.checkValidity();
             //   System.out.println(ctr_us.getSubjectDN().getName());
            }
            catch ( NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | CertificateExpiredException | CertificateNotYetValidException e){
                System.out.println("Exception happened at verifying client's certificate : "+ e.getMessage());
                return ;
            }

            //step2: send serverhello

            FileInputStream us = new FileInputStream(arguments.get("usercert"));
            CertificateFactory factory1 =CertificateFactory.getInstance("X509");
            X509Certificate cert_us =(X509Certificate)factory1.generateCertificate(us);
           // System.out.println(cert_us.getSubjectDN().getName());


            HandshakeMessage serverhello = new HandshakeMessage();
            serverhello.putParameter("MessageType","ServerHello");
            serverhello.putParameter("Certificate",encodeCertificate( cert_us));
            serverhello.send(clientSocket);

            //step3: receive forward message
            HandshakeMessage fromclient2 = new HandshakeMessage();
            fromclient2.recv(clientSocket);
            if(fromclient2.getParameter("MessageType").equals("Forward")){
                targetHost = fromclient2.getParameter("TargetHost");
                targetPort = Integer.parseInt(fromclient2.getParameter("TargetPort")) ;

                //step4: send session message

                  //generate sessionkey and encrypt it
                SessionEncrypter session = new SessionEncrypter(128);
                sessionkey = session.encodeKey();
                sessioniv = session.encodeIV();

                sessionkey_encrypted = HandshakeCrypto.encrypt(sessionkey, ctr_us.getPublicKey());
                sessioniv_encrypted = HandshakeCrypto.encrypt(sessioniv,ctr_us.getPublicKey());

                HandshakeMessage session_message = new HandshakeMessage();
                session_message.putParameter("MessageType","Session");
                session_message.putParameter("SessionKey", new String(Base64.getEncoder().encode(sessionkey_encrypted)));
                //System.out.println(new String(Base64.getEncoder().encode(sessionkey_encrypted)));
                session_message.putParameter("SessionIV", new String(Base64.getEncoder().encode(sessioniv_encrypted)));
                session_message.putParameter("ServerHost",Handshake.serverHost);
                session_message.putParameter("ServerPort",Integer.toString( Handshake.serverPort) );
                session_message.send(clientSocket);
            }
            else{
                log("Received illegal argument, should received: Forward");
                log("But received "+ fromclient2.getParameter("MessageType")+" actually " );
            }

        }
        else{
            log("Received illegal argument, should received: ClientHello");
            log("But received "+ fromclient.getParameter("MessageType")+" actually " );
        }

        clientSocket.close();





        /* listenSocket is a new socket where the ForwardServer waits for the 
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the 
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort). 
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
    }



    private static String encodeCertificate(X509Certificate clientctr) throws Exception{

        return Base64.getEncoder().encodeToString(clientctr.getEncoded()) ;
    }
    private static X509Certificate decodeCertificate(String ctr) throws Exception{
        InputStream ctrstream = new ByteArrayInputStream(Base64.getDecoder().decode(ctr));
        CertificateFactory factory =CertificateFactory.getInstance("X509");
        return (X509Certificate)factory.generateCertificate(ctrstream);
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
           throw new IOException("Unable to bind to port " + port);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
           try {
               doHandshake();
               forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort,Base64.getEncoder().encodeToString( this.sessionkey), Base64.getEncoder().encodeToString(  this.sessioniv));
               forwardThread.start();
           } catch (IOException e) {
               throw e;
           }
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--serverhost=<hostname>");
        System.err.println(indent + "--serverport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        try {
           srv.startForwardServer();
        } catch (Exception e) {
           e.printStackTrace();
        }
    }
 
}
