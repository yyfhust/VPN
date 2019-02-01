/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;

    ///
    private static X509Certificate crt_server;
    private static X509Certificate crt_ca;
    private static SessionKey sessionkey;
    private static String sessionkey_string;
    private static String sessioniv;

    private static PrivateKey privatekey;

    private static String target_host;
    private static String targer_port;

    private static void doHandshake() throws IOException,Exception {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));


        /* This is where the handshake should take place */

        String ca =    arguments.get("cacert");
        FileInputStream ca_file = new FileInputStream(ca);
        CertificateFactory factory =CertificateFactory.getInstance("X509");
        X509Certificate crt_ca =(X509Certificate)factory.generateCertificate(ca_file);


        try{
            crt_ca.verify(crt_ca.getPublicKey());
            crt_ca.verify(crt_ca.getPublicKey());
        }catch (SignatureException e){
            System.out.println("Certificate CA verification fail, please input again: ");
            System.out.println(e.getMessage());
            return;
        }


        target_host =    arguments.get("targethost");
        targer_port =   arguments.get("targetport");

        privatekey = HandshakeCrypto.getPrivateKeyFromKeyFile (arguments.get("key") );


        FileInputStream us = new FileInputStream(arguments.get("usercert") );
        CertificateFactory factory1 =CertificateFactory.getInstance("X509");
        X509Certificate cert_us =(X509Certificate)factory1.generateCertificate(us);
        try{
            cert_us.verify(crt_ca.getPublicKey());
            cert_us.verify(crt_ca.getPublicKey());
        }catch (SignatureException e){
            System.out.println("Certificate clientforward(YOURSELF) verification fail, please input again: ");
            System.out.println(e.getMessage());
            return;
        }


        //step 1, clienthello
        HandshakeMessage clienthello = new HandshakeMessage();
        clienthello.putParameter("MessageType","ClientHello");
        clienthello.putParameter("Certificate",encodeCertificate( cert_us ));
        clienthello.send(socket);

        //step2, waiting for response
        HandshakeMessage fromserver= new HandshakeMessage();
        fromserver.recv(socket);
        if (fromserver.getParameter("MessageType").equals("ServerHello")) {
            crt_server = decodeCertificate(fromserver.getParameter("Certificate"));
            try{
                crt_server.verify(crt_ca.getPublicKey());
                crt_server.checkValidity();
            }
            catch ( NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | CertificateExpiredException | CertificateNotYetValidException e){
                System.out.println("Exception happened at verifying server's certificate : "+ e.getMessage());
                return ;
            }

            ///step3: Forward message
            HandshakeMessage forward = new HandshakeMessage();
            forward.putParameter("MessageType","Forward");
            forward.putParameter("TargetHost",target_host);
            forward.putParameter("TargetPort",targer_port);
            forward.send(socket);


            //step4, waiting for session message from server
            HandshakeMessage fromserver2= new HandshakeMessage();
            fromserver2.recv(socket);
            if(fromserver2.getParameter("MessageType").equals("Session") ){
                serverHost = fromserver2.getParameter("ServerHost");
		//serverHost= arguments.get("handshakehost");
                serverPort = Integer.parseInt( fromserver2.getParameter("ServerPort")) ;

                sessionkey= new SessionKey(  Base64.getEncoder().encodeToString(HandshakeCrypto.decrypt(  Base64.getDecoder().decode(fromserver2.getParameter("SessionKey").getBytes()), privatekey)) );
               // System.out.println(fromserver2.getParameter("SessionKey"));
                sessionkey_string=sessionkey.encodeKey();
                sessioniv=  Base64.getEncoder().encodeToString ( (HandshakeCrypto.decrypt( Base64.getDecoder().decode(fromserver2.getParameter("SessionIV").getBytes())  ,privatekey )));
            }
            else{
                log("Received illegal argument, should received : Session");
                log("But received "+ fromserver2.getParameter("MessageType")+ " actually");
            }

        }

        else{
            log("Received illegal argument, should received: ServerHello");
            log("But received "+ fromserver.getParameter("MessageType")+" actually " );
        }

        socket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect. 
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead. 
         */

    }




    private static String encodeCertificate(X509Certificate cert) throws Exception{
        return Base64.getEncoder().encodeToString(cert.getEncoded()) ;
    }
    private static X509Certificate decodeCertificate(String ctr) throws Exception{
        InputStream ctrstream = new ByteArrayInputStream(Base64.getDecoder().decode(ctr));
        CertificateFactory factory =CertificateFactory.getInstance("X509");
        return (X509Certificate)factory.generateCertificate(ctrstream);
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws IOException,Exception {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            listensocket.bind(null); 
            /* Tell the user, so the user knows where to connect */ 
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);
            
            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort, sessionkey_string,sessioniv);
            forwardThread.start();
            
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }



    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) throws Exception
    {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        try {
            startForwardClient();
        } catch(IOException e) {
           e.printStackTrace();
        }
    }
}
