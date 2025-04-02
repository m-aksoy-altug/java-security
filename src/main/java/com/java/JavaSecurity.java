package com.java;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JavaSecurity {
	// exec:java -Dexec.mainClass="com.java.JavaSecurity"
	private static final Logger log = LoggerFactory.getLogger(JavaSecurity.class);
	private static final int PORT = 8443;
	private static final String KEYSTORE = "server.p12";
	private static final String KEYSTORE_PASSWORD = "password";
	private static final String TLSv1_3 = "TLSv1.3";
	private static final String PKCS12 = "PKCS12";

	public static void main(String[] args) {
		// openssl s_client -connect 192.168.1.113:8443 -tls1_3
		pureTLSOverTCP();
	
	}
	
	/* - Protocol: Pure TLS (Transport Layer Security) over TCP (Transmission Control Protocol) 
	 * - Connection Type: Raw Socket SSLSocket with TLS encryption
	 * - Data type: Unstructured binary/plain text  
	 * - Use case: IoT, Gaming, financial data stream
	*/
	private static void pureTLSOverTCP() {
		try {
			SSLContext sslContext = SSLContext.getInstance(TLSv1_3);
			KeyStore ks = KeyStore.getInstance(PKCS12);
			ks.load(new FileInputStream(KEYSTORE), KEYSTORE_PASSWORD.toCharArray());
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
	        kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());
	        // Disable hostname verification (for testing with self-signed certs)
	        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
	        sslContext.init(kmf.getKeyManagers(), null, null);
	        
	        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
	        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(PORT,0, 
	        										InetAddress.getByName("0.0.0.0"));
	        
	        log.info("Server started on port " + PORT + " (TLS 1.3, AES-256-GCM)");
	        
	        // Enforce TLS 1.3 and AES-256-GCM
	        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
	        serverSocket.setEnabledCipherSuites(new String[]{"TLS_AES_256_GCM_SHA384"});
	        ExecutorService threadPool = Executors.newCachedThreadPool(); //Executors.newFixedThreadPool(10);
	        
	        while(true) {
	        	 SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
	        	 threadPool.execute(() -> handleClient(clientSocket));
	        }
	        
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {	
			e.printStackTrace();
		}
	}

	private static void handleClient(SSLSocket socket) {
		log.info("New client connected: " + socket.getRemoteSocketAddress());
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	         PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
	        
	        out.println("Welcome to TLS 1.3 Server! Type 'exit' to disconnect.");

	        String clientMessage;
	        while ((clientMessage = in.readLine()) != null) {
	        	log.info("Client [" + socket.getRemoteSocketAddress() + "] says: " + clientMessage);
	            
	            if ("exit".equalsIgnoreCase(clientMessage.trim())) {
	                out.println("Goodbye!");
	                break;
	            }
	            out.println("Server echoes: " + clientMessage);
	        }
	    } catch (IOException e) {
	        log.error("Client handling error: " + e.getMessage());
	    } finally {
	        try {
	        	log.info("Client disconnected: " + socket.getRemoteSocketAddress());
	            socket.close();
	        } catch (IOException e) {
	        	log.error("Error closing socket: " + e.getMessage());
	        }
	    }
	}

}