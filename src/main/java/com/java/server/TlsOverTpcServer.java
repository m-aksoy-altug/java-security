package com.java.server;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.utils.Constant;
import com.java.utils.Utils;

/* - Protocol: Pure TLS (Transport Layer Security) over TCP (Transmission Control Protocol), layer below HTTP/WebSocket (OSI Layer 4/5 - Transport/Session Layer).
 * - Connection Type: Stateful SSL/TLS-secured TCP socket (SSLSocket)
 * - Data type: Unstructured binary/plain text
 * - Message Framing: Manual   
 * - Use case: IoT, Gaming, financial data stream
*/
public class TlsOverTpcServer {
	private static final Logger log = LoggerFactory.getLogger(TlsOverTpcServer.class);
	
	/* - TLS version: TLSv1.3
	 * - Cipher: TLS_AES_256_GCM_SHA384
	*/
	public static void sslServerSocketTLS1Point3OverTCP() {
	        SSLServerSocket serverSocket = Utils.
	        		createSSLServerSocket(Constant.TLSv1_3,Constant.P8443);
	        log.info("Server started on port " + Constant.P8443 + " (TLS 1.3, AES-256-GCM)");
	        // Enforce TLS 1.3 and AES-256-GCM
	        serverSocket.setEnabledProtocols(new String[]{Constant.TLSv1_3});
	        serverSocket.setEnabledCipherSuites(new String[]{Constant.TLS_AES_256_GCM_SHA384});
	        serverSocket.setNeedClientAuth(false);   // true for mutual TLS, client must authenticate by KeyManager and TrustManager
	        AtomicInteger clientCounter = new AtomicInteger(0);
	        while(true) {
	        	 try {
		        	 SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
		        	 int clientNumber = clientCounter.incrementAndGet();
		             // Handle client in a new thread
	                 new Thread(() -> {
	                     try {
	                         handleClient(clientSocket, clientNumber);
	                     } finally {
	                         try {
	                             clientSocket.close();
	                         } catch (IOException e) {
	                             log.error("Error closing client socket: " + e.getMessage());
	                         }
	                     }
	                 }).start();
	        	 } catch (SSLHandshakeException e) {
	        		 log.error("SSL handshake failed: " + e.getMessage());
               } catch (IOException e) {
               	log.error("Server socket error: " + e.getMessage());
               }
	        }
	}
		
	/* - TLS version: TLSv1.2
	 * - Cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	*/
	public static void sslServerSocketTLS1Point2OverTCP() {
	        SSLServerSocket serverSocket = Utils.
	        		createSSLServerSocket(Constant.TLSv1_2,Constant.P8444);
	        
	        log.info("Server started on port " + Constant.P8444 + " (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)");
	        // Enforce TLS 1.2 and TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	        serverSocket.setEnabledProtocols(new String[]{Constant.TLSv1_2});
	        serverSocket.setEnabledCipherSuites(new String[]{Constant.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256});
	        
            AtomicInteger clientCounter = new AtomicInteger(0);
	        while(true) {
	        	 try {
		        	 SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
		        	 int clientNumber = clientCounter.incrementAndGet();
		             new Thread(() -> {
	                     try {
	                         handleClient(clientSocket, clientNumber);
	                     } finally {
	                         try {
	                             clientSocket.close();
	                         } catch (IOException e) {
	                             log.error("Error closing client socket: " + e.getMessage());
	                         }
	                     }
	                 }).start();
	        	 } catch (SSLHandshakeException e) {
	        		 log.error("SSL handshake failed: " + e.getMessage());
                } catch (IOException e) {
                	log.error("Server socket error: " + e.getMessage());
                }
	        }
	}

	
	private static void handleClient(SSLSocket socket,int clientNumber) {
		log.info("New client " + clientNumber + " connected from: " + socket.getRemoteSocketAddress());
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	         PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
			
            SSLSession session = socket.getSession();
            log.info("Client " + clientNumber + " Protocol: " + session.getProtocol());
            log.info("Client " + clientNumber + " Cipher suite: " + session.getCipherSuite());

			String[] protocols= socket.getEnabledProtocols();
			String[] cipherS= socket.getEnabledCipherSuites();
		    out.println("Welcome to Server with port" +socket.getLocalPort()+", enabled protocols: "+ String.join(" ",protocols)+
		    			", enabled cipherSuites: "+ String.join(" ",cipherS)+",Type 'exit' to disconnect.");

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
