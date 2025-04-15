package com.java.client;

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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class TlsOverTpcClient {
	
	private static final Logger log = LoggerFactory.getLogger(TlsOverTpcClient.class);
	
	private static final String IP = "192.168.1.113";
	private static final String PKIX = "PKIX";
	private static final String KEYSTORE = "server.p12";
	private static final String KEYSTORE_PASSWORD = "password";
	private static final String TLSv1_3 = "TLSv1.3";
	private static final int P8443 = 8443;
	private static final String TLSv1_2 = "TLSv1.2";
	private static final int P8444 = 8444;
	private static final String PKCS12 = "PKCS12";

	/*
	 * - TLS version: TLSv1.3 - Cipher: TLS_AES_256_GCM_SHA384
	 */
	public static void sslClientSocketTLS1Point3OverTCP() {
		try {

			KeyStore trustStore = KeyStore.getInstance(PKCS12);
			trustStore.load(new FileInputStream(KEYSTORE), KEYSTORE_PASSWORD.toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(PKIX);
			tmf.init(trustStore);

			SSLContext sslContext = SSLContext.getInstance(TLSv1_3);
			sslContext.init(null, tmf.getTrustManagers(), null); 
			
			SSLSocketFactory factory = sslContext.getSocketFactory();
			SSLSocket socket = (SSLSocket) factory.createSocket(IP, P8443);
			
			socket.startHandshake();
			log.info("Connected to server at " + IP + ":" + P8443);
			SSLSession session = socket.getSession();
			printAllSSLSessionDetails(session);
			
			try {
				 client(socket);
	         } finally {
	             try {
	            	 socket.close();
	             } catch (IOException e) {
	                 log.error("Error closing client socket: " + e.getMessage());
	             }
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
			} catch (KeyManagementException e) {	
				e.printStackTrace();
			}

	}

	private static void client(SSLSocket socket) {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in))) {

			log.info("Server says: " + in.readLine());

			String userInput;
			while ((userInput = consoleIn.readLine()) != null) {
				out.println(userInput);
				log.info("Server reply: " + in.readLine());
				if ("exit".equalsIgnoreCase(userInput))
					break;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void printAllSSLSessionDetails(SSLSession session) throws SSLPeerUnverifiedException {
		 log.info("Peer Host: " + session.getPeerHost());
         log.info("Peer Port: " + session.getPeerPort());
         log.info("Protocol: " + session.getProtocol());
         log.info("Cipher Suite: " + session.getCipherSuite());
         log.info("Session ID: " + bytesToHex(session.getId()));
         log.info("Creation Time: " + session.getCreationTime());
         log.info("Last Accessed Time: " + session.getLastAccessedTime());

         log.info("Peer Certificates:");
         Certificate[] peerCerts = session.getPeerCertificates();
         for (Certificate cert : peerCerts) {
             log.info(" - Type: " + cert.getType());
             if (cert instanceof X509Certificate) {
                 X509Certificate x509 = (X509Certificate) cert;
                 log.info("   Subject: " + x509.getSubjectDN());
                 log.info("   Issuer: " + x509.getIssuerDN());
                 log.info("   Serial Number: " + x509.getSerialNumber());
                 log.info("   Valid From: " + x509.getNotBefore());
                 log.info("   Valid Until: " + x509.getNotAfter());
                 log.info("   Signature Algorithm: " + x509.getSigAlgName());
             }
         }
	}

	private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
