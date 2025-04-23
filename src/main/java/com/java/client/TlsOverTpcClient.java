package com.java.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;


import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.utils.Constant;
import com.java.utils.Utils;

/* - HTTP1.1 | HTTP2
*/
public class TlsOverTpcClient {
	
	private static final Logger log = LoggerFactory.getLogger(TlsOverTpcClient.class);
	/*
	 * - TLS version: TLSv1.3 - Cipher: TLS_AES_256_GCM_SHA384
	 */
	public static void sslClientSocketTLS1Point3OverTCP() {
		try {
			SSLSocket socket =Utils.
					createSSLSocket(Constant.TLSv1_3, Constant.IP, Constant.P8443);
			socket.startHandshake();
			log.info("Connected to server at " + Constant.IP + ":" + Constant.P8443);
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
			} catch (IOException e) {
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
