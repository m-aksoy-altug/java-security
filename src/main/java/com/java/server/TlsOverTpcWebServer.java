package com.java.server;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
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
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.utils.Constant;
import com.java.utils.Utils;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/* - Protocol: HTTPS (HTTP Over TLS (Transport Layer Security)) over TCP (Transmission Control Protocol),  (OSI Layer 7 - Application Layer)
 * - Connection Type: HTTP-aware TLS connection (SslConnectionFactory + HttpConnection)
 * - Data type: Structured HTTP messages (headers + body)
 * - Message Framing: Automatic (HTTP/1.1 chunking or HTTP/2 frames)  
 * - Use case: Web apps, REST APIs, websites
*/
public class TlsOverTpcWebServer {
	private static final Logger log = LoggerFactory.getLogger(TlsOverTpcWebServer.class);

	public static void javaNetWebServer() {
		try {
		SSLContext sslContext = Utils.createSSLContext();
		// Configure supported protocols and cipher suites
		SSLParameters params = new SSLParameters();
		params.setProtocols(new String[] { Constant.TLSv1_3, Constant.TLSv1_2 }); 
		params.setCipherSuites(new String[] {
				Constant.TLS_AES_256_GCM_SHA384,
				Constant.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 });
		params.setNeedClientAuth(false); 

		HttpsServer server = HttpsServer.create(
			            new InetSocketAddress(InetAddress.getByName(Constant.IP), Constant.P9443), 0);
		
		server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
			public void configure(HttpsParameters httpsParams) {
				httpsParams.setSSLParameters(params);
			}
		});

		server.createContext("/", exchange -> {
			HttpsExchange httpsExchange = (HttpsExchange) exchange;
            SSLSession sslSession = httpsExchange.getSSLSession();
            
            String response = "Serving from " + Constant.IP + "\n" +
                    "Protocol: " + sslSession.getProtocol() + "\n" +
                    "Cipher: " + sslSession.getCipherSuite();
            
			exchange.sendResponseHeaders(200, response.length());
			exchange.getResponseBody().write(response.getBytes());
			exchange.close();
		});

		server.start();
		log.info("HTTPS Server started on https://"+ Constant.IP+":" + Constant.P9443);
		} catch (IOException e) {
			log.error("Http server connection error: " + e.getMessage());
			e.printStackTrace();
		}
	}

}
