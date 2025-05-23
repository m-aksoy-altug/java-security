package com.java.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.eclipse.jetty.util.ssl.SslContextFactory;

public class Utils {

	public static SSLServerSocket createSSLServerSocket(String tlsVersion, int port) {
		SSLServerSocket serverSocket = null;
		try {
			String password = getKeyStorePasswordFromSystemProperty();
			SSLContext sslContext = SSLContext.getInstance(tlsVersion);
			KeyStore ks = KeyStore.getInstance(Constant.PKCS12);
			ks.load(new FileInputStream(Constant.KEYSTORE), password.toCharArray());
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(Constant.PKIX);
			kmf.init(ks, password.toCharArray());
			sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
			SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
			serverSocket = (SSLServerSocket) factory.createServerSocket(port, 0,
					InetAddress.getByName(Constant.ZERO_DOT_ZERO_DOT_ZERO_DOT_ZERO_DOT));
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
		return serverSocket;
	}

	public static SSLSocket createSSLSocket(String tlsVersion, String host, int port) {
		SSLSocket socket = null;
		try {
			String password = getKeyStorePasswordFromSystemProperty();
			KeyStore trustStore = KeyStore.getInstance(Constant.PKCS12);
			trustStore.load(new FileInputStream(Constant.KEYSTORE), password.toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(Constant.PKIX);
			tmf.init(trustStore);

			SSLContext sslContext = SSLContext.getInstance(tlsVersion);
			sslContext.init(null, tmf.getTrustManagers(), null);

			SSLSocketFactory factory = sslContext.getSocketFactory();
			socket = (SSLSocket) factory.createSocket(host, port);
			
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
		return socket;
	}
	
	
	public static SSLContext createSSLContext() {
		SSLContext sslContext =null;
		try {
		String password = getKeyStorePasswordFromSystemProperty();
		KeyStore trustStore = KeyStore.getInstance(Constant.PKCS12);
		trustStore.load(new FileInputStream(Constant.KEYSTORE), password.toCharArray());

		TrustManagerFactory tmf = TrustManagerFactory.getInstance(Constant.PKIX);
		tmf.init(trustStore);

		KeyManagerFactory kmf = KeyManagerFactory.getInstance(Constant.PKIX);
        kmf.init(trustStore, password.toCharArray());
        
	    sslContext = SSLContext.getInstance(Constant.TLS);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        
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
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}
	       return sslContext;
	}
	
	
	public static SslContextFactory.Server createSslContextFactory() {
		SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
		String password = getKeyStorePasswordFromSystemProperty();
		sslContextFactory.setKeyStorePath(Paths.get(Constant.KEYSTORE).toAbsolutePath().toString());
        sslContextFactory.setKeyStorePassword(password);
        sslContextFactory.setKeyStoreType(Constant.PKCS12);
        // Using the same Keystore as TrustStore, in pro, seperate trust store with CA Certificates 
        sslContextFactory.setTrustStorePath(Paths.get(Constant.KEYSTORE).toAbsolutePath().toString());
        sslContextFactory.setTrustStorePassword(password);
        sslContextFactory.setTrustAll(false); 
        sslContextFactory.setNeedClientAuth(false); 
        // sslContextFactory.setValidatePeerCerts(true); 
        return sslContextFactory;
	}
	
	public static String getKeyStorePasswordFromSystemProperty() {
		String password = System.getProperty("keystore.password");
		if (password == null) {
			throw new IllegalStateException("Pass keystore.password variable on runtime");
		}
		return password;
	}
}
