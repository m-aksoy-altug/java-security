package com.java.utils;

public class Constant {
	public static final int P8443 = 8443; // SSL/TLS-secured TCP socket , SSLSocket for only TLSv1_3
	public static final int P8444 = 8444; // SSL/TLS-secured TCP socket , SSLSocket for only TLSv1_2
	public static final int P9443 = 9443; // Using for java net HTTPS server for both TLSv1_3 and TLSv1_2
	public static final int P9444 = 9444; // Using for Jetty HTTPS server for both TLSv1_3 and TLSv1_2
	public static final String PKIX = "PKIX";  // Public Key Infrastructure
	public static final String KEYSTORE = "server.p12";
	public static final String TLSv1_3 = "TLSv1.3";
	public static final String TLSv1_2 = "TLSv1.2";
	public static final String TLS= "TLS";
	public static final String PKCS12 = "PKCS12";
	public static final String TLS_AES_256_GCM_SHA384 = "TLS_AES_256_GCM_SHA384";
	public static final String TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
	public static final String ZERO_DOT_ZERO_DOT_ZERO_DOT_ZERO_DOT ="0.0.0.0";
	public static final String IP = "192.168.1.113";
}
