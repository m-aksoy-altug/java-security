package com.java.server;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.List;

import org.eclipse.jetty.http3.server.HTTP3ServerConnectionFactory;
import org.eclipse.jetty.quic.server.QuicServerConnector;
import org.eclipse.jetty.quic.server.ServerQuicConfiguration;
import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.utils.Constant;
import com.java.utils.Utils;

/* HTTP/3 runs over QUIC, UDP based protocol
 * - Multiplexing : QUIC handles streams independently, avoiding “head-of-line blocking” issues seen in TCP-based HTTP/2.
 * - QUIC’s streamlined handshake (combining transport and cryptographic setup) enables faster connection establishment, often achieving “0-RTT” (zero round-trip time) for subsequent connections.
*/
public class TlsOverUdpWebServer {

	private static final Logger log = LoggerFactory.getLogger(TlsOverUdpWebServer.class);

	/*
	 * HTTP/3 over QUIC (UDP) - sudo ufw allow 7443/udp
	 */
	public static void jettyWebServer() {
		try {
			System.setProperty("org.eclipse.jetty.LEVEL", "DEBUG"); 
			Server server = new Server();
			SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
			sslContextFactory.setKeyStorePath(Paths.get(Constant.KEYSTORE).toAbsolutePath().toString());
			String password = Utils.getKeyStorePasswordFromSystemProperty();
			sslContextFactory.setKeyStorePassword(password);
			sslContextFactory.setKeyStoreType(Constant.PKCS12);
			sslContextFactory.setIncludeProtocols(Constant.TLSv1_3);
			sslContextFactory.setIncludeCipherSuites(Constant.TLS_AES_256_GCM_SHA384,
					Constant.TLS_CHACHA20_POLY1305_SHA256);
			sslContextFactory.setTrustAll(true); // Temporarily for testing
			sslContextFactory.setValidateCerts(false);
			sslContextFactory.setEndpointIdentificationAlgorithm(null); // Disable hostname verification

			HttpConfiguration httpConfig = new HttpConfiguration();
			httpConfig.addCustomizer(new SecureRequestCustomizer());
			httpConfig.setIdleTimeout(900000);

			Path pemDir = Paths.get("jetty-quic-server-pem");
			Files.createDirectories(pemDir);

			ServerQuicConfiguration quicConfig = new ServerQuicConfiguration(sslContextFactory, pemDir);
			quicConfig.setProtocols(List.of(Constant.TLSv1_3));
			quicConfig.setMaxBidirectionalRemoteStreams(100);
			quicConfig.setMaxUnidirectionalRemoteStreams(100);

			HTTP3ServerConnectionFactory http3Factory = new HTTP3ServerConnectionFactory(quicConfig, httpConfig);
			
			ServerConnector http3Connector = new ServerConnector(server, null, null, null, -1, -1,
					new ConnectionFactory[] { http3Factory });
			
			http3Connector.setPort(Constant.P7443);
			server.addConnector(http3Connector);
			server.setHandler(new SimpleHttp3Handler());
			server.start();
			log.info("Jetty HTTP/3 server started on https://" + Constant.IP + ":" + Constant.P7443);
			server.setDumpAfterStart(true); // debugging
			server.join();
		} catch (Exception e) {
			log.error("Jetty HTTP/3 server connection error: " + e.getMessage());
			e.printStackTrace();
		}
	}

}
