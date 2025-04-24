package com.java.client;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http.MetaData;
import org.eclipse.jetty.http3.api.Session;
import org.eclipse.jetty.http3.api.Stream;

import org.eclipse.jetty.http3.frames.HeadersFrame;
import org.eclipse.jetty.quic.client.ClientQuicConfiguration;
import org.eclipse.jetty.http3.client.HTTP3Client;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.utils.Constant;

/* - HTTP3
*/
public class TlsOverUdpClient {

	private static final Logger log = LoggerFactory.getLogger(TlsOverUdpClient.class);
	/* 
	 * - HTTP/3+QUIC support is experimental and not suited for production use.
	 */

	public static void webClientTLS1Point3OverUDP() {
		try {
			System.setProperty("javax.net.debug", "ssl,handshake,record");
			SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
			// trust all for only testing, regardless of whether they are valid, self-signed, expired, or untrusted by a known Certificate Authority.
			sslContextFactory.setTrustAll(true); 
			sslContextFactory.setEndpointIdentificationAlgorithm(null); // skip domain validation for only testing!!
			Path pemDir = Paths.get("jetty-quic-client-pem");
			Files.createDirectories(pemDir);

			ClientQuicConfiguration quicConfig = new ClientQuicConfiguration(sslContextFactory, pemDir);

			HTTP3Client client = new HTTP3Client(quicConfig);
			client.start();

			try {
				client(client);
			} finally {
				try {
					client.close();
				} catch (Exception e) {
					log.error("Error closing client socket: " + e.getMessage());
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void client(HTTP3Client client) {
		try {
			SocketAddress address = new InetSocketAddress(Constant.IP, Constant.P7443);
			CompletableFuture<Session.Client> sessionFuture = client.
					connect(address, new Session.Client.Listener() {});
			Session.Client session = sessionFuture.get();
		
			HttpFields fields = HttpFields.build().put(HttpHeader.USER_AGENT, "Jetty HTTP3Client");

			HttpURI uri = HttpURI.from("https://" + Constant.IP + ":" + Constant.P7443 + "/");
			MetaData.Request metaData = new MetaData.Request("GET", uri, HttpVersion.HTTP_3, fields);
			HeadersFrame headersFrame = new HeadersFrame(metaData, true);

			session.newRequest(headersFrame, new Stream.Client.Listener() {

				@Override
				public void onDataAvailable(Stream.Client stream) {
					Stream.Data data = stream.readData();
					if (data == null) {
						stream.demand();
					} else {
						ByteBuffer buffer = data.getByteBuffer();
						byte[] bytes = new byte[buffer.remaining()];
						buffer.get(bytes);
						log.info("Received data: " + new String(bytes));
						data.release();
						if (!data.isLast()) {
							stream.demand();
						}
					}
				}

			});
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			log.error("InterruptedException: " + e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			log.error("Exception: " + e.getMessage());
			e.printStackTrace();
		} finally {
			try {
				log.info("Client disconnected");
				client.close();
			} catch (Exception e) {
				log.error("Error closing socket: " + e.getMessage());
			}
		}
	}

}
