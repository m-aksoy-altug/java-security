package com.java.server;


import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.EventListener;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.io.Connection;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.server.SslConnectionFactory;
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
	
	public static void jettyWebServer() {
		try {
			Server server = new Server();
			SslContextFactory.Server sslContextFactory = Utils.createSslContextFactory();
			sslContextFactory.setIncludeProtocols(Constant.TLSv1_3, Constant.TLSv1_2); 
			sslContextFactory.setIncludeCipherSuites(Constant.TLS_AES_256_GCM_SHA384,
											Constant.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 );
	        HttpConfiguration httpsConfig = new HttpConfiguration();
	        httpsConfig.addCustomizer(new SecureRequestCustomizer());

	        HttpConnectionFactory http = new HttpConnectionFactory();
	        ServerConnector sslConnector = new ServerConnector(server,
	                new SslConnectionFactory(sslContextFactory, http.getProtocol()),
	                new HttpConnectionFactory(httpsConfig));
	        sslConnector.setPort(Constant.P9444);
	        server.setConnectors(new Connector[]{sslConnector});
	       
	        server.setHandler(new Handler() {
			@Override
			public boolean handle(Request request, Response response, Callback callback) throws Exception {
				StringBuilder sb = new StringBuilder(); 
				sb.append("Raw Jetty 12 Handler!\n");
				try {
					 if (request.isSecure()) {
						    Connection connection = request.getConnectionMetaData().getConnection();
		                    EndPoint endPoint = connection.getEndPoint();
		                    sb.append("Client Address: ").append(endPoint.getRemoteSocketAddress()).append("\n");
						    if (connection instanceof SslConnection sslConnection) {
		                        SSLSession sslSession = sslConnection.getSSLEngine().getSession();
	                            sb.append("SSL Protocol: ").append(sslSession.getProtocol()).append("\n");
					            sb.append("SSL Cipher Suite: ").append(sslSession.getCipherSuite()).append("\n");
					          }
		                }
				 	    response.setStatus(200);
	                    response.getHeaders().add("Content-Type", "text/plain; charset=utf-8");
	                    ByteBuffer body = ByteBuffer.wrap(sb.toString().getBytes(StandardCharsets.UTF_8));
	                    response.write(true, body, callback); 
	                    return true;
	                } catch (Exception e) {
	                    e.printStackTrace();
	                    return false;  
	                }
			}
			@Override
			public void destroy() {
			}
			@Override
			public void stop() throws Exception {
			}
			@Override
			public void start() throws Exception {
			}
			@Override
			public boolean removeEventListener(EventListener listener) {
				return false;
			}
			@Override
			public boolean isStopping() {
				return false;
			}
			@Override
			public boolean isStopped() {
				return false;
			}
			@Override
			public boolean isStarting() {
				return false;
			}
			@Override
			public boolean isStarted() {
				return false;
			}
			@Override
			public boolean isRunning() {
				return false;
			}
			@Override
			public boolean isFailed() {
				return false;
			}
			@Override
			public boolean addEventListener(EventListener listener) {
				return false;
			}
			@Override
			public void setServer(Server server) {
			}
			@Override
			public Server getServer() {
				return null;
			}
		});
	        server.start();
	        log.info("Jetty server started on https://"+ Constant.IP+":" + Constant.P9444);
	        server.join();
     	} catch (IOException e) {
			log.error("Jetty Https server connection error: " + e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {

			e.printStackTrace();
		}
	}

}
