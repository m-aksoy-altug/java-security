package com.java.server;

import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http.MetaData;
import org.eclipse.jetty.http3.api.Session;
import org.eclipse.jetty.http3.api.Stream;
import org.eclipse.jetty.http3.frames.DataFrame;
import org.eclipse.jetty.http3.frames.HeadersFrame;

import org.eclipse.jetty.http3.server.RawHTTP3ServerConnectionFactory;
import org.eclipse.jetty.quic.server.QuicServerConnector;
import org.eclipse.jetty.quic.server.ServerQuicConfiguration;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.java.utils.Constant;
import com.java.utils.Utils;

/* HTTP/3 runs over QUIC, UDP based protocol
 * - Multiplexing : QUIC handles streams independently, avoiding “head-of-line blocking” issues seen in TCP-based HTTP/2.
 * - QUIC’s streamlined handshake (combining transport and cryptographic setup) enables faster connection establishment, often achieving “0-RTT” (zero round-trip time) for subsequent connections.
*/
public class TlsOverUdpWebServer {

	private static final Logger log = LoggerFactory.getLogger(TlsOverUdpWebServer.class);
	private static final ObjectMapper mapper = new ObjectMapper();
	
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
			// The listener for session events.
			Session.Server.Listener sessionListener = new Session.Server.Listener(){
			    @Override
			    public void onAccept(Session session){
			        SocketAddress remoteAddress = session.getRemoteSocketAddress();
			        log.info(" HTTP3 Connection from "+ remoteAddress);
			    }
			    @Override
			    public Stream.Server.Listener onRequest(Stream.Server stream, HeadersFrame frame){
			        MetaData.Request request = (MetaData.Request)frame.getMetaData();
			        HttpVersion version = request.getHttpVersion();
			        log.info("Request Version: " + version);
			        if (frame.isLast()){
			            respond(stream, request);
			            return null;
			        }else{
			            stream.demand();
			            return new Stream.Server.Listener(){
			                @Override
			                public void onDataAvailable(Stream.Server stream){
			                    Stream.Data data = stream.readData();
			                    if (data == null){
			                        stream.demand();
			                    }else{
			                        data.release();
			                        if (data.isLast())
			                            respond(stream, request);
			                        else
			                            stream.demand();
			                    }
			                }
			            };
			        }
			    }
			};
			
			Path pemDir = Paths.get("jetty-quic-server-pem");
			Files.createDirectories(pemDir);
			ServerQuicConfiguration quicConfiguration = new ServerQuicConfiguration(sslContextFactory, pemDir);
			quicConfiguration.setMaxBidirectionalRemoteStreams(1024);

			RawHTTP3ServerConnectionFactory http3 = new RawHTTP3ServerConnectionFactory(quicConfiguration, sessionListener);
			http3.getHTTP3Configuration().setStreamIdleTimeout(15000);

			QuicServerConnector connector = new QuicServerConnector(server, quicConfiguration, http3);
			connector.setPort(Constant.P7443);
			server.addConnector(connector);

			server.start();
			log.info("Jetty HTTP/3 server started on https://" + Constant.IP + ":" + Constant.P7443);
			server.setDumpAfterStart(true); // debugging
			server.join();
		} catch (Exception e) {
			log.error("Jetty HTTP/3 server connection error: " + e.getMessage());
			e.printStackTrace();
		}
	}
	
	
    private static void respond(Stream.Server stream, MetaData.Request request){
       HttpFields.Mutable fields = HttpFields.build();
    	fields.put(HttpHeader.CONTENT_TYPE, "application/json");
    	MetaData.Response response = new MetaData.Response(HttpStatus.OK_200, null, HttpVersion.HTTP_3, fields);
        if (HttpMethod.GET.is(request.getMethod())){
            ByteBuffer resourceBytes = getResourceBytes(request);
            stream.respond(new HeadersFrame(response, false))
            	.thenAccept(s -> s.data(new DataFrame(resourceBytes, true)));
        }
        else{
            stream.respond(new HeadersFrame(response, true));
        }
    }
    
	private static ByteBuffer getResourceBytes(MetaData.Request request) {
	    String uri = request.getHttpURI().toString();
	    Map<String, Object> jsonMap = new HashMap<>();
	    log.info("Handling GET request for URI: "+ uri);
	    switch (uri) {
	        case "/error":
	        	jsonMap.put("error", "Not Found");
	        	jsonMap.put("status", 404);
	             break;
	        default:
	        	jsonMap.put("message", "Welcome to Jetty HTTP/3");
	        	jsonMap.put("status", 200);
	            break;
	    }
	    try {
	        byte[] jsonBytes = mapper.writeValueAsBytes(jsonMap);
	        return ByteBuffer.wrap(jsonBytes);
	    } catch (Exception e) {
	        throw new RuntimeException("JSON serialization error", e);
	    }
	}

}
