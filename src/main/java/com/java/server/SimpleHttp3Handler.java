package com.java.server;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.EventListener;

import javax.net.ssl.SSLSession;

import org.eclipse.jetty.io.Connection;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.Callback;

public class SimpleHttp3Handler implements Handler {

	@Override
	public void start() throws Exception {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void stop() throws Exception {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isRunning() {
		return true;
	}

	@Override
	public boolean isStarted() {
		return true;
	}

	@Override
	public boolean isStarting() {
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
	public boolean isFailed() {
		return false;
	}

	@Override
	public boolean addEventListener(EventListener listener) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean removeEventListener(EventListener listener) {
		return false;
	}

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean handle(Request request, Response response, Callback callback) throws Exception {
			StringBuilder sb = new StringBuilder(); 
			sb.append("UDP-Http/3- Raw Jetty 12 Handler!\n");
			try {
				 if (request.isSecure()) {	
					    Connection connection = request.getConnectionMetaData().getConnection();
	                    EndPoint endPoint = connection.getEndPoint();
	                    sb.append("Protocol: ").append(request.getConnectionMetaData().getProtocol()).append("\n");
	                    sb.append("Client Address: ").append(endPoint.getRemoteSocketAddress()).append("\n");
	                    sb.append("Connection: ").append(connection.getClass().getName()).append("\n");
					    if (connection instanceof SslConnection sslConnection) {
	                        SSLSession sslSession = sslConnection.getSSLEngine().getSession();
                         sb.append("SSL Protocol: ").append(sslSession.getProtocol()).append("\n");
				            sb.append("SSL Cipher Suite: ").append(sslSession.getCipherSuite()).append("\n");
				          }
	                }
			 	    response.setStatus(200);
                 response.getHeaders().add("Content-Type", "text/plain; charset=utf-8");
                 response.getHeaders().add("Alt-Svc", "h3=\":7443\"; ma=3600"); 
                 ByteBuffer body = ByteBuffer.wrap(sb.toString().getBytes(StandardCharsets.UTF_8));
                 response.write(true, body, callback); 
                 return true;
             } catch (Exception e) {
                 e.printStackTrace();
                 return false;  
             }
	}

	@Override
	public Server getServer() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setServer(Server server) {
		// TODO Auto-generated method stub
		
	}

}
