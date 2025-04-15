package com.java;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.client.TlsOverTpcClient;
import com.java.server.TlsOverTpcServer;

public class JavaSecurity {
	// exec:java Dkeystore.password="password" -Dexec.mainClass="com.java.JavaSecurity"
	private static final Logger log = LoggerFactory.getLogger(JavaSecurity.class);
	
		
	public static void main(String[] args) {
		
		ExecutorService executors = Executors.newFixedThreadPool(3);
		// wireshark: ip.addr == 192.168.1.113 && tcp.port==8443
		// openssl s_client -connect 192.168.1.113:8443 -tls1_3
		executors.submit(()->TlsOverTpcServer.sslServerSocketTLS1Point3OverTCP());
		// openssl s_client -connect 192.168.1.113:8444 -tls1_2
		executors.submit(()->TlsOverTpcServer.sslServerSocketTLS1Point2OverTCP());
		executors.submit(()-> { threadSleep(2_000); TlsOverTpcClient.sslClientSocketTLS1Point3OverTCP(); });
		
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
	        log.info("Shutting down servers...");
	        executors.shutdownNow();
	        try {
	            if (!executors.awaitTermination(5, TimeUnit.SECONDS)) {
	                log.debug("Forcing shutdown after 5 secs...");
	            }
	        } catch (InterruptedException e) {
	            Thread.currentThread().interrupt();
	        }
	    }));
		
		
	    try {
	        while (!executors.isTerminated()) {
	        	executors.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
	        }
	    } catch (InterruptedException e) {
	        log.info("Main thread interrupted, shutting down");
	        Thread.currentThread().interrupt();
	    }
	    
	}
	
	private static void threadSleep(long milliSec) {
		try {
			Thread.sleep(milliSec);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	
}