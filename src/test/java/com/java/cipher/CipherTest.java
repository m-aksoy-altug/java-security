package com.java.cipher;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class CipherTest {
	
	private static final Logger log = LoggerFactory.getLogger(CipherTest.class);
	
	@Test
	public void allpossibleChipherAlgorithms() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Provider[] providers = Security.getProviders();
		for (Provider provider : providers) {
			log.info("Provider: " + provider.getName());
		    for (Provider.Service service : provider.getServices()) {
		        if (service.getType().equals("Cipher") && service.getAlgorithm().contains("RSA")) {
		            log.info("  " + service.getAlgorithm());
		        }
		    }
		}
	}
	
	@Test
	public void allpossibleRSAAlgorithms() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Provider[] providers = Security.getProviders();
		for (Provider provider : providers) {
			log.info("RSA Provider: " + provider.getName());
		    for (Provider.Service service : provider.getServices()) {
		        if (service.getAlgorithm().contains("RSA")) {
		            log.info("  " + service.getAlgorithm());
		        }
		    }
		}
	}
}
