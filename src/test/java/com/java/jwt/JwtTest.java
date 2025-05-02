package com.java.jwt;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.utils.TestUtils;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;



public class JwtTest {
	
	private static final Logger log = LoggerFactory.getLogger(JwtTest.class);
	
	
	@BeforeAll
	public static void writeSharedKey() throws NoSuchAlgorithmException, NoSuchProviderException {
		final byte[] sharedSecret = Jwt.generateNewSecretKey(); // HmacSHA256
		TestUtils.writeData("JWT","jwt-shared.key",sharedSecret);
	}
		
	@Test
	public void jsonWebToken() throws Exception {
		// Generate Secret once and store in Secure, like environment variable or vault 
		final byte[] sharedSecret = Jwt.generateNewSecretKey();
//		String base64Key = Base64.getEncoder().encodeToString(sharedSecret);
//		log.info("Secret length: " + base64Key.length()); 
//		log.info(" Base64 Secret for only Signature validation test:" + base64Key);
		String jws= Jwt.createSignedJwt(sharedSecret);
		log.info("Signed JWT (JWS): " + jws);
		JWTClaimsSet claims = Jwt.validateSignedJwt(jws,sharedSecret);
		log.info("JWT Claims: " + claims.toJSONObject());
	}
	
	@Test
	public void jsonWebEncryption() throws Exception {
		final RSAKey rsaKey = new RSAKeyGenerator(2048)
	            .keyID("123").algorithm(JWEAlgorithm.RSA_OAEP_256).generate();
		String jwe= Jwt.createEncryptedJWT(rsaKey);
		log.info("Encrypted JWT (JWE): " + jwe);
		JWTClaimsSet decryptedClaims = Jwt.decryptJWE(jwe,rsaKey);
		log.info("Decrypted JWT Claims: " + decryptedClaims.toJSONObject());
	}
}
