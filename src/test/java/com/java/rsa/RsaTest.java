package com.java.rsa;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/*  Rivest-Shamir-Adleman
 * - Asymmetric Cryptographic Algorithm
 * - Public Key: Encrypting data 
 * - Private Key: Decryting data
*/
public class RsaTest {
	
	private static final Logger log = LoggerFactory.getLogger(RsaTest.class);
	
	void writeData(String fileName, byte[] writeBytes) {
		Path filePath= Paths.get("RSA",fileName);
		try (FileOutputStream fos = new FileOutputStream(filePath.toAbsolutePath().toString())) {
		    fos.write(writeBytes);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	@Test
	public void exploringRSApublicKey() throws Exception {
		KeyPairGenerator generator=	KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048); // 2048 bits = 256 bytes
		KeyPair pair= generator.generateKeyPair();
		PublicKey publicK= pair.getPublic();
		log.info("publicK.getAlgorithm(): "+ publicK.getAlgorithm());
		log.info("publicK.getFormat(): "+ publicK.getFormat());
		writeData("public.key",publicK.getEncoded());
		String publicStr= Base64.getEncoder().encodeToString(publicK.getEncoded());
		log.info("publicStr: "+ publicStr);
		String hex = Hex.encodeHexString(publicK.getEncoded());
		log.info("publicHex: "+ hex);
		
		java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) publicK;
		// 2048 bits, derived from the product of two prime numbers p * q
		BigInteger modulus = rsaPublicKey.getModulus();
		assertEquals(2048,modulus.bitLength());
		// Public exponent, e = 65537 = 0x10001 
		BigInteger exponent = rsaPublicKey.getPublicExponent(); // e
		assertEquals(new BigInteger("65537"),exponent);
		
		// For MetaData of Public RSA, decoding x.509 structure
		SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicK.getEncoded());
		RSAPublicKey rsaStruct = RSAPublicKey.getInstance(keyInfo.parsePublicKey());
		
		BigInteger modulusX509 = rsaStruct.getModulus();
		assertEquals(2048,modulusX509.bitLength());
		BigInteger exponentX509 = rsaStruct.getPublicExponent();  
		assertEquals("65537",exponentX509.toString());
		String algorithmOID = keyInfo.getAlgorithm().getAlgorithm().getId(); // OID
		log.info("Object Identifier of RSA: "+ algorithmOID);
		assertEquals("1.2.840.113549.1.1.1",algorithmOID);
		// "1.2.840.113549" : RSA’s root OID (assigned to RSA Security LLC).
		// "1.1.1" : Specifies RSA Encryption (PKCS #1)
		// "1.1.4" : RSA with MD5 // "1.1.5" :  RSA with SHA-1 // "1.1.11" :  RSA with SHA-256
		
		PrivateKey privateK=pair.getPrivate();
		// 
		 
	}
	
	
}
