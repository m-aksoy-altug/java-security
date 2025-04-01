package com.java.rsa;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.utils.Utils;


/*  Rivest-Shamir-Adleman
 * - Asymmetric Cryptographic Algorithm
 * - Public Key: Encrypting data 
 * - Private Key: Decryting data
*/
public class RsaTest {
	private final static String RSA="RSA";
	private final static String BC="BC";
	
	private static final Logger log = LoggerFactory.getLogger(RsaTest.class);
	
	@BeforeAll
	public static void writePublicAndPrivateKeys() throws NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator generator=	KeyPairGenerator.getInstance(RSA);
		generator.initialize(2048); // 2048 bits = 256 bytes
		KeyPair pair= generator.generateKeyPair();
		PublicKey publicK= pair.getPublic();
		Utils.writeData("public.key",publicK.getEncoded());
		PrivateKey privateK=pair.getPrivate();
		Utils.writeData("private.key",privateK.getEncoded());
		KeyPairGenerator bouncycastle=KeyPairGenerator.getInstance(RSA,BC); // Standard RSA (PKCS#1 key format) in TLS 1.2/1.3
		bouncycastle.initialize(2048); // 2048 bits = 256 bytes
		KeyPair bouncyCastlePair= bouncycastle.generateKeyPair();
		PublicKey bouncyCastlePublicK= bouncyCastlePair.getPublic();
		Utils.writeData("bouncyCastlePublic.key",bouncyCastlePublicK.getEncoded());
		PrivateKey bouncyCastlePrivateK=bouncyCastlePair.getPrivate();
		Utils.writeData("bouncyCastlePrivate.key",bouncyCastlePrivateK.getEncoded());
	}
	
	
	@Test
	public void encrytAndDecryptCipherWithPublicAndPrivateKey() throws Exception {
		KeyFactory keyFactory= KeyFactory.getInstance(RSA); // default SunRsaSign
		byte[] publicKeyBytes= Utils.readData("public.key");
		X509EncodedKeySpec encodedKeySpec =new X509EncodedKeySpec(publicKeyBytes);
		PublicKey publicKey =keyFactory.generatePublic(encodedKeySpec);
		// Legacy Cipher: RSA/ECB/PKCS1Padding
		Cipher encryptCipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");// same as RSA
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		String message = "message secret first encrpt than decrpt";
		byte[] encryptedMessageBytes = encryptCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
		String encryptedMessage= Base64.getEncoder().encodeToString(encryptedMessageBytes);
		log.info("encryptedMessage: "+ encryptedMessage);
		
		byte[] privateKeyBytes= Utils.readData("private.key");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		PrivateKey privateK = keyFactory.generatePrivate(keySpec);
		Cipher decryptCipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");
		decryptCipher.init(Cipher.DECRYPT_MODE, privateK);
		byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
		String decryptedMessage= new String(decryptedMessageBytes,StandardCharsets.UTF_8);
		log.info("decryptedMessage: "+ decryptedMessage);
		assertEquals(message,decryptedMessage);
		
	}
		
	@Test
	public void exploringRSApublicAndPrivateKeys() throws Exception {
//		KeyPairGenerator generator=	KeyPairGenerator.getInstance(RSA);
//		generator.initialize(2048); // 2048 bits = 256 bytes
//		KeyPair pair= generator.generateKeyPair();
		KeyFactory keyFactory= KeyFactory.getInstance(RSA);
		byte[] publicKeyBytes= Utils.readData("public.key");
		X509EncodedKeySpec encodedKeySpec =new X509EncodedKeySpec(publicKeyBytes);
		PublicKey publicK =keyFactory.generatePublic(encodedKeySpec);
//		PublicKey publicK= pair.getPublic();
		log.info("publicK.getAlgorithm(): "+ publicK.getAlgorithm()); // RSA
		log.info("publicK.getFormat(): "+ publicK.getFormat());	// X.509
		String publicStr= Base64.getEncoder().encodeToString(publicK.getEncoded());
		log.info("publicStr: "+ publicStr);
		String hex = Hex.encodeHexString(publicK.getEncoded());
		log.info("publicHex: "+ hex);
		
		java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) publicK;
		// 2048 bits, derived from the product of two prime numbers p * q, both prime numbers are secret
		BigInteger modulusPuiblic = rsaPublicKey.getModulus();
		assertEquals(2048,modulusPuiblic.bitLength());
		// Public exponent, e = 65537 = 0x10001 
		BigInteger exponentPublic = rsaPublicKey.getPublicExponent(); // e
		assertEquals(new BigInteger("65537"),exponentPublic);
		
		// For MetaData of Public RSA, decoding x.509 structure, wraps PKCS#1 keys in an ASN.1 container
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
		// PKCS => Public Key Cryptography Standards
		// "1.1.1" : Specifies RSA Encryption (PKCS #1) Core RSA Standard 
		// "1.1.4" : RSA with MD5 // "1.1.5" :  RSA with SHA-1 // "1.1.11" :  RSA with SHA-256
		
		byte[] privateKeyBytes= Utils.readData("private.key");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		PrivateKey privateK = keyFactory.generatePrivate(keySpec);
		
//		PrivateKey privateK=pair.getPrivate();
		log.info("privateK.getAlgorithm(): "+ privateK.getAlgorithm()); // RSA
		log.info("privateK.getFormat(): "+ privateK.getFormat());		// PKCS#8
		
		java.security.interfaces.RSAPrivateKey rsaPrivateKey = 
				(java.security.interfaces.RSAPrivateKey) privateK;
	    
	    BigInteger modulusPrivate = rsaPrivateKey.getModulus(); // n
	    assertEquals(2048,modulusPrivate.bitLength());
	    BigInteger privateExponentPrivate = rsaPrivateKey.getPrivateExponent(); // d
	    
	    // For MetaData of Private RSA
	    PrivateKeyInfo rsaPrivateInfo = PrivateKeyInfo.getInstance(privateK.getEncoded());
	    RSAPrivateKey rsaPrivate = RSAPrivateKey.getInstance(rsaPrivateInfo.parsePrivateKey());
	    
	    BigInteger modulusPrivateD = rsaPrivate.getModulus();          // Public n = Secret p * Secret q
	    assertEquals(2048,modulusPrivateD.bitLength());
	    assertEquals(modulusPuiblic.toString(),modulusPrivateD.toString());
	    BigInteger privateExponent = rsaPrivate.getPrivateExponent(); // d
	    
	    log.info("HEX Modulus (n): " + modulusPrivateD.toString(16));  // toString(16) to Hex String
	    log.info("HEX Private Exponent (d): " + privateExponent.toString(16));
	    log.info("Modulus (n): " + modulusPrivateD);  
	    log.info("Private Exponent (d): " + privateExponent);
	    
	    if (rsaPrivate.getPublicExponent() != null) {
	        BigInteger publicExponent = rsaPrivate.getPublicExponent();  // e
	        assertEquals(new BigInteger("65537"),publicExponent);
	        BigInteger primeP = rsaPrivate.getPrime1();                 // p
	        BigInteger primeQ = rsaPrivate.getPrime2();                 // q
	        BigInteger exponentP = rsaPrivate.getExponent1();           // dP
	        BigInteger exponentQ = rsaPrivate.getExponent2();           // dQ
	        BigInteger crtCoefficient = rsaPrivate.getCoefficient();    // qInv
	        
	        log.info("Public Exponent (e): " + publicExponent);
	        log.info("Prime P (p): " + primeP);
	        log.info("Prime Q (q): " + primeQ);
	        log.info("Exponent P (dP): " + exponentP);
	        log.info("Exponent Q (dQ): " + exponentQ);
	        log.info("CRT Coefficient (qInv): " + crtCoefficient);
	        
	        // eulerTotientOfn = ϕ(n) = (p - 1) * (q - 1)
//	        BigInteger eulerTotientOfn=rsaPrivate.getPrime1().subtract(BigInteger.ONE)
//    				.multiply(rsaPrivate.getPrime2().subtract(BigInteger.ONE));  
//	        if(publicExponent.compareTo(BigInteger.ONE) < 0
//	        		|| publicExponent.compareTo(eulerTotientOfn)> 0) {
//	        	throw new RuntimeException("e must be greater than 1 and smaller than (p - 1) * (q - 1)");
//	        }
	        //d = e⁻¹ mod ϕ(n)  OR  (e * d) mod ϕ(n) = 1

	        // Bouncy Castle, OpenSSL use λ(n)= lcm(p-1,q-1)
	        BigInteger lambdaN= primeP.subtract(BigInteger.ONE).
	        		multiply(primeQ.subtract(BigInteger.ONE)).
	        		divide(primeP.subtract(BigInteger.ONE).
	        				gcd(primeQ.subtract(BigInteger.ONE)));
	        if (publicExponent.compareTo(BigInteger.ONE) < 0 || 
	        		publicExponent.compareTo(lambdaN) > 0) {
	        	throw new RuntimeException("e must be > 1 and < λ(n)");
	        }
	        if(!publicExponent.modInverse(lambdaN).equals(privateExponent)) {
	        	throw new RuntimeException("d = e⁻¹ mod ϕ(n)");
	        }
	    }
	}
	
	
}
