package com.java.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;


import java.io.File;
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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.pojo.DummyClass;
import com.java.utils.Utils;


/*	AES-GCM : Advance Encryption Standard - Galois/Counter Mode : symmetric encryption
* - TLS (HTTPS) – Modern web security (TLS 1.2 & 1.3).
* - Encrypting Files / Databases – Secure storage with integrity checks.
* - VPNs & Secure Messaging – Fast and authenticated encryption.
* - IoT & Embedded Systems – Efficient for devices with limited resources.
* Confidentiality – Encrypts data using AES.
* 
*/
public class AdvanceEncryptionStandardTest {
	
	private static final Logger log = LoggerFactory.getLogger(AdvanceEncryptionStandardTest.class);
	private final static String RSA="RSA";
	private final static String AES="AES";
	private final static String BC="BC";
	
	/* Generate a random AES-256 key - only for testing
	*/
	@BeforeAll
	public static void writeSecretKeyWithKeyGenerator() throws NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator aesBC=KeyGenerator.getInstance(AES, BC); 
		aesBC.init(256); //256 bits
		SecretKey secretKey= aesBC.generateKey();
		Utils.writeData("aesSecretKey.key",secretKey.getEncoded());
	}
	
	/*
	 * - Use the SecretKeyFactory class with the PBKDF2WithHmacSHA256 algorithm for generating a key from a given password.
	*/
	@BeforeAll
	public static void writeSecretKeyFromPassword() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		String password="DummyPassWord12^4#2@()";
		String salt = "12345678";
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		// Generating the AES key from a given password with 65,536 iterations and a key length of 256 bits
	    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
		    SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
		        .getEncoded(), AES);
		Utils.writeData("aesSecretKeyFromPassword.key",secret.getEncoded());
	}

	/*  - RSA + AES-GCM  (Hybrid Approach)
	 * Secure Key Exchange: When you need to securely share an AES key between two parties (e.g., client-server, device-cloud).
	 * Asymmetric Requirements: When only one party has the private key (e.g., server decrypts data sent by clients).
	 * TLS/HTTPS-like Scenarios: Modern web encryption uses hybrid encryption (RSA/ECDH for key exchange + AES-GCM for data).
	*/
	@Test
	public void ServerDecrytWithAES() throws Exception {
		String message = "Encryption: Step 1: Generate a random AES-256 key, Step 2: Encrypt the AES key with RSA Step 3: Encrypt data with AES-GCM Combine IV + encrypted AES key + encrypted data";
		byte[] 	encryptedMessage= clientEncrytWithAES(message);
		KeyFactory keyFactory= KeyFactory.getInstance(RSA);
		byte[] privateKeyBytes= Utils.readData("private.key");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		PrivateKey rsaPrivateKey = keyFactory.generatePrivate(keySpec);
		
		// Extract IV (first 12 bytes)
	    byte[] iv = new byte[12];
	    System.arraycopy(encryptedMessage, 0, iv, 0, iv.length);
	
	    // Extract encrypted AES key (next 256 bytes for RSA-2048)
	    int rsaKeySize = 256; // 2048-bit RSA produces 256-byte ciphertext
	    byte[] encryptedAesKey = new byte[rsaKeySize];
	    System.arraycopy(encryptedMessage, iv.length, encryptedAesKey, 0, rsaKeySize);
	
	    // Step 1: Decrypt the AES key with RSA
	    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
	    byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
	    SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
	
	    // Step 2: Decrypt data with AES-GCM
	    int encryptedDataPos = iv.length + encryptedAesKey.length;
	    byte[] encryptedData = new byte[encryptedMessage.length - encryptedDataPos];
	    System.arraycopy(encryptedMessage, encryptedDataPos, encryptedData, 0, encryptedData.length);
	
	    Cipher aesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
	    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
	    aesGcmCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
	    byte[] decrypted = aesGcmCipher.doFinal(encryptedData);
	    log.info("decrypted: "+new String(decrypted));
	    assertEquals( message, new String(decrypted));
   }
	
	/*  - RSA + AES-GCM  (Hybrid Approach)
	*/
	@Test
	public byte[] clientEncrytWithAES(String message) throws Exception {
		
		KeyFactory keyFactory= KeyFactory.getInstance(RSA); // default SunRsaSign
		byte[] publicKeyBytes= Utils.readData("public.key");
		X509EncodedKeySpec encodedKeySpec =new X509EncodedKeySpec(publicKeyBytes);
		PublicKey rsaPublicKey =keyFactory.generatePublic(encodedKeySpec);
		
		byte[] aesSecretKeyBytes= Utils.readData("aesSecretKey.key");
		SecretKey aesSecretKey= new SecretKeySpec(aesSecretKeyBytes , AES);
		
		 //  Encrypt the AES key with RSA
	    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // same as RSA, default
	    rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
	    byte[] encryptedAesKey = rsaCipher.doFinal(aesSecretKey.getEncoded());
	    
	    // Encrypt data with AES-GCM,  Initialization Vector (IV) 
	    byte[] iv = new byte[12]; // 12 bytes= 12*8= 96-bit IV (recommended for GCM)
	    SecureRandom random = new SecureRandom();
	    random.nextBytes(iv);
	    assertEquals(12,iv.length);
	    
	    Cipher aesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
	    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);   // 128-bit authentication tag
	    aesGcmCipher.init(Cipher.ENCRYPT_MODE, aesSecretKey, gcmSpec);
	    byte[] encryptedData = aesGcmCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
	    
	 // Combine IV + encrypted AES key + encrypted data
	    byte[] result = new byte[iv.length + encryptedAesKey.length + encryptedData.length];
	    
	    System.arraycopy(iv, 0, result, 0, iv.length);
	    System.arraycopy(encryptedAesKey, 0, result, iv.length, encryptedAesKey.length);
	    System.arraycopy(encryptedData, 0, result, iv.length + encryptedAesKey.length, encryptedData.length);
	    assertEquals(iv.length + encryptedAesKey.length + encryptedData.length,result.length);
	    return  result;
	    
	}
	
	/* - Advance Encryption Standard - Galois/Counter Mode
	 * Pre-shared Keys (PSK): When both parties already have the same AES key (e.g., stored securely).
	 * Local Encryption: Encrypting files/databases where you control both ends.
	 * Performance-Critical Apps: When RSA overhead is unacceptable (e.g., IoT devices).
	*/
	@Test
	void localEncryptionAndDecrpytion()throws Exception { 
		    String input = "Advance Encryption Standard - Galois/Counter Mode";
		    SecretKey key = AdvanceEncryptionStandard.generateKey(128);
		    GCMParameterSpec gcmParameterSpec = AdvanceEncryptionStandard.generateIv();
		    String algorithm = "AES/GCM/NoPadding";
		    String cipherText = AdvanceEncryptionStandard.encrypt(algorithm, input, key, gcmParameterSpec);
		    String plainText = AdvanceEncryptionStandard.decrypt(algorithm, cipherText, key, gcmParameterSpec);
		    assertEquals(input, plainText);
		}

	
	@Test
	void localFileEncryptionAndDecrpytion() throws Exception{
	    SecretKey key = AdvanceEncryptionStandard.generateKey(128);
	    GCMParameterSpec gcmParameterSpec = AdvanceEncryptionStandard.generateIv();
	    String algorithm = "AES/GCM/NoPadding";
	    File encryptedFile = new File(
        		Paths.get("SQLite","SQLite.encrypted").toAbsolutePath().toString());
        File decryptedFile = new File(
        		Paths.get("SQLite","SQLite.decrypted").toAbsolutePath().toString());
        
        Path inputFilePath  = Paths.get("SQLite","SQLite.txt");
        Path decryptedFilePath  = Paths.get("SQLite","SQLite.decrypted");
        AdvanceEncryptionStandard.encryptFile(
	    		algorithm, key, gcmParameterSpec, inputFilePath.toFile(), encryptedFile);
	    AdvanceEncryptionStandard.decryptFile(
	    		algorithm, key, gcmParameterSpec, encryptedFile, decryptedFile);
        
	    String inputContent = Files.readString(inputFilePath);
        String decryptedContent = Files.readString(decryptedFilePath);
	    assertEquals(inputContent, decryptedContent, "The files do not have the same content.");
//	    encryptedFile.deleteOnExit();
//	    decryptedFile.deleteOnExit();
	}
	
	@Test
	void objectEncryptionAndDecrpytion() throws Exception{
		DummyClass dummyObject = new DummyClass("dummy name", 34);
		SecretKey key = AdvanceEncryptionStandard.generateKey(128);
	    GCMParameterSpec gcmParameterSpec = AdvanceEncryptionStandard.generateIv();
	    String algorithm = "AES/GCM/NoPadding";
	    SealedObject sealedObject = AdvanceEncryptionStandard.encryptObject(
	    					algorithm, dummyObject, key, gcmParameterSpec);
	    DummyClass object = (DummyClass) AdvanceEncryptionStandard.decryptObject(
	    				algorithm, sealedObject, key, gcmParameterSpec);
	    // DummyClass implemented with POJO (Plain Old Java Object), override equals and hash methods.   
	    assertEquals(dummyObject, object, "Dummy objects should be equal field by field.");
	}

}


/* 
* Key Exchange:
* 1) Client generates a random AES-256 key. 
* 2)Encrypts it with Server’s RSA public key and sends it.
* 
* Data Encryption:
* 1) Client encrypts data using AES-256-GCM with the shared key.
* 2) Sends the ciphertext + authentication tag to Server.
* 
* Decryption:
* Server decrypts the AES key with his RSA private key.
* Uses AES-GCM to decrypt and verify the data.
*/

/*
* Step1: Asymmetric Encryption is used to securely exchange a symmetric key.
* 	Ex: RSA or ECC encrypts the AES key.
* Step2: Symmetric Encryption (AES) then encrypts the actual data for efficiency.
* 
* Reason: Asymmetric encryption is slow for large data but good for key exchange and 
* Symmetric encryption (AES) is fast for bulk data encryption.
*/

/* Advance Encryption Standard :
 * - ECB (Electronic Code Book) : Simplest of all, The plaintext is divided into blocks with a size of 128 bits. Then each block is encrypted with the same key and algorithm. Therefore, it produces the same result for the same block. This is the main weakness of this mode, and it’s not recommended for encryption. It requires padding data.
 * - CBC (Cipher Block Chaining):  CBC mode uses an Initialization Vector (IV) to augment the encryption. First, CBC uses the plaintext block xor with the IV. Then it encrypts the result to the ciphertext block. In the next block, it uses the encryption result to xor with the plaintext block until the last block. In this mode, encryption can’t be parallelized, but decryption can be parallelized. It also requires padding data.
 * - CFB (Cipher FeedBack): This mode can be used as a stream cipher. First, it encrypts the IV, then it will xor with the plaintext block to get ciphertext. Then CFB encrypts the encryption result to xor the plaintext. It needs an IV. In this mode, decryption can be parallelized, but encryption can’t be parallelized.
 * - OFB (Output FeedBack): This mode can be used as a stream cipher. First, it encrypts the IV. Then it uses the encryption results to xor the plaintext to get ciphertext. It doesn’t require padding data, and won’t be affected by the noisy block.
 * - CTR (Counter): This mode uses the value of a counter as an IV. It’s very similar to OFB, but it uses the counter to be encrypted every time instead of the IV. This mode has two strengths, including encryption/decryption parallelization, and noise in one block does not affect other blocks.
 * - GCM (Galois/Counter Mode): This mode is an extension of the CTR mode. The GCM has received significant attention and is recommended by NIST. Unlike CBC, GCM provides both confidentiality and authenticity through the use of an authentication tag. 
 * It doesn’t require padding and is highly efficient due to its parallelizable nature.
 * 
*/
