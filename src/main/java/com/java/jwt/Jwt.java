package com.java.jwt;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Date;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.KeyGenerator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.utils.Constant;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/*
 * - JSON Web Token- JSON Web Signature
 * - Use JWT-JWS : Authentication tokens, for verify the integrity of the token but not hide the contents
 * - JSON Web Token - JSON Web Encryption
 * - Use JWT-JWE : Passing sensitive data, use RSA public private key logic.
*/
public class Jwt {
	
	private static final Logger log = LoggerFactory.getLogger(Jwt.class);
	
	
	/* - Signed JWT (JSE) with HMAC protection
	 *	 
	*/
	public static String createSignedJwt(final byte[] sharedSecret) throws JOSEException {
		Map<String, Object> customClaims = new HashMap<>();
		customClaims.put("name", "Dummy User");
		customClaims.put("email", "dummyUser@gmail.com");
		customClaims.put("role",new String[]{"user", "admin"});
		// HMAC signer
		MACSigner signer= new MACSigner(sharedSecret);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
	            .subject("Dummy User")
	            .issuer(Constant.IP) // should be domain name
	            .expirationTime(Date.from(LocalDateTime.now()
	            		            .plusMinutes(60)
	            		            .atZone(ZoneId.of("UTC"))
	            		            .toInstant()))
	            .jwtID(UUID.randomUUID().toString())
	            .claim("name", "Dummy User")
	            .claim("email", "dummyUser@gmail.com")
	            .claim("roles", new String[]{"user", "admin"})
	            .build();
		
		 
		 // Json Web Signature,  header with HMAC SHA-256
		JWSHeader jWSHeader = new JWSHeader.Builder(JWSAlgorithm.HS256)
	            .type(JOSEObjectType.JWT)
	            .build();
	
		SignedJWT signedJWT =new SignedJWT(jWSHeader, claimsSet);
		signedJWT.sign(signer);
		return signedJWT.serialize();
	}
	
	public static JWTClaimsSet validateSignedJwt(String jwtString, final byte[] sharedSecret) 
									throws JOSEException, ParseException {
		
		SignedJWT signedJWT = SignedJWT.parse(jwtString);
        JWSVerifier verifier = new MACVerifier(sharedSecret);
        
        if (!signedJWT.verify(verifier)) {
            throw new JOSEException("Invalid signature");
        }
        
        if (LocalDateTime.now().atZone(ZoneId.of("UTC")).toEpochSecond() > 
        		(signedJWT.getJWTClaimsSet().getExpirationTime().getTime()/1000)) {
            throw new JOSEException("Expired token");
        }
        
        return (JWTClaimsSet) signedJWT.getJWTClaimsSet();
	}
	
	/* - HmacSHA256: 256-bits key = 256/8=32 bytes
	 * - HmacSHA384: 384-bits key = 384/8=48 bytes
	 * - HmacSHA512: 512-bits key = 384/8=64 bytes
	*/
	public static byte[] generateNewSecretKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            keyGen.init(256); // 256-bits key = 256/8=32 bytes
            return keyGen.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            // Fallback to SecureRandom
            byte[] key = new byte[32]; // 256-bit
            new SecureRandom().nextBytes(key);
            return key;
        }
    }

    public static String createEncryptedJWT(RSAKey rsaKey) throws JOSEException {
        
        JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
            .contentType("JWT") 
            .build();
       
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("Sensitive User")
                .issuer(Constant.IP) // should be domain name
                .expirationTime(Date.from(LocalDateTime.now()
    		            .plusMinutes(60)
    		            .atZone(ZoneId.of("UTC"))
    		            .toInstant()))
                .claim("data", "Sensitive")
	            .build();
        
        JWEObject jweObject = new JWEObject(jweHeader,new Payload(jwtClaimsSet.toJSONObject()));
        jweObject.encrypt(new RSAEncrypter(rsaKey.toRSAPublicKey()));
        return jweObject.serialize();
    }

    
    public static JWTClaimsSet decryptJWE(String jweString, RSAKey rsaKey) 
            					throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(jweString);
        jweObject.decrypt(new RSADecrypter(rsaKey.toRSAPrivateKey()));
        Payload payload = jweObject.getPayload();
        return JWTClaimsSet.parse(payload.toJSONObject());
    }
	
}
