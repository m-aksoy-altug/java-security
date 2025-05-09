package com.java.ref;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.java.controller.ContollerA;
import com.java.controller.ContollerB;
import com.java.jwt.Jwt;
import com.java.service.ServiceA;
import com.java.service.SpecialServiceA;
import com.java.utils.TestUtils;

/*
 * - Dependency-Injection (DI) and Inversion-of-Control-Containers (IoC):
 * To instantiate objects, inject dependencies and configure components based on metadata like annotations, XML config file.
 * For dynamically discover and wire dependencies at Runtime. EX: Spring
 * - Aspect-Orineted-Programming (AOP): EX: AspectJ, Spring AOP
 * To apply cross cutting concerns like logging, security and transactions. 
 * To dynamically create proxies and apply aspects to target objects or methods.
 * - Object-Relational-Mapping (ORM): EX: Hibernate
 * To map java objects to DB tables and columns. To introspect entity classes, retrieve their metaData.
 * To dynamically create SQL queries based on the class structure.
 * - Serialization and Deserialization: EX: Jackson, JAXB
 * To introspect object fields, methods and annotations to determine how to serialize and deserialize objects. 
 * To convert Java objects to or from JSON, XML.
 * - Testing frameworks: EX: Junit 
 * To dynamically discover test methods, instantiate test classes and execute test cases.
 * To scan test classes for test annotations, identify test methods and invoke them in Runtime.
 * - GUI Framework: EX: JavaFX
 * To configure UI components, event handlers and set properties programmatically.
 * - Plugin Systems : EX: Eclipse, Jenkins, Maven
 * To dynamically load and manage plugins.
 * To Scan directories or JAR files for plugin classes, instantiate plugin objects and invoke their methods without compile time dependencies.
 * - Template Engine: Dynamic Code Generation: EX: Apache Velocity, Freemarker
 * To dynamically generate code based on templates or configuration files. 
 */

public class TestReflection {
	
	@Test
	public void BasicObjectRelationalMapping() throws Exception {
		BasicReflection ref = new BasicReflection();
		String insertQuery =
				ref.basicInsertORMbyEntityManager(new Hibernate(1, "Dummy", "dummy@gmail.com"));
		System.out.println("insertQuery"+insertQuery);
		assertTrue(insertQuery.contains("INSERT INTO"));
	}
	
	@Test
	public void BasicAspectOrientedProgramming() throws Exception {
		BasicReflection ref = new BasicReflection();
		ServiceA proxyServiceA= (ServiceA) ref.createAOPproxy(new SpecialServiceA(), new AspectLogging());
		proxyServiceA.get();
	}
	
	@Test
	public void BasicDepedencyInjection() throws Exception {
		BasicReflection ref = new BasicReflection();
		ContollerA controllerA= ref.basicAnnotationBasedDependencyInjector(ContollerA.class);
		assertEquals("SpecialService A is executing.",controllerA.fetch());
	    ContollerB controllerB = ref.basicConstructorBasedDependencyInjector(ContollerB.class);
		assertEquals("SpecialService B is executing.",controllerB.fetch());
	}
	
	
	@Test
	public void methodExecution() throws Exception {
		Jwt jwtObject = new Jwt();
		Class<?> jwtClass =  Jwt.class;
		Method jwtSecret = jwtClass.getMethod("generateNewSecretKey");
		final byte[] sharedSecret = (byte[]) jwtSecret.invoke(jwtObject);
		assertEquals(256/8,sharedSecret.length); // 256 bits = 32 bytes
		Method jwtSignedJwt = jwtClass.getMethod("createSignedJwt", byte[].class);
		String jwt= (String) jwtSignedJwt.invoke(jwtSignedJwt, sharedSecret);
		String[] jwtParts= jwt.split("\\.");
		assertEquals(3,jwtParts.length); 
		String jwtHeader = new String(Base64.getUrlDecoder().decode(jwtParts[0]));
		assertTrue(jwtHeader.contains("HS256"));
		String jwtBody = new String(Base64.getUrlDecoder().decode(jwtParts[1]));
		assertTrue(jwtBody.contains("roles"));
		byte[] signatureDecoded= Base64.getUrlDecoder().decode(jwtParts[2]);
		assertEquals(256/8,signatureDecoded.length); // 256 bits = 32 bytes
	}
		
	@Test
	public void inspectClassInfo() throws Exception {
		Class<?> jwtClass =  Jwt.class;
		assertEquals("com.java.jwt.Jwt", jwtClass.getName()) ;
		int modifier = jwtClass.getModifiers();
		assertEquals("public", Modifier.toString(modifier)) ;
		Class<?> jwtSuperClass = jwtClass.getSuperclass();
		assertEquals( Object.class.getName(), jwtSuperClass.getName());
		Class<?> [] jwtinterfaces = jwtClass.getInterfaces();
		assertEquals( 0, jwtinterfaces.length);
		for (Class<?> intf : jwtinterfaces) {}
		Annotation [] jwtAnnotations = jwtClass.getAnnotations();
		assertEquals( 0, jwtAnnotations.length);
		for (Annotation annotation : jwtAnnotations) {}
	}
	
	@Test
	public void inspectSystemClassInfo() throws Exception {
		Class<?> systemClass =  System.class;
		assertEquals(System.class.getName(), systemClass.getName()) ;
		int modifier = systemClass.getModifiers();
		assertEquals("public final", Modifier.toString(modifier)) ;
		Class<?> jwtSuperClass = systemClass.getSuperclass();
		assertEquals( Object.class.getName(), jwtSuperClass.getName());
		Class<?> [] systemInterfaces = systemClass.getInterfaces();
		assertEquals( 0, systemInterfaces.length);
		Annotation [] systemAnnotations = systemClass.getAnnotations();
		assertEquals( 0, systemAnnotations.length);
		assertTrue(Object.class.isAssignableFrom(System.class)); // Object is super class of System
		assertFalse(systemClass.isInterface());
	}
	
}
