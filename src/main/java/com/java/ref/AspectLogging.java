package com.java.ref;


public class AspectLogging {
	
	public void before(String methodName) {
		System.out.println("LOG: Before method " + methodName);
	}
	public void after(String methodName) {
		System.out.println("LOG: After method " + methodName);
	}
}
