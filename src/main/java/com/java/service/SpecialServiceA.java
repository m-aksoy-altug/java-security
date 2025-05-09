package com.java.service;

public class SpecialServiceA implements ServiceA {
		
	@Override
	public String get() {
		System.out.println("SpecialService A is executing.");
		return "SpecialService A is executing.";
	}
}
