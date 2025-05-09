package com.java.controller;

import com.java.ref.anno.Inject;
import com.java.service.ServiceA;

public class ContollerA {
	
	@Inject
	private  ServiceA servicea;

	public String fetch() {
		return servicea.get();
	}
}
