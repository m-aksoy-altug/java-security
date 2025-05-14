package com.java.ref.controller;

import com.java.ref.anno.Inject;
import com.java.ref.service.ServiceA;

public class ContollerA {
	
	@Inject
	private  ServiceA servicea;

	public String fetch() {
		return servicea.get();
	}
}
