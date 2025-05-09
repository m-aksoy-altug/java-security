package com.java.controller;

import com.java.ref.Inject;
import com.java.service.ServiceA;

public class ContollerA {
	
	@Inject
	private  ServiceA servicea;

	public String fetch() {
		return servicea.get();
	}
}
