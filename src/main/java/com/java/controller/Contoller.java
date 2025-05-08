package com.java.controller;

import com.java.ref.Inject;
import com.java.service.Service;

public class Contoller {
	
	@Inject
	private Service service;

	// basicDependencyInjector
//	public Contoller(Service service) {
//		this.service = service;
//	}

	public String fetch() {
		return service.get();
	}
}
