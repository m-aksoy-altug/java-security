package com.java.ref.controller;

import com.java.ref.service.ServiceB;

public class ContollerB {
	
	private  ServiceB serviceb;

	public ContollerB(ServiceB serviceb) {
		this.serviceb = serviceb;
	}

	public String fetch() {
		return serviceb.get();
	}
}
