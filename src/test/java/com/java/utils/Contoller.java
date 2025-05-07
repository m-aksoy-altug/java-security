package com.java.utils;

public class Contoller {

	private Service service;

	public Contoller(Service service) {
		this.service = service;
	}

	public String fetch() {
		return service.get();
	}
}
