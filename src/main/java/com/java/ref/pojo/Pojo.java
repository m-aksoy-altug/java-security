package com.java.ref.pojo;

public class Pojo {
	
	private String name;
	private int age;
	private Pojo() {}
	public Pojo(String name, int age) {
		super();
		this.name = name;
		this.age = age;
	}

	@Override
	public String toString() {
		return "Pojo [name=" + name + ", age=" + age + "]";
	}
	
	
}
