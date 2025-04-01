package com.java.pojo;

import java.io.Serializable;
import java.util.Objects;

public class DummyClass implements Serializable {

	private static final long serialVersionUID = 1L;

	private String name;
	private int age;
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getAge() {
		return age;
	}
	public void setAge(int age) {
		this.age = age;
	}
	public DummyClass(String name, int age) {
		super();
		this.name = name;
		this.age = age;
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(age, name);
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DummyClass other = (DummyClass) obj;
		return age == other.age && Objects.equals(name, other.name);
	}

	
}
