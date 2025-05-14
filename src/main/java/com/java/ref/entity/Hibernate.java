package com.java.ref.entity;

import com.java.ref.anno.Entity;
import com.java.ref.anno.Id;
import com.java.ref.anno.Column;

//Hibernate is a table name
@Entity(name="Hibernate") 
public class Hibernate {
	
	@Id
    @Column(name = "id")
    private int id;

    @Column(name = "name")
    private String name;

    @Column(name = "email")
    private String email;

    public Hibernate(int id, String name, String email) {
        this.id = id;
        this.name = name;
        this.email = email;
    }
    public Hibernate() {}
	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}
    
}