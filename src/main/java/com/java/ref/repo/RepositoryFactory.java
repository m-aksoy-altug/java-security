package com.java.ref.repo;

public interface RepositoryFactory<T,ID> {
	Boolean save(T entity); // should return PK 
	T findById(ID id);
}
