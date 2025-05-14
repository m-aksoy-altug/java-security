package com.java.ref.repo;

import com.java.ref.anno.Repository;
import com.java.ref.entity.Hibernate;

@Repository
public interface HibernateRepository extends RepositoryFactory<Hibernate,Integer>{
}
