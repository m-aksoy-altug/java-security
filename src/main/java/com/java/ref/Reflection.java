package com.java.ref;

import java.lang.reflect.Constructor;

import java.util.HashMap;
import java.util.Map;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Reflection {
	
	private static final Logger log = LoggerFactory.getLogger(Reflection.class);
	
	private Map<Class<?>, Class<?>> binds= new HashMap<>();
	
	public <T> void manualBind(Class<T> interfaceType, Class<? extends T> implementType) {
		binds.put(interfaceType, implementType);
	}
	
	public <T> T basicDependencyInjector(Class<T> clazzz) {
		try {
			if(clazzz.isInterface()) {
				// TODO: Manual binding required now between interface and class implementor
				Class<?> impl = binds.get(clazzz);
                if (impl == null) {
                	 throw new RuntimeException("No implementation found for interface: " + clazzz.getName());
                }
                clazzz = (Class<T>) impl;
            }
			log.info("clazzz.getName():::"+ clazzz.getName());
			// return all constructors but not includes inherited ones.
			Constructor<?>[] constructors =  clazzz.getDeclaredConstructors();  
			if(constructors.length>0) {
				Constructor<?> constructor = 	constructors[0];
				constructor.setAccessible(true);
				Class<?>[] paramTypes = constructor.getParameterTypes();
		        Object[] params = new Object[paramTypes.length];
		        for (int i = 0; i < paramTypes.length; i++) {
		        	log.info("recursive DI:::"+ paramTypes[i].getName());
		            params[i] = basicDependencyInjector(paramTypes[i]); 
		        }
		        return  (T) constructor.newInstance(params);
			}else {
				log.info("no Constructor is found"+ clazzz.getName());
				throw new RuntimeException("no Constructor is found"+ clazzz.getName());
			}
		}catch(Exception e) {
			 throw new RuntimeException("Failed to inject dependencies", e);
		}
	}
	
	
}
