package com.java.ref;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Proxy;
import java.lang.reflect.Type;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.java.ref.anno.Column;
import com.java.ref.anno.Entity;
import com.java.ref.anno.Inject;
import com.java.ref.anno.Repository;
import com.java.ref.repo.RepositoryFactory;

public class BasicReflection {
	private static final Logger log = LoggerFactory.getLogger(BasicReflection.class);

	public <T> T basicConstructorBasedDependencyInjector(Class<T> clazzz) {
		try {
			if (clazzz.isInterface()) {
				Class<?> impl = scanningImplementedClasses(clazzz);
				if (impl == null) {
					throw new RuntimeException("No implementation found for interface: " + clazzz.getName());
				}
				clazzz = (Class<T>) impl;
			}
			log.info("clazzz.getName():::" + clazzz.getName());
			// return all constructors but not includes inherited ones.
			Constructor<?>[] constructors = clazzz.getDeclaredConstructors();
			if (constructors.length > 0) {
				Constructor<?> constructor = constructors[0];
				constructor.setAccessible(true);
				Class<?>[] paramTypes = constructor.getParameterTypes();
				Object[] params = new Object[paramTypes.length];
				for (int i = 0; i < paramTypes.length; i++) {
					log.info("recursive DI:::" + paramTypes[i].getName());
					params[i] = basicConstructorBasedDependencyInjector(paramTypes[i]);
				}
				return (T) constructor.newInstance(params);
			} else {
				throw new RuntimeException("no Constructor is found" + clazzz.getName());
			}
		} catch (Exception e) {
			throw new RuntimeException("Failed to inject dependencies", e);
		}
	}

	public <T> T basicAnnotationBasedDependencyInjector(Class<T> clazzz) {
		// log.info("clazzz.getName():::" + clazzz.getName());
		try {
			// return all constructors but not includes inherited ones.
			Constructor<T> constructor = clazzz.getDeclaredConstructor();
			constructor.setAccessible(true);
			T instance = constructor.newInstance();
			// log.info("instance :: " + instance.getClass().getName());

			for (Field field : clazzz.getDeclaredFields()) {
				if (field.isAnnotationPresent(Inject.class)) {
					Class<?> fieldType = field.getType();
					Class<?> implClass = scanningImplementedClasses(fieldType);

					if (implClass == null) {
						throw new RuntimeException("No implementation found for " + fieldType.getName());
					}

					Object dependency = basicAnnotationBasedDependencyInjector(implClass); // Recursive dependency
																							// creator
					// log.info("dependency.getClass().getName():: " +
					// dependency.getClass().getName());
					// log.info("instance for dependency:: " + instance.getClass().getName());
					field.setAccessible(true);
					field.set(instance, dependency);
				}
			}

			return instance;
		} catch (Exception e) {
			throw new RuntimeException("Failed to inject dependencies", e);
		}
	}

	/*
	 * - Scan only inside the same package name, usually interface and implementors
	 * should be in same package TODO : Scan all subpackages recursively.
	 */
	private Class<?> scanningImplementedClasses(Class<?> clazzz) {
		try {
			String packageName = clazzz.getPackageName();
			String packagePath = packageName.replace('.', '/');

			ClassLoader classLoader = clazzz.getClassLoader();
			URL resource = classLoader.getResource(packagePath);

			if (resource == null) {
				throw new RuntimeException("Cannot find resource for package: " + packageName);
			}
			File directory = new File(resource.toURI());
			// log.info("directory:: " + directory);
			return scanDirectoryForImplementation(directory, packageName, clazzz);

		} catch (Exception e) {
			throw new RuntimeException("Error scanning package: " + e.getMessage(), e);
		}
	}

	private Class<?> scanDirectoryForImplementation(File directory, String packageName, Class<?> interfaceClass) {
		File[] files = directory.listFiles();
		if (files == null) {
			return null;
		}
		for (File file : files) {
			if (file.isDirectory()) {
				Class<?> found = scanDirectoryForImplementation(file, packageName + "." + file.getName(),
						interfaceClass);
				if (found != null) {
					return found;
				}
			} else if (file.getName().endsWith(".class")) {
				String className = packageName + '.' + file.getName().replaceAll("\\.class$", ""); // remove end of str
				// log.info("String className: " + className);
				try {
					Class<?> clazz = Class.forName(className);
					// log.info("Class<?> clazz: " + clazz.getName() );
					if (interfaceClass.isAssignableFrom(clazz) && !clazz.isInterface()
							&& !Modifier.isAbstract(clazz.getModifiers())) {
						return clazz;
					}
				} catch (ClassNotFoundException e) {
					log.error("ClassNotFoundException" + e);
				}
			}
		}
		return null;
	}

	public Object createAOPproxy(Object obj, AspectLogging aspectLogging) {
		return Proxy.newProxyInstance(obj.getClass().getClassLoader(), obj.getClass().getInterfaces(),
				new InvocationHandler() {
					@Override
					public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
						// log.info("createProxy- invoke: " + args);
						aspectLogging.before(method.getName());
						Object result = method.invoke(obj, args);
						aspectLogging.after(method.getName());
						return result;
					}
				});

	}
	
	@SuppressWarnings("unchecked")
	public <T> T createRepository(Class<T> repoInterface) {
		if(!repoInterface.isInterface()) {
			throw new IllegalArgumentException("Proxy can be only created by Interface");
		}
		if(!repoInterface.isAnnotationPresent(Repository.class)) {
			throw new IllegalArgumentException("No Repository annotation is present");
		}
		
		final Class<?> entityClass = findClassFromGivenInterface(repoInterface);

		if (entityClass == null) {
			throw new RuntimeException("Could not determine entity class for repository: " + repoInterface.getName());
		}
//		return (T) Proxy.newProxyInstance(
//				repoInterface.getClassLoader(),
//				new Class<?>[] {repoInterface},
//				new RepositoryInvocationHandler(repoInterface,entityClass)
//				);
		return (T) Proxy.newProxyInstance(
					repoInterface.getClassLoader(),
					new Class<?>[] {repoInterface},
					new InvocationHandler() {
						
						@Override
						public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
							if ("save".equals(method.getName()) && args != null && args.length == 1) {
				                Object entity = args[0];
				                String sql = basicInsertORMbyEntityManager(entity);
				                log.info("Insert SQL: " + sql);
				                return true; // should return PK
				            }
							 if ("findById".equals(method.getName()) && args != null && args.length == 1) {
								  Object id = args[0];
			                        System.out.println("DB query for ID: " + id);
			                        Object instance = entityClass.getDeclaredConstructor().newInstance();
			    					Field idField = Arrays.stream(entityClass.getDeclaredFields())
			    							.filter(f -> f.getName().equals("id"))
			    							.findFirst()
			    							.orElseThrow(() -> new RuntimeException("No 'id' field found!!!"));
			    					idField.setAccessible(true);
			    					idField.set(instance, id);
			    					return instance;
							 }
				            throw new UnsupportedOperationException("Method " + method.getName() + " is not implemented");							
						}
					});
	}
	
	private Class<?> findClassFromGivenInterface(final Class<?> repoInterface) {
		Type[] genericInterfaces =  repoInterface.getGenericInterfaces();
		for (Type type : genericInterfaces) {
			if (type instanceof ParameterizedType) {
				ParameterizedType pt = (ParameterizedType) type;
				Type rawType = pt.getRawType();
				if (rawType instanceof Class && 
						RepositoryFactory.class.isAssignableFrom((Class<?>) rawType)) {
					Type[] typeArguments = pt.getActualTypeArguments();
					if (typeArguments.length >= 1 && typeArguments[0] instanceof Class) {
						return (Class<?>) typeArguments[0]; // Get the entity type
					}
				}
			}
		}
		return null;
	}	
	
	public String basicInsertORMbyEntityManager(Object obj) {
		List<String> columns = new ArrayList<>();
		List<String> values = new ArrayList<>();
		Class<?> clazz = obj.getClass();
		if (!clazz.isAnnotationPresent(Entity.class)) {
			throw new RuntimeException("No @Entity annotation...");
		}
		Entity entity = clazz.getAnnotation(Entity.class);
		String tableName = entity.name();
		for (Field field : clazz.getDeclaredFields()) {
			if (field.isAnnotationPresent(Column.class)) {
				field.setAccessible(true);
				Column column = field.getAnnotation(Column.class);
				columns.add(column.name());
				try {
					Object value = field.get(obj);
					if (value instanceof String) {
						values.add("'" + value + "'");
					} else {
						values.add(value.toString());
					}
				} catch (IllegalArgumentException | IllegalAccessException e) {
					log.error("IllegalArgumentException | IllegalAccessException" + e);
				}
		    }
		}
		return 	"INSERT INTO " + tableName + 
				"(" + String.join(", ", columns) + 
				") VALUES (" +  String.join(", ", values) + ");";
	}	
}

class RepositoryInvocationHandler<T> implements InvocationHandler {
	
	private static final Logger log = LoggerFactory.getLogger(RepositoryInvocationHandler.class);
	
	private final Class<T> repoInterface;
    private final Class<?> entityClass;
    	
    public RepositoryInvocationHandler(Class<T> repoInterface, Class<?> entityClass) {
        this.repoInterface = repoInterface;
        this.entityClass = entityClass;
    }
    
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if ("save".equals(method.getName()) && args != null && args.length == 1) {
            Object entity = args[0];
            BasicReflection basicReflection = new BasicReflection();
            String sql = basicReflection.basicInsertORMbyEntityManager(entity);
//            System.out.println("Insert SQL: " + sql);
            log.info("Insert SQL: " + sql);
            return true;
        }

        if ("findById".equals(method.getName()) && args != null && args.length == 1) {
            Object id = args[0];
//            System.out.println("DB query for ID: " + id);
            log.info("Insert SQL: " + "DB query for ID: " + id);
            Object instance = entityClass.getDeclaredConstructor().newInstance();

            Field idField = Arrays.stream(entityClass.getDeclaredFields())
                    .filter(f -> f.getName().equals("id"))
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("No ID field found"));

            idField.setAccessible(true);
            idField.set(instance, id);
            return instance;
        }

        throw new UnsupportedOperationException("Method " + method.getName() + " is not implemented");
    }
    
}
