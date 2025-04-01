package com.java;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class JavaSecurity {
	
	private static final Logger log = LoggerFactory.getLogger(JavaSecurity.class);
	private static final Path filePath= Paths.get("SQLite","database.db");
	private static final String url = "jdbc:sqlite:"+filePath.toAbsolutePath().toString();

    
	public static void main(String[] args) {
	    try (Connection conn = DriverManager.getConnection(url)) {
	    	createTables(conn);
	    	selectQuery(conn);
	    	whereQuery(conn);
	    	groupByQuery(conn);
	    	joinQuery(conn);
	    	orderByQuery(conn);
	    	rightJoinExample(conn);
	    	fullOuterJoinExample(conn);
	    	unionCombineNames(conn);
	    	unionForSearch(conn);
	    } catch (SQLException e) {
            e.printStackTrace();
        }
    }
	
	private static void unionForSearch(Connection conn) throws SQLException {
		System.out.println("\n=== UNION ALL Example ===");
		 String sql =
				 "SELECT 'user' AS type, name FROM users WHERE name LIKE '%A%' "+
				 "UNION "+
				 "SELECT 'department' AS type, name FROM departments WHERE name LIKE '%A%' OR name LIKE '%E%' ";
    
	    try (Statement stmt = conn.createStatement();
	         ResultSet rs = stmt.executeQuery(sql)) {
	        
	        System.out.println("Search names in users and  departments ");
	        while (rs.next()) {
	            System.out.println("type: " + rs.getString("type")+ "- name: "+ rs.getString("name"));
	        }
	    }
	}
	
	private static void unionCombineNames(Connection conn) throws SQLException {
	    System.out.println("\n=== UNION Example ===");
	    
	    // Combine names from users and department names into a single list
	    String sql = "SELECT name FROM users " +
	                 "UNION " +  // Removes duplicates
	                 "SELECT name FROM departments " +
	                 "ORDER BY name";  // Sorts combined results
	    
	    try (Statement stmt = conn.createStatement();
	         ResultSet rs = stmt.executeQuery(sql)) {
	        
	        System.out.println("Combined names (users + departments):");
	        while (rs.next()) {
	            System.out.println("- " + rs.getString("name"));
	        }
	    }
	}
	
	/*
	 * SQLite doesn't support FULL OUTER JOIN, combining LEFT JOIN and RIGHT JOIN with UNION:
	 * - All users + all departments
	*/
	private static void fullOuterJoinExample(Connection conn) throws SQLException {
	    System.out.println("\n=== FULL OUTER JOIN (Simulated) ===");
	    
	    String sql = "SELECT u.name AS user, d.name AS department " +
	                 "FROM users u " +
	                 "LEFT JOIN departments d ON u.department_id = d.id " +
	                 "UNION " +
	                 "SELECT u.name AS user, d.name AS department " +
	                 "FROM departments d " +
	                 "LEFT JOIN users u ON d.id = u.department_id " +
	                 "WHERE u.id IS NULL";  // Exclude overlaps already shown in LEFT JOIN
	    
	    try (Statement stmt = conn.createStatement();
	         ResultSet rs = stmt.executeQuery(sql)) {
	        
	        System.out.println("All users and departments (FULL OUTER JOIN):");
	        while (rs.next()) {
	            String user = rs.getString("user");
	            String dept = rs.getString("department");
	            System.out.printf("User: %-8s | Department: %s%n", 
	                            (user != null) ? user : "NULL (no user)", 
	                            (dept != null) ? dept : "NULL (no department)");
	        }
	    }
	}
	
	
	/*
	 * - RIGHT JOIN: Useful to find departments with no users.
	*/
	private static void rightJoinExample(Connection conn) throws SQLException {
	    System.out.println("\n=== RIGHT JOIN (Simulated) ===");
	    String sql = "SELECT d.name AS department, u.name AS user " +
	                 "FROM departments d " +
	                 "LEFT JOIN users u ON d.id = u.department_id " +
	                 "ORDER BY d.name";
	    
	    try (Statement stmt = conn.createStatement();
	         ResultSet rs = stmt.executeQuery(sql)) {
	        
	        System.out.println("Departments and their users (RIGHT JOIN):");
	        while (rs.next()) {
	            String dept = rs.getString("department");
	            String user = rs.getString("user");
	            System.out.printf("Department: %-12s | User: %s%n", 
	                            dept, 
	                            (user != null) ? user : "NULL (no user)");
	        }
	    }
	}

	
	private static void joinQuery(Connection conn) throws SQLException {
	    System.out.println("\n=== INNER JOIN ===");
	    String sql = "SELECT u.name, d.name as department " +
	                 "FROM users u " +
	                 "INNER JOIN departments d ON u.department_id = d.id";
	                 
	    try (Statement stmt = conn.createStatement();
	         ResultSet rs = stmt.executeQuery(sql)) {
	        while (rs.next()) {
	            System.out.printf("User: %s, Department: %s%n",
	                            rs.getString("name"),
	                            rs.getString("department"));
	        }
	    }
	}
	
	private static void orderByQuery(Connection conn) throws SQLException {
	    System.out.println("\n=== ORDER BY ===");
	    String sql = "SELECT name, age FROM users ORDER BY age DESC";
	    
	    try (Statement stmt = conn.createStatement();
	         ResultSet rs = stmt.executeQuery(sql)) {
	        
	        while (rs.next()) {
	            System.out.printf("Name: %s, Age: %d%n",
	                            rs.getString("name"),
	                            rs.getInt("age"));
	        }
	    }
	}
	
	
	private static void groupByQuery(Connection conn) throws SQLException {
	    System.out.println("\n=== GROUP BY ===");
	    String sql = "SELECT department_id, COUNT(*) as user_count, AVG(age) as avg_age " +
	                 "FROM users GROUP BY department_id";
	    
	    try (Statement stmt = conn.createStatement();
	         ResultSet rs = stmt.executeQuery(sql)) {
	        
	        while (rs.next()) {
	            System.out.printf("Dept ID: %d, Users: %d, Avg Age: %.2f%n",
	                            rs.getInt("department_id"),
	                            rs.getInt("user_count"),
	                            rs.getDouble("avg_age"));
	        }
	    }
	}
	
	
	private static void whereQuery(Connection conn) throws SQLException {
	    System.out.println("\n=== WHERE Clause ===");
	    String sql = "SELECT name, age FROM users WHERE age > ? OR name LIKE ? ";
	    
	    try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
	        pstmt.setInt(1, 25);  
	        pstmt.setString(2, "%"+"A" +"%");
	        ResultSet rs = pstmt.executeQuery();
	        
	        while (rs.next()) {
	            System.out.printf("Name: %s, Age: %d%n",
	                            rs.getString("name"),
	                            rs.getInt("age"));
	        }
	    }
	}
	
	
	private static void selectQuery(Connection conn) throws SQLException {
	    System.out.println("\n=== Basic SELECT ===");
	    String sql = "SELECT id, name, age FROM users";
	    
	    try (Statement stmt = conn.createStatement();
	         ResultSet rs = stmt.executeQuery(sql)) {
	        
	        while (rs.next()) {
	            System.out.printf("ID: %d, Name: %s, Age: %d%n",
	                            rs.getInt("id"),
	                            rs.getString("name"),
	                            rs.getInt("age"));
	        }
	    }
	}
	
	private static void createTables(Connection conn) throws SQLException {
		String dropUsers = "DROP TABLE IF EXISTS users";
		String createUsers = "CREATE TABLE IF NOT EXISTS users (" +
                            "id INTEGER PRIMARY KEY, " +
                            "name TEXT, " +
                            "age INTEGER, " +
                            "department_id INTEGER)";
		String dropDepartments = "DROP TABLE IF EXISTS departments";
		String createDepartments = "CREATE TABLE IF NOT EXISTS departments (" +
                                 "id INTEGER PRIMARY KEY, " +
                                 "name TEXT)";
		String dropOrders = "DROP TABLE IF EXISTS orders";
        String createOrders = "CREATE TABLE IF NOT EXISTS orders (" +
                            "id INTEGER PRIMARY KEY, " +
                            "user_id INTEGER, " +
                            "amount REAL, " +
                            "order_date TEXT)";
        conn.createStatement().execute(dropUsers);
        conn.createStatement().execute(dropDepartments);
        conn.createStatement().execute(dropOrders);
        conn.createStatement().execute(createUsers);
        conn.createStatement().execute(createDepartments);
        conn.createStatement().execute(createOrders);
        conn.createStatement().execute("INSERT INTO users (name, age, department_id) VALUES " +
                                      "('Alice', 25, 1), ('Bob', 30, 2), ('Charlie', 22, 1),('Jake', 19, null)");
        
        conn.createStatement().execute("INSERT INTO departments (name) VALUES " +
                                      "('HR'), ('Engineering')");
        
        conn.createStatement().execute("INSERT INTO orders (user_id, amount, order_date) VALUES " +
                                      "(1, 100.50, '2023-01-15'), " +
                                      "(1, 200.75, '2023-02-20'), " +
                                      "(2, 50.25, '2023-01-10')");
    }
	
}
