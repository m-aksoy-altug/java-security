package com.java.utils;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class TestUtils {
	
	public static void writeData(String path, String fileName, byte[] writeBytes) {
		Path filePath= Paths.get(path,fileName);
		try (FileOutputStream fos = new FileOutputStream(filePath.toAbsolutePath().toString())) {
		    fos.write(writeBytes); // raw 
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	public static byte[] readData(String path, String fileName) {
		Path filePath= Paths.get(path,fileName);
		try {
			 return Files.readAllBytes(filePath); // raw
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
}
