package com.java.utils;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Utils {
	
	public static void writeData(String fileName, byte[] writeBytes) {
		Path filePath= Paths.get("RSA",fileName);
		try (FileOutputStream fos = new FileOutputStream(filePath.toAbsolutePath().toString())) {
		    fos.write(writeBytes); // raw 
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	public static byte[] readData(String fileName) {
		Path filePath= Paths.get("RSA",fileName);
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
