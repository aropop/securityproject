package be.msec.smartcard;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

public class AttributesToBytes {

	public static void main(String[] args) {
		String name = String.format("%1$-" + 30 + "s", "John Doe");
		String address = String.format("%1$-" + 50 + "s", "TestStreet 45, 1000 Brussels");
		String country = String.format("%1$-" + 2 + "s", "BE");
		String birthday = String.format("%1$-" + 8 + "s", "01011990");
		String age = String.format("%1$-" + 3 + "s", "27"); // should be calculated on the card
		
		String[] atrs = new String[]{name, address, country, birthday, age};
		for(String a : atrs) {
			for(byte b : a.getBytes(StandardCharsets.US_ASCII)) {
				System.out.print("(byte) ");
				System.out.print(b);
				System.out.print(", ");
			}
			System.out.print("\n");			
		}
		
		try {
			FileInputStream fi = new FileInputStream("John_Doe_small.jpg");
			byte[] d = new byte[(int)(new File("John_Doe_small.jpg")).length()];
			fi.read(d);
			for(byte b : d) {
				System.out.print("(byte) ");
				System.out.print(b);
				System.out.print(", ");
			}
			System.out.print("\n");	
		} catch(Exception e) {
			System.out.println("Something went wrong");
		}

	}

}
