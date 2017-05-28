package be.vub.serviceprovider;

import static spark.Spark.*;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;


public class Main {

	static final String middelware = "http://localhost:4570/";
	
	public static void main(String[] args) {
		//CA.sign(CA);
		port(4566);
		get("/", (req, res) -> {
			
			return getMain();
		});
		post("/", (req, res) -> {
			 ServiceProvider sp = new ServiceProvider(req.queryParams("sp"));
			 if(sp.authenticateServiceProvider()) {
				 if(sp.authenticateCard()) {
					 String attr = sp.getAttributes();
					 return "Service Provider "+sp.getName()+ " is authenticated on the  card"+
							 "<br />Card is authenticated (Certificate is correct)<br />"+
							 "<br />" + 
							 (attr.contains("Error") ? attr : getHTMLAttributes(sp.getRawAttributes(), sp.getType()));
				 }
				 return "";
			 } else {
				 return "Authentication of the Service Provider failed";
			 }
		});

	}
	
	public static String getMain() {
		return "<form method=\"POST\">" +
				"Select Service Provider: " +
				"<select name=\"sp\">" +
				"<option value=\"Egov1\">EGovernment service 1</option>" +
				"<option value=\"Egov2\">EGovernment service 2</option>" +
				"<option value=\"SocNet1\">Social Network 1</option>" +
				"<option value=\"SocNet2\">Social Network 2</option>" +
				"<option value=\"Default1\">Default 1</option>" +
				"<option value=\"Default2\">Default 2</option>" +
				"<option value=\"Webshop1\">Web Shop 1</option>" +
				"<option value=\"Webshop2\">Web Shop 2</option>" +
				"</select>" +
				"<input type=\"submit\" value=\"Submit\" />" +
				"</form>";
						
	}
	
	public static String getHTMLAttributes(byte[] attributes, String type) {
		String res = "Unique idenitifier: " + javax.xml.bind.DatatypeConverter.printHexBinary(Arrays.copyOfRange(attributes, 0, 32));
		
		if(type.equals("egov")) {
			res += "<br>Name: " + new String(Arrays.copyOfRange(attributes, 32, 62), StandardCharsets.US_ASCII);
			res += "<br>Address: " + new String(Arrays.copyOfRange(attributes, 62, 112), StandardCharsets.US_ASCII);
			res += "<br>Country: " + new String(Arrays.copyOfRange(attributes, 112, 114), StandardCharsets.US_ASCII);
			res += "<br>Birthdate: " + new String(Arrays.copyOfRange(attributes, 114, 122), StandardCharsets.US_ASCII);
			res += "<br>Age: " + new String(Arrays.copyOfRange(attributes, 122, 125), StandardCharsets.US_ASCII);
			res += "<br>Gender: " + new String(Arrays.copyOfRange(attributes, 125, 126), StandardCharsets.US_ASCII);
		} else if(type.equals("socnet")) {
			res += "<br>Name: " + new String(Arrays.copyOfRange(attributes, 32, 62), StandardCharsets.US_ASCII);
			res += "<br>Country: " + new String(Arrays.copyOfRange(attributes, 62, 64), StandardCharsets.US_ASCII);
			res += "<br>Age: " + new String(Arrays.copyOfRange(attributes, 64, 67), StandardCharsets.US_ASCII);
			res += "<br>Gender: " + new String(Arrays.copyOfRange(attributes, 67, 68), StandardCharsets.US_ASCII);
			try{
				FileOutputStream fo = new FileOutputStream("tst.jpg");
				fo.write(Arrays.copyOfRange(attributes, 68, 68+5572));
				fo.close();
			} catch(Exception e) {
				
			}
			res += "<br>Picture: <img src=\"data:image/jpeg;base64," + new String(Base64.getEncoder().encode(Arrays.copyOfRange(attributes, 68, 68+5572)));
			res += "\" />";
		} else if(type.equals("webshop")) {
			res += "<br>Name: " + new String(Arrays.copyOfRange(attributes, 32, 62), StandardCharsets.US_ASCII);
			res += "<br>Address: " + new String(Arrays.copyOfRange(attributes, 62, 112), StandardCharsets.US_ASCII);
			res += "<br>Country: " + new String(Arrays.copyOfRange(attributes, 112, 114), StandardCharsets.US_ASCII);
		} else {
			res += "<br>Age: " + new String(Arrays.copyOfRange(attributes, 32, 35), StandardCharsets.US_ASCII);
		}
		
		return res;
	}

}
