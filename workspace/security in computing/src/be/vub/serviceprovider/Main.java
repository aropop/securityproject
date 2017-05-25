package be.vub.serviceprovider;

import static spark.Spark.*;

import be.vub.security.CertificateAttributes;
import be.vub.security.CustomKeyPair;

public class Main {

	static final String middelware = "http://localhost:4570/";
	//static final byte[] CA_cert = CustomKeyPair.fromFile("ca.ckeys");
	
	public static void main(String[] args) {
		//CA.sign(CA);
		port(4566);
		get("/", (req, res) -> {
			
			return getMain();
		});
		post("/", (req, res) -> {
			System.out.println(req.queryParams("sp"));
			return new ServiceProvider(req.queryParams("sp")).authenticate();
//			return getMain();
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

}
