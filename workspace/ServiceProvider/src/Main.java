
import static spark.Spark.*;

import be.vub.security.CertificateAttributes;
import be.vub.security.MinimalCertificate;

public class Main {

	static final String middelware = "http://localhost:4570/";
	static final MinimalCertificate CA = new MinimalCertificate(new CertificateAttributes("CA", 365, "CA"));
	
	public static void main(String[] args) {
		CA.sign(CA);
		port(4566);
		get("/", (req, res) -> {
			
			return getMain();
		});
		post("/", (req, res) -> {
			System.out.println(req.queryParams("sp"));
			return new ServiceProvider(req.queryParams("sp")).Authenticate();
//			return getMain();
		});

	}
	
	public static String getMain() {
		return "<form method=\"POST\">" +
				"Select Service Provider: " +
				"<select name=\"sp\">" +
				"<option value=\"egov1\">EGovernment service 1</option>" +
				"<option value=\"egov2\">EGovernment service 2</option>" +
				"<option value=\"socnet1\">Social Network 1</option>" +
				"<option value=\"socnet2\">Social Network 2</option>" +
				"<option value=\"default1\">Default 1</option>" +
				"<option value=\"default2\">Default 2</option>" +
				"<option value=\"web1\">Web Shop 1</option>" +
				"<option value=\"web2\">Web Shop 2</option>" +
				"</select>" +
				"<input type=\"submit\" value=\"Submit\" />" +
				"</form>";
						
	}

}
