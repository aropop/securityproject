
import static spark.Spark.*;

public class Main {

	public static void main(String[] args) {
		port(4566);
		get("/", (req, res) -> {
			
			return getMain();
		});

	}
	
	public static String getMain() {
		return "<form method=\"POST\">" +
				"Select Service Provider: " +
				"<select name=\"sp\">" +
				"<item value=\"egov1\">EGovernment service 1</item>" +
				"<item value=\"egov2\">EGovernment service 2</item>" +
				"<item value=\"socnet1\">Social Network 1</item>" +
				"<item value=\"socnet2\">Social Network 2</item>" +
				"<item value=\"default1\">Default 1</item>" +
				"<item value=\"default2\">Default 2</item>" +
				"<item value=\"web1\">Web Shop 1</item>" +
				"<item value=\"web2\">Web Shop 2</item>" +
				"</select>" +
				"<input type=\"submit\" value=\"Submit\" />" +
				"</form>";
						
	}

}
