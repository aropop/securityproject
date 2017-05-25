package be.project.middleware;

import java.awt.Desktop;
import java.net.URI;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;

import spark.Spark;

public class Main {


	interface PinOperation { boolean operate(byte[] pin); }
	interface SuccessOperation { void operate(); }

	
	private static final spark.Service serv = spark.Service.ignite();
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		final Commands cm = new Commands();
		//cm.init();
		
		try{
			HttpResponse<String> res  = Unirest.get("http://localhost:4569/time").asString();
			System.out.println(res.getBody());
			System.out.println(res.getStatusText());
		} catch(Exception e) {
			System.out.println(e.getMessage());
		}
		//cm.debug();
		
		
		serv.post("authenticatesp", (req, res) -> {
			String cert = req.queryParams("cert");
			byte[] certBytes = cert.getBytes();
			try {
				byte[] keyAndMessage = cm.authenticateSP(certBytes);
				return keyAndMessage.toString();				
			} catch(Exception e) {
				return "Error: " + e.getMessage();
			}
		});
		
		serv.post("authenticatespchallenge", (req, res) -> {
			String challenge = req.queryParams("challenge");
			byte[] challengeBytes = challenge.getBytes();
			try {
				cm.authenticateSPChallenge(challengeBytes);
				return "ok";				
			} catch(Exception e) {
				return "Error: " + e.getMessage();
			}
		});	
		
		serv.post("authenticatecard", (req, res) -> {
			String challenge = req.queryParams("challenge");
			byte[] challengeBytes = challenge.getBytes();
			try {
				byte[] Emsg = cm.authenticateCard(challengeBytes);
				return Emsg; // TODO gaat niet werken				
			} catch(Exception e) {
				return "Error: " + e.getMessage();
			}
		});
		
		serv.post("queryattribute", (req, res) -> {
			final PinState pinState = new PinState();
			askForPin((pin) -> {
				return cm.sendPIN(pin);
			}, () -> {
				pinState.setStatus(PinState.PIN_DONE);
				try {
					byte[] Eattributes = cm.getAttributes(req.queryParams("query").getBytes());
					pinState.setData(Eattributes);
					pinState.setStatus(PinState.ATTRIBUTES_READY);
					
				} catch(Exception e) {
					pinState.setStatus(PinState.ERROR);
				}
			});
			
			int loadAn = 1;
			while(pinState.status() != PinState.ATTRIBUTES_READY) {
				Thread.sleep(1000);
				System.out.print("Waiting For pin");
				for(int i = 0; i <= loadAn; i++) {
					System.out.print(".");
				}
				if(PinState.ERROR == pinState.status()) {
					return "Error";
				}
				System.out.print("\r");
				loadAn++;
				loadAn = loadAn % 4;
			}
			return pinState.attributes();
		});
		
		
	}
	
	public static void askForPin(final PinOperation cont, final SuccessOperation success) {
		spark.Service pinServ = spark.Service.ignite();
		final Counter tries = new Counter();
		pinServ.port(4568);
		pinServ.get("/pin", (req, res) -> ("<form method=\"POST\">" +
				"    Tries left: " + (3 - tries.val()) + "<br />" +
				"    PIN:<input type=\"text\" name=\"pin\" pattern=\"[0-9]{4}\" maxlength=\"4\">" +
				"    <input type=\"submit\" value=\"Validate\">" +
				"</form>"));
		
		pinServ.post("/pin", (req, res) -> { // TODO pin wrong
			String pin = req.queryParams("pin");
			String[] pp = pin.split("");
			int i = 0;
			byte[] pinarr = new byte[4];
			for(String num : pp) {
				pinarr[i] = Byte.parseByte(num);
				i++;
			}
			if(cont.operate(pinarr)) {
				pinServ.stop();
				success.operate();
				return "OK";				
			} else {
				if(tries.val() == 3) {
					pinServ.stop();
					return "Too many tries";
				} else {
					tries.plus();
					res.redirect("/pin");
					return res;					
				}
			}
		});
		
		// Open browser
		try {
			Desktop.getDesktop().browse(new URI("http://localhost:4568/pin"));			
		} catch(Exception e ) {
			System.out.println("Opening browser failed");
		}

	}


}
