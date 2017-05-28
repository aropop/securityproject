package be.project.middleware;

import java.awt.Desktop;
import java.net.URI;
import java.util.Arrays;
import java.util.Base64;



public class Main {


	interface PinOperation { boolean operate(byte[] pin); }
	interface SuccessOperation { void operate(); }

	
	private static final spark.Service serv = spark.Service.ignite();
	private static final byte[] serviceType = new byte[21];
	public final static byte WEBSHOP_BYTE = 0x00;
	public final static byte DEFAULT_BYTE = 0x01;
	public final static byte SOCNET_BYTE = 0x02;
	public final static byte EGOV_BYTE = 0x03;

	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		serv.port(4570);
		final Commands cm = new Commands();
		cm.init(); // Set up communication
		cm.sendTime(); // Send the first time
	
		
		serv.post("authenticatesp", (req, res) -> {
			try {
				String cert = req.body();
				byte[] certBytes = Base64.getDecoder().decode(cert);
				
				byte[] keyAndMessage = cm.authenticateSP(certBytes);
				return Base64.getEncoder().encode(keyAndMessage);				
			} catch(Exception e) {
				return "Error: " + e.getMessage();
			}
		});
		
		serv.post("authenticatespchallenge", (req, res) -> {
			String challenge = req.body();
			byte[] challengeBytes = Base64.getDecoder().decode(challenge);
			try {
				cm.authenticateSPChallenge(challengeBytes);
				return "ok";				
			} catch(Exception e) {
				return "Error: " + e.getMessage();
			}
		});	
		
		serv.post("authenticatecard", (req, res) -> {
			String challenge = req.body();
			byte[] challengeBytes = Base64.getDecoder().decode(challenge);
			try {
				byte[] Emsg = cm.authenticateCard(challengeBytes);
				return Base64.getEncoder().encode(Emsg); 			
			} catch(Exception e) {
				return "Error: " + e.getMessage();
			}
		});
		
		serv.post("queryattribute", (req, res) -> {
			// Ask for pin asynchronously
			final PinState pinState = new PinState();
			System.arraycopy(Base64.getDecoder().decode(req.body().getBytes()), 0, serviceType, 0, 21);
			askForPin((pin) -> {
				return cm.sendPIN(pin);
			}, () -> {
				pinState.setStatus(PinState.PIN_DONE);
				try {
					byte[] Eattributes = cm.getAttributes(new byte[]{0x00,0x00});
					pinState.setData(Eattributes);
					pinState.setStatus(PinState.ATTRIBUTES_READY);
					
				} catch(Exception e) {
					System.out.println(e.getMessage());
					pinState.setStatus(PinState.ERROR);
				}
			}, () -> {
				pinState.setStatus(PinState.DENIED);
			});
			
			// Middleware waits until it is done and answers the request
			int loadAn = 1;
			while(pinState.status() != PinState.ATTRIBUTES_READY) {
				Thread.sleep(1000);
				if(PinState.ERROR == pinState.status()) {
					return "Error";
				}
				if(PinState.DENIED == pinState.status()) {
					return "Error: User denied request";
				}
				System.out.print("Waiting For pin");
				for(int i = 0; i <= loadAn; i++) {
					System.out.print(".");
				}
				System.out.print("\r");
				loadAn++;
				loadAn = loadAn % 4;
			}
			return Base64.getEncoder().encode(pinState.attributes());
		});
		
		
	}
	
	public static void askForPin(final PinOperation cont, final SuccessOperation success, final SuccessOperation deny) {
		spark.Service pinServ = spark.Service.ignite();
		final Counter tries = new Counter();
		final String[] errMessages = new String[1];
		pinServ.port(4568);
		pinServ.get("/pin", (req, res) -> ("<form method=\"POST\">" +
				(errMessages[0] == null ? "" : errMessages[0]) + "<br>" +
				"Service Provider "+ new String(Arrays.copyOf(serviceType, 20)) + " request following information of your card: " +getQueryString() + "<br>" +
				"    Tries left: " + (3 - tries.val()) + "<br />" +
				"    PIN:<input type=\"text\" name=\"pin\" pattern=\"[0-9]{4}\" maxlength=\"4\">" +
				"    <input type=\"submit\" value=\"Validate\">" +
				"</form>"+
				"<form method=\"POST\" action=\"pindeny\"><button>Deny</button></form>"));
		
		pinServ.post("/pin", (req, res) -> { 
			String pin = req.queryParams("pin");
			String[] pp = pin.split("");
			errMessages[0] = null;
			int i = 0;
			byte[] pinarr = new byte[4];
			for(String num : pp) {
				pinarr[i] = Byte.parseByte(num);
				i++;
			}
			if(cont.operate(pinarr)) {
				success.operate();
				pinServ.stop();
				return "OK<script>setTimeout(function() { window.close(); }, 2000);</script>";				
			} else {
				if(tries.val() == 3) {
					pinServ.stop();
					return "Too many tries";
				} else {
					tries.plus();
					errMessages[0] = "<div style='color:red'>Wrong Pin!</div>";
					res.redirect("/pin");
					return res;					
				}
			}
		});
		
		pinServ.post("/pindeny", (req, res) -> {
			deny.operate();
			pinServ.stop();
			return "Denied request!";
		});
		
		// Open browser
		try {
			Desktop.getDesktop().browse(new URI("http://localhost:4568/pin"));			
		} catch(Exception e ) {
			System.out.println("Opening browser failed");
		}

	}
	
	public static String getQueryString() {
		if(serviceType[20] == WEBSHOP_BYTE) {
			return "a unique identifier, full name, address and country";
		} else if(serviceType[20] == DEFAULT_BYTE) {
			return "a unique identifier and age";
		} else if(serviceType[20] == EGOV_BYTE) {
			return "a unique identifier, full name, address, country, birthdate, age and gender";
		} else if (serviceType[20] == SOCNET_BYTE) {
			return "a unique identifier, full name, country, age, gender and your picture";
		} else {
			return "";
		}
	}


}
