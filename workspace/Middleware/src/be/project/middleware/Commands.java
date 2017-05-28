package be.project.middleware;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;

import be.msec.client.connection.CardConnectException;
import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

public class Commands {
	
	private final static boolean simulation = true;

	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GIVE_TIME = 0x25;
	private static final byte TIME_UPDATE = 0x26;
	private static final byte AUTHENTICATE_SP = 0x27;
	private static final byte CLOSE_CONNECTION = 0x28;
	private static final byte AUTHENTICATE_RESPONSE = 0x29;
	private static final byte AUTHENTICATE_CARD = 0x30;
	private static final byte GET_ATTRIBUTES = 0x31;
	private static final byte GET_REMAINING = 0x32;
	
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private final static short SW_TIME_UPDATE_REQUIRED = 0x6302;
	private final static short SW_NOT_AUTHENTICATED = 0x6304;
	private final static short SW_CHALLENGE_WRONG = 0x6305;
	private final static short SW_UNAUTHORISED = 0X6306;
	private final static short SW_MORE_DATA = 0X6309;
	private final static short SW_CERTIFICATE_OUTDATED = 0x6310;
	
	private IConnection c;
	
	public Commands() {
		
	}

	public void init() {


		if (simulation) {
			//Simulation:
			c = new SimulatedConnection();
		} else {
			//Real Card:
			c = new Connection();
			((Connection)c).setTerminal(0); //depending on which cardreader you use
		}
		
		try {
			
			c.connect();
			
			/*
			 * For more info on the use of CommandAPDU and ResponseAPDU:
			 * See http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/spec/index.html
			 */
			
			CommandAPDU a;
			ResponseAPDU r;
			
			if (simulation) {
				//0. create applet (only for simulator!!!)
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{(byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01}, 0x7f);
				r = c.transmit(a);
				if (r.getSW()!=0x9000) throw new Exception("select installer applet failed");
				
				a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,new byte[]{0xb, 0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00, 0x00}, 0x7f);
				r = c.transmit(a);
				if (r.getSW()!=0x9000) throw new Exception("Applet creation failed");
				
				//1. Select applet  (not required on a real card, applet is selected by default)
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00}, 0x7f);
				r = c.transmit(a);
				if (r.getSW()!=0x9000) throw new Exception("Applet selection failed");
			}
		} catch (Exception e) {
			System.out.println("Something went wrong in init");
		}

	}
	
	public boolean sendPIN(byte[] pin) {
		CommandAPDU a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, pin);
		try {
			printBA(pin);
			ResponseAPDU r = c.transmit(a);
			if(r.getSW() == 0x9000) {
				System.out.println("Pin succesful");
				return true;
			}
		} catch (Exception e) {
			return false;
		}
		return false;
	}
	
	
	public void sendTime() {
		long time = System.currentTimeMillis();
		CommandAPDU a = new CommandAPDU(IDENTITY_CARD_CLA, GIVE_TIME, 0x00, 0x00, longToBytes(time));
		try {
			ResponseAPDU r = c.transmit(a);
			if(r.getSW() == SW_TIME_UPDATE_REQUIRED) {
				HttpResponse<String> res  = Unirest.get("http://localhost:4569/time").asString();
				String body = res.getBody();
				String[] split = body.split("\n");
				byte[] timeSigned = Base64.getDecoder().decode(split[0]);
				byte[] timeUnsigned = longToBytes(Long.parseLong(split[1]));
				byte[] toCard = new byte[timeSigned.length+timeUnsigned.length];
				System.arraycopy(timeUnsigned, 0, toCard, 0, timeUnsigned.length);
				System.arraycopy(timeSigned, 0, toCard, timeUnsigned.length, timeSigned.length);
				a = new CommandAPDU(IDENTITY_CARD_CLA, TIME_UPDATE, 0x00, 0x00, toCard);
				r = c.transmit(a);
				if(r.getSW() != 0x9000) {
					throw new Exception("Time Update failed: SW=" + r.getSW());
				}
			} 	
		} catch (Exception e) {
			System.out.println("Error sending time: " + e.getMessage());
		}
	}
	

	public byte[] authenticateSP(byte[] cert) throws Exception{
		CommandAPDU a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_SP, 0x00, 0x00, cert);
			ResponseAPDU r;
			try {
				r = c.transmit(a);
				if(r.getSW() == SW_VERIFICATION_FAILED) {
					throw new Exception("Verification failed");
				} else if(r.getSW() == SW_CERTIFICATE_OUTDATED) {
					throw new Exception("Certificate is outdated");
				} else if(r.getSW() == SW_MORE_DATA || r.getSW() == 0x9000) {
					return getAllData(a, r);
				}
			} catch (CardConnectException e) {
				System.out.println("Authenticate SP middleware error:" + e.getMessage());
			}
		return null;
	}
	
	public byte[] authenticateSPChallenge(byte[] encryptedChallenge) throws Exception{
		CommandAPDU a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_RESPONSE, 0x00, 0x00, encryptedChallenge);
			ResponseAPDU r;
			try {
				r = c.transmit(a);
				if(r.getSW() == SW_NOT_AUTHENTICATED) {
					throw new Exception("Not Authenticated");
				} else if (r.getSW() == SW_CHALLENGE_WRONG) {
					throw new Exception("Challenge wrong");
				} else if(r.getSW() == 0x9000) {
					return null;				
				} else {
					throw new Exception("Something else went wrong, SW:" + r.getSW());
				}
			} catch (CardConnectException e) {
				System.out.println("Card Connect Error");
			}
		return null;
	}
	
	public byte[] authenticateCard(byte[] encryptedChallenge) throws Exception{
		CommandAPDU a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_CARD, 0x00, 0x00, encryptedChallenge);
		ResponseAPDU r;
		try {
			r = c.transmit(a);
			if(r.getSW() == SW_NOT_AUTHENTICATED) {
				throw new Exception("Not Authenticated");
			} else if (r.getSW() == SW_CHALLENGE_WRONG) {
				throw new Exception("Challenge wrong");
			} else if(r.getSW() == SW_MORE_DATA || r.getSW() == 0x9000) {
				return getAllData(a, r);				
			} else {
				System.out.println(r.getSW());
			}
		} catch (CardConnectException e) {
			System.out.println("Card Connect Error");
		}
		return null;
	}
	
	public byte[] getAttributes(byte[] query) throws Exception {
		CommandAPDU a = new CommandAPDU(IDENTITY_CARD_CLA, GET_ATTRIBUTES, 0x00, 0x00, query);
		ResponseAPDU r;
		try {
			r = c.transmit(a);
			if(r.getSW() == SW_NOT_AUTHENTICATED) {
				throw new Exception("Not Authenticated");
			} else if (r.getSW() == SW_UNAUTHORISED) {
				throw new Exception("Challenge wrong");
			} else if(r.getSW() == SW_MORE_DATA || r.getSW() == 0x9000) {
				return getAllData(a, r);
			} else {
				System.out.println("SW:"+r.getSW());
			}
		} catch (CardConnectException e) {
			System.out.println("Test");
		}
		return null;
	}

	public void close() {
		try { 
			// TODO send close
			c.close();
		} catch(Exception e) {
			System.out.println("Could not close: " +  e.getMessage());
		}
	}
	
	
	private byte[] getAllData(CommandAPDU a, ResponseAPDU r) throws CardConnectException {
		byte[] current;
		byte[] sum = new byte[0];
		while(r.getSW() == SW_MORE_DATA) {
			// Get from current frame (frame is 255 bytes)
			current = r.getData();
			int offset = sum.length;
			sum = Arrays.copyOf(sum, sum.length + 255);
			int j = 0;
			for(int i = current.length-255; i < current.length; i++) {
				sum[offset + j] = current[i];
				j++;
			}			
				
			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_REMAINING, 0x00, 0x00, new byte[]{0x00, 0x00});
			r = c.transmit(a);
		}
		
		current = r.getData();
		int offset = sum.length;
		sum = Arrays.copyOf(sum, sum.length + (current.length - a.getBytes().length));
		int j = 0;
		for(int i = (a.getBytes().length + 1); i < current.length; i++) {
			sum[offset + j] = current[i];
			j++;
		}	
		
		return sum;
	}
	
	
	public static byte[] longToBytes(long x) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.putLong(x);
	    return buffer.array();
	}
	
	public static long bytesToLong(byte[] bytes) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.put(bytes);
	    buffer.flip();//need flip 
	    return buffer.getLong();
	}
	
	public static void printBA(byte[] i) {
		System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(i));
	}
	
	public static Byte[] toObjects(byte[] bytesPrim) {
	    Byte[] bytes = new Byte[bytesPrim.length];

	    int i = 0;
	    for (byte b : bytesPrim) bytes[i++] = b; // Autoboxing

	    return bytes;
	}

	public static byte[] toPrimitives(Byte[] oBytes)
	{
	    byte[] bytes = new byte[oBytes.length];

	    for(int i = 0; i < oBytes.length; i++) {
	        bytes[i] = oBytes[i];
	    }

	    return bytes;
	}
	
	
}
