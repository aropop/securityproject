package be.vub.timeserver;

import static spark.Spark.*;
import java.io.ObjectInputStream;

import java.io.FileInputStream;
import java.io.File;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import be.vub.security.CustomKeyPair;
import java.util.Base64;
/**
 * Time server G, requires password of the keystore to be passed as the only argument
 * @author arno
 *
 */
public class TimeServer {
	
	private static final String KS_FILE = "TimeServer.ckeys";
	private static RSAPrivateKey kp;
	private static final int PORT = 4569;
	
	private static RSAPrivateKey getKey() {
		if(kp == null) {
			try {
				FileInputStream is = new FileInputStream(KS_FILE);
				ObjectInputStream ois = new ObjectInputStream(is);
				CustomKeyPair cp = (CustomKeyPair) ois.readObject();
				ois.close();
				kp = cp.getPrivateKey();
				return kp;
			} catch(Exception e) {
				System.out.println("Error occured when reading the key: "+ e.getMessage());
			}
			return null;			
		} else {
			return kp;
		}
	}

	public static void main(String[] args) { 
		port(PORT); // Set a different port than default so everything can run on the same pc
		get("/time", (req, res) -> {
			RSAPrivateKey sk = (RSAPrivateKey) getKey();
			Signature rsasign;
			try {
				rsasign = Signature.getInstance("SHA1withRSA");
				rsasign.initSign(sk);
				long time = System.currentTimeMillis();
				rsasign.update(longToBytes(time));
				byte[] sign = rsasign.sign();
				byte[] encoded = Base64.getEncoder().encode(sign);
				return new String(encoded) + "\n" + time;				
			} catch(Exception e) {
				System.out.println("error");
				return "Error:"+e.getMessage();
			}
		});

	}
	
	public static byte[] longToBytes(long x) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.putLong(x);
	    return buffer.array();
	}
	

}
