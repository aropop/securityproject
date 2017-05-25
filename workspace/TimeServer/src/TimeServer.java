
import static spark.Spark.*;

import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
/**
 * Time server G, requires password of the keystore to be passed as the only argument
 * @author arno
 *
 */
public class TimeServer {
	
	private static final String KS_FILE = "../../g.jks";
	private static Key kp;
	private static final int PORT = 4569;
	private static String password;
	
	private static Key getKey() {
		if(kp == null) {
			try {
				KeyStore keyStore = KeyStore.getInstance("JKS");
				FileInputStream is = new FileInputStream(KS_FILE);
				keyStore.load(is, password.toCharArray());
				is.close();
				return keyStore.getKey("skg", password.toCharArray());
			} catch(Exception e) {
				System.out.println("Error occured when reading the key");
			}
			return null;			
		} else {
			return kp;
		}
	}

	public static void main(String[] args) { 
		password = args[0];
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
