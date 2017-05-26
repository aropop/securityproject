package be.vub.security;

import java.math.BigInteger;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Date;

public class CertificateAttributes implements Serializable {

	private static final long serialVersionUID = 1L;
	public final static int NAME_LEN = 20;
	public final static int SERVICE_LEN  = 1;
	public final static int VALID_LEN = 8;
	public final static int EXP_LEN = 3;
	public final static int MOD_LEN = 64;
	public final static int TOTAL_LEN = NAME_LEN + SERVICE_LEN + VALID_LEN + MOD_LEN + EXP_LEN;
	public final static byte WEBSHOP_BYTE = 0x00;
	public final static byte DEFAULT_BYTE = 0x01;
	public final static byte SOCNET_BYTE = 0x02;
	public final static byte EGOV_BYTE = 0x03;
	public final static byte SPECIAL_BYTE = 0x10;
	
	String name;
	long validatedTime;
	String service;
	RSAPublicKey public_key;
	
	public CertificateAttributes(String name, int days_valid, String service){
		this.name = name;
		this.validatedTime = new Date().getTime() + days_valid * 24 * 60 * 60 * 1000;
		this.service = service;
	}
	
	public CertificateAttributes(byte[] encoded){
		this.decode(encoded);
	}
	
	private void decode(byte[] encoded){
		// TODO change to match endocidng
		String paddedStringName = new String(Arrays.copyOfRange(encoded, 0, NAME_LEN));
		this.name = paddedStringName.substring(0, NAME_LEN).trim();
		
		if(encoded[NAME_LEN] == WEBSHOP_BYTE) {
			this.service = "webshop";
		} else if(encoded[NAME_LEN] == DEFAULT_BYTE) {
			this.service = "default";
		} else if(encoded[NAME_LEN] == EGOV_BYTE) {
			this.service = "egov";
		} else if (encoded[NAME_LEN] == SOCNET_BYTE) {
			this.service = "socnet";
		} else {
			this.service = "special";
		}
		
		this.validatedTime = bytesToLong(Arrays.copyOfRange(encoded, NAME_LEN+SERVICE_LEN, VALID_LEN));
		
		BigInteger exp = new BigInteger(Arrays.copyOfRange(encoded, NAME_LEN+SERVICE_LEN+VALID_LEN, EXP_LEN));
		BigInteger mod = new BigInteger(Arrays.copyOfRange(encoded, NAME_LEN+SERVICE_LEN+VALID_LEN+EXP_LEN, MOD_LEN));
		
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
		
		KeyFactory fact;
		try {
			fact = KeyFactory.getInstance("RSA");
			this.public_key = (RSAPublicKey) fact.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public byte[] encode(){
		byte[] encoded = new byte[TOTAL_LEN];
		String padded_name = String.format("%1$-" + NAME_LEN + "s", name);
		byte[] serviceByte = new byte[SERVICE_LEN];
		if(service.equals("webshop")) {
			serviceByte[0] = WEBSHOP_BYTE;
		} else if(service.equals("egov")) {
			serviceByte[0] = EGOV_BYTE;
		} else if(service.equals("socnet")) {
			serviceByte[0] = SOCNET_BYTE;
		} else if(service.equals("default")) {
			serviceByte[0] = DEFAULT_BYTE;
		} else {
			serviceByte[0] = SPECIAL_BYTE;
		}
		
		byte[] validBytes = longToBytes(validatedTime);		
		byte[] expBytes =  public_key.getPublicExponent().toByteArray();
		byte[] modBytes  =  public_key.getModulus().toByteArray();
		
		System.arraycopy(padded_name.getBytes(StandardCharsets.US_ASCII), 0, encoded, 0, NAME_LEN);
		System.arraycopy(serviceByte, 0, encoded, NAME_LEN, SERVICE_LEN);
		System.arraycopy(validBytes, 0, encoded, NAME_LEN + SERVICE_LEN, VALID_LEN);
		System.arraycopy(expBytes, 0, encoded, NAME_LEN + SERVICE_LEN + VALID_LEN, EXP_LEN);
		System.arraycopy(modBytes, 1, encoded, NAME_LEN + SERVICE_LEN + VALID_LEN +EXP_LEN, MOD_LEN);
		
		
		return encoded;
		
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
	
	public String toString(){
		return name + "\n" + service + "\n" + Long.toString(validatedTime) + "\n" + public_key.getPublicExponent().toString() + "\n" + public_key.getModulus().toString() ;
	}
	
//	public static void main(String[] args) throws NoSuchAlgorithmException {
//		
//		CertificateAttributes c_attr = new CertificateAttributes("Naam", 5, "Service");
//		
//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(512);
//
//        KeyPair kp = kpg.genKeyPair();
//        RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
//        
//        c_attr.public_key = pubkey;
//		
//		byte[] c_attr_encoded = c_attr.encode();
//        
//		System.out.println(c_attr);
//		System.out.println("-");
//		System.out.print(c_attr_encoded.length);
//		System.out.print(" - ");
//		System.out.println(c_attr_encoded);
//		System.out.println(CertificateAttributes.TOTAL_LEN);
//		System.out.println("-");
//		CertificateAttributes c_attr_copied = new CertificateAttributes(c_attr_encoded);
//		System.out.println(c_attr_copied);
//		
//	}
	
}
