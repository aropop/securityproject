package be.vub.security;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

public class CertificateAttributes {

	static int name_len = 20;
	static int service_len  = 1;
	static int validatedUntil_len = 8;
	static int mod_len = 160;
	static int exp_len = 5;
	static int total_len = name_len + service_len + validatedUntil_len + mod_len + exp_len;
	
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
		
		String padded_string = new String(encoded);
		
		this.name = padded_string.substring(0, name_len).trim();
		this.service = padded_string.substring(name_len, name_len + service_len).trim();
		
		this.validatedTime = Long.parseLong(padded_string.substring(name_len + service_len, name_len + service_len + validatedUntil_len).trim());
		
		BigInteger exp = BigInteger.valueOf(Long.parseLong(padded_string.substring(name_len + service_len + validatedUntil_len, name_len + service_len + validatedUntil_len + exp_len).trim()));
		BigInteger mod = new BigInteger(padded_string.substring(name_len + service_len + validatedUntil_len + exp_len, name_len + service_len + validatedUntil_len + exp_len + mod_len).trim());
		
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
		
		String padded_name = String.format("%1$-" + name_len + "s", name);
		String padded_service = String.format("%1$-" + service_len + "s", service);
		String padded_time = String.format("%1$-" + validatedUntil_len + "s", Long.toString(validatedTime));
		
		String padded_exp =  String.format("%1$-" + exp_len + "s", public_key.getPublicExponent().toString());
		String padded_mod =  String.format("%1$-" + mod_len + "s", public_key.getModulus().toString());
		
		return (padded_name + padded_service + padded_time + padded_exp + padded_mod).getBytes(StandardCharsets.US_ASCII);
		
	}
	
	public String toString(){
		return name + "\n" + service + "\n" + Long.toString(validatedTime) + "\n" + public_key.getPublicExponent().toString() + "\n" + public_key.getModulus().toString() ;
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException {
		
		CertificateAttributes c_attr = new CertificateAttributes("Naam", 5, "Service");
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);

        KeyPair kp = kpg.genKeyPair();
        RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
        
        c_attr.public_key = pubkey;
		
		byte[] c_attr_encoded = c_attr.encode();
        
		System.out.println(c_attr);
		System.out.println("-");
		System.out.print(c_attr_encoded.length);
		System.out.print(" - ");
		System.out.println(c_attr_encoded);
		System.out.println(CertificateAttributes.total_len);
		System.out.println("-");
		CertificateAttributes c_attr_copied = new CertificateAttributes(c_attr_encoded);
		System.out.println(c_attr_copied);
		
	}
	
}
