package be.vub.security;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class CertificateAttributes {

	static int name_len = 20;
	static int service_len  = 20;
	static int validatedUntil_len = 15;
	static int mod_len = 160;
	static int exp_len = 5;
	
	String name;
	long validatedTime;
	String service;
	RSAPublicKey public_key;
	
	public CertificateAttributes(){
		
	}
	
	public CertificateAttributes(byte[] encoded){
		this.decode(encoded);
	}
	
	private void decode(byte[] encoded){
		this.name = Arrays.copyOfRange(encoded, 0, name_len).toString().trim();
		this.service = Arrays.copyOfRange(encoded, name_len, name_len + service_len).toString().trim();
		this.validatedTime = Long.parseLong(Arrays.copyOfRange(encoded, name_len + service_len, name_len + service_len + validatedUntil_len).toString().trim());
		
		BigInteger exp = BigInteger.valueOf(Long.parseLong(Arrays.copyOfRange(encoded, name_len + service_len + validatedUntil_len, name_len + service_len + validatedUntil_len + exp_len).toString().trim()));
		BigInteger modulus = BigInteger.valueOf(Long.parseLong(Arrays.copyOfRange(encoded, name_len + service_len + validatedUntil_len + exp_len, name_len + service_len + validatedUntil_len + exp_len + mod_len ).toString().trim()));
	}
	
	public byte[] encode(){
		
		String padded_name = String.format("%1$-" + name_len + "s", name);
		String padded_service = String.format("%1$-" + service_len + "s", service);
		String padded_time = String.format("%1$-" + validatedUntil_len + "s", Long.toString(validatedTime));
		
		String padded_exp =  String.format("%1$-" + exp_len + "s", public_key.getPublicExponent().toString());
		String padded_mod =  String.format("%1$-" + mod_len + "s", public_key.getModulus().toString());
		
		return (padded_name + padded_service + padded_time + padded_exp + padded_mod).getBytes();
		
	}
	
}
