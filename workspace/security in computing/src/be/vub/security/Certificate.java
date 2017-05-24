package be.vub.security;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class certificate {
	
	String Name;
	String invalid;
	PrivateKey secret_key; // used for signing
	PublicKey public_key; // stored in the certificate
	byte[] CA_cert;
	
	public certificate(String Name, int days_valid){
		Date date = new Date();
		this.invalid = String.format("%1$" + 15 + "s", String.valueOf(date.getTime() + days_valid * 24 * 60 * 60 * 1000));
		this.Name = String.format("%1$" + 100 + "s", Name);
		
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
	        kpg.initialize(512);
	
	        KeyPair kp = kpg.genKeyPair();
	        RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
	        RSAPrivateKey privkey = (RSAPrivateKey) kp.getPrivate();
	        
	        this.public_key = pubkey;
	        this.secret_key = privkey;
	        this.CA_cert = null;
	        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			
			this.public_key = null;
	        this.secret_key = null;
	        this.CA_cert = null;
		}
		
	}
	
	public certificate(String Name, int days_valid, byte[] CA, PrivateKey CA_SK){
		Date date = new Date();
		this.invalid = String.format("%1$" + 15 + "s", String.valueOf(date.getTime() + days_valid * 24 * 60 * 60 * 1000));
		this.Name = String.format("%1$" + 100 + "s", Name);
		
		this.CA_cert = CA;
		this.secret_key = CA_SK;
		
		try {
			KeyPairGenerator kpg;
			kpg = KeyPairGenerator.getInstance("RSA");
	        kpg.initialize(512);
	
	        KeyPair kp = kpg.genKeyPair();
	        RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
	        this.public_key = pubkey;
	        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			this.public_key = null;
		}
		
	}
	
	public byte[] encode(){
		byte[] current_result = (this.Name + this.invalid + this.public_key.toString()).getBytes();
		
		if (this.CA_cert != null){
			byte[] result = new byte[current_result.length + this.CA_cert.length];
			System.arraycopy(current_result, 0, result, 0, current_result.length);
			System.arraycopy(this.CA_cert, 0, result, current_result.length, this.CA_cert.length);
			
			return result;
		} else {
			return current_result;
		}
		
	}
	
	public void sign(){
		Signature rsasign;
		try {
			rsasign = Signature.getInstance("SHA1withRSA");
        Signature rsacheck = Signature.getInstance("SHA1withRSA");

        rsasign.initSign(this.secret_key);          // Say which RSA private key to use for sign
        rsasign.update(this.encode()); // Feed data to be signed
        rsacheck.initVerify(this.public_key);        // Say which RSA public key to use for verif
        rsacheck.update(this.encode());// Feed data whose signature is to be checked

        byte[] signature = rsasign.sign();  // Get the signature: signature = rsa(sha1(data))
        
        FileOutputStream fos = new FileOutputStream(this.Name + ".cer");
        fos.write(signature);
        fos.close();
        
        System.out.print(this.Name);
        System.out.println(": ");
        System.out.print("Secret key: ");
        System.out.println(this.secret_key.toString());
        System.out.print("Public key: ");
        System.out.println(this.public_key.toString());
        System.out.println(" * - - - - - - - - * ");
        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		certificate c;
		certificate ca;
		ca = new certificate("CA", 365);
		ca.sign();
		
		c = new certificate("smartcard", 365, ca.encode(), ca.secret_key);
		c.sign();
		c = new certificate("egov-ses1", 365, ca.encode(), ca.secret_key);
		c.sign();
		c = new certificate("egov-ses2", 365, ca.encode(), ca.secret_key);
		c.sign();
		c = new certificate("SocNet-ses1", 365, ca.encode(), ca.secret_key);
		c.sign();
		c = new certificate("SocNet-ses2", 365, ca.encode(), ca.secret_key);
		c.sign();
		c = new certificate("default-ses1", 365, ca.encode(), ca.secret_key);
		c.sign();
		c = new certificate("default-ses2", 365, ca.encode(), ca.secret_key);
		c.sign();
		c = new certificate("eShopping-ses1", 365, ca.encode(), ca.secret_key);
		c.sign();
		c = new certificate("eShopping-ses2", 365, ca.encode(), ca.secret_key);
		c.sign();
		
	}
}