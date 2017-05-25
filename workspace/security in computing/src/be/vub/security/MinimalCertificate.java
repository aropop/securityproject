package be.vub.security;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
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
import java.util.Arrays;
import java.util.Date;

public class MinimalCertificate extends Certificate{
	
	static Path KeyStore = Paths.get("/test");
	
	CertificateAttributes attributes;
	private RSAPublicKey pubkey;
	private RSAPrivateKey privkey;
	
	public MinimalCertificate(CertificateAttributes attributes) {
		this.attributes = attributes;
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
	        kpg.initialize(512);
	
	        KeyPair kp = kpg.genKeyPair();
	        RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
	        RSAPrivateKey privkey = (RSAPrivateKey) kp.getPrivate();
	        
	        this.pubkey = pubkey;
	        this.privkey = privkey;
	        
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			
			this.pubkey = null;
	        this.privkey = null;
		}
		
		
		
	}
	
	public MinimalCertificate(byte[] signed, RSAPublicKey pubkey) throws Exception{
		byte[] attr = Arrays.copyOfRange(signed, 0, CertificateAttributes.total_len);
		byte[] sign = Arrays.copyOfRange(signed, CertificateAttributes.total_len, signed.length);
		
		try {
			Signature rsacheck = Signature.getInstance("SHA1withRSA");
			rsacheck.initVerify(pubkey);
			rsacheck.update(attr);
			if (rsacheck.verify(sign)){
				this.attributes = new CertificateAttributes(attr);
			} else {
				throw new Exception("invalid sign");
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	
	public byte[] sign(MinimalCertificate c){
		Signature rsasign;
		try {
			rsasign = Signature.getInstance("SHA1withRSA");
//        Signature rsacheck = Signature.getInstance("SHA1withRSA");
        this.attributes.public_key = this.pubkey;
        byte[] data = c.attributes.encode();

        rsasign.initSign(this.privkey);          // Say which RSA private key to use for sign
        rsasign.update(data); // Feed data to be signed
//        rsacheck.initVerify(this.public_key);        // Say which RSA public key to use for verif
//        rsacheck.update(this.encode());// Feed data whose signature is to be checked

        byte[] signature = rsasign.sign();  // Get the signature: signature = rsa(sha1(data))
        
        byte[] full_cert = new byte[data.length + signature.length];
        System.arraycopy(data, 0, full_cert, 0, data.length);
        System.arraycopy(signature, 0, full_cert, data.length, signature.length);
        
        FileOutputStream fos = new FileOutputStream(this.attributes.name + ".cer");
        fos.write(full_cert);
        fos.close();
        
        return full_cert;
        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	public static void main(String[] args) throws Exception {
		MinimalCertificate ca;
		MinimalCertificate ct;
		
		CertificateAttributes c_attr = new CertificateAttributes("Test", 5, "Service");
		
		ca = new MinimalCertificate(c_attr);
		ct = new MinimalCertificate(ca.sign(ca), ca.pubkey);
		ct = new MinimalCertificate(ca.sign(ca), new MinimalCertificate(c_attr).pubkey);
		
		
		/*
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
		c.sign();*/
		
	}
}
