package be.vub.security;

import java.io.Serializable;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.FileInputStream;

// rewrite required.

public class CustomKeyPair implements Serializable {
	
	private static final long serialVersionUID = 1L;

	
	CertificateAttributes attributes;
	private RSAPublicKey pubkey;
	private RSAPrivateKey privkey;
	
	private CustomKeyPair ca; // Certificate authority
	
	public CustomKeyPair(CertificateAttributes attributes) {
		this.attributes = attributes;
		KeyPairGenerator kpg;
		this.ca = null;
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
	
	// Encodes the certificate itself
	public byte[] getCertificate(){
		Signature rsasign;
		try {
			rsasign = Signature.getInstance("SHA1withRSA");
	        this.attributes.public_key = this.pubkey;
	        byte[] data = this.attributes.encode();
	
	        if(ca == null) {
	        	rsasign.initSign(this.privkey); // Self sign       	
	        } else {
	        	rsasign.initSign(this.ca.getPrivateKey()); // Sign by authority
	        }
	        System.out.println(data.length);
	        rsasign.update(data); // Feed data to be signed
	        byte[] signature = rsasign.sign();  // Get the signature: signature = rsa(sha1(data))
	        byte[] full_cert = new byte[data.length + signature.length];
	        System.arraycopy(data, 0, full_cert, 0, data.length);
	        System.arraycopy(signature, 0, full_cert, data.length, signature.length);
	        
	        return full_cert;
        
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
		return null;
	}
	
	public static boolean verifyCert(byte[] certBytes, RSAPublicKey pk) {
		byte[] attr = Arrays.copyOfRange(certBytes, 0, CertificateAttributes.TOTAL_LEN);
		byte[] sign = Arrays.copyOfRange(certBytes, CertificateAttributes.TOTAL_LEN, certBytes.length);
		
		try {
			Signature rsacheck = Signature.getInstance("SHA1withRSA");
			rsacheck.initVerify(pk);
			rsacheck.update(attr);
			return rsacheck.verify(sign);
		} catch (Exception e) {
			System.out.println("Something went wrong verify sign: " + e.getMessage());
		} 
		return false;
	}
	
	/**
	 * Signs data with its private key
	 * @param data
	 * @return
	 */
	public byte[] sign(byte[] data) {
		Signature rsasign;
		try {
			rsasign = Signature.getInstance("SHA1withRSA");
			rsasign.initSign(this.privkey);          // Say which RSA private key to use for sign
			rsasign.update(data); // Feed data to be signed
			return rsasign.sign();			
		} catch(Exception e) {
			System.out.println("Sign failed: "+ e.getMessage());
			return null;
		}
	}
	
	public RSAPrivateKey getPrivateKey() {
		return this.privkey;
	}
	
	public RSAPublicKey getPublicKey() {
		return this.pubkey;
	}
	
	public void setCertificateAuthority(CustomKeyPair ca) {
		this.ca = ca;
	}
	
	public void store() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		
	}
	
	public String getName() {
		return this.attributes.name;
	}
	
	public static CustomKeyPair issue(String name, String type, CustomKeyPair ca) {
		CertificateAttributes attributes = new CertificateAttributes(name, 365, type);
		CustomKeyPair kp = new CustomKeyPair(attributes);
		kp.setCertificateAuthority(ca);
		return kp;
	}
	
	public static void writeToFile(String fn, CustomKeyPair c) {
		FileOutputStream fo;
		FileOutputStream fo2;
		try {
			fo = new FileOutputStream(fn + ".ckeys");
			fo2 = new FileOutputStream(fn + ".cert");
			ObjectOutputStream oo = new ObjectOutputStream(fo);
			oo.writeObject(c);
			fo2.write(c.getCertificate());
			oo.close();
			fo2.close();
		} catch(Exception e) {
			System.out.println("Write to file failed: " + e.getMessage());
		} 
	}
	
	public static CustomKeyPair fromFile(String fn) {
		FileInputStream fo;
		try {
			fo = new FileInputStream(fn);
			ObjectInputStream oo = new ObjectInputStream(fo);
			CustomKeyPair ckp = (CustomKeyPair) oo.readObject();
			oo.close();
			return ckp;
		} catch(Exception e) {
			System.out.println("Read from file failed: " + e.getMessage());
		}
		return null;
	}
	
	public static void printBA(byte[] i) {
		System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(i));
	}
	
	public static void generateKeys() {
		CertificateAttributes c_attr = new CertificateAttributes("CA", 365, "CA");
		CustomKeyPair ca = new CustomKeyPair(c_attr);
		
		
		CertificateAttributes timeServerAttributes = new CertificateAttributes("TimeServer", 365, "TimeServer");
		CustomKeyPair timeServerKeys = new CustomKeyPair(timeServerAttributes);
		timeServerKeys.setCertificateAuthority(ca);
		
		CertificateAttributes commonAttributes = new CertificateAttributes("common", 365, "common");
		CustomKeyPair commonKeys = new CustomKeyPair(commonAttributes);
		commonKeys.setCertificateAuthority(ca);
		
		CustomKeyPair egov1 = issue("Egov1", "egov", ca);
		CustomKeyPair egov2 = issue("Egov2", "egov", ca);
		CustomKeyPair socnet1 = issue("SocNet1", "socnet", ca);
		CustomKeyPair socnet2 = issue("SocNet2", "socnet", ca);
		CustomKeyPair default1 = issue("Default1", "default", ca);
		CustomKeyPair default2 = issue("Default2", "default", ca);
		CustomKeyPair webshop1 = issue("Webshop1", "webshop", ca);
		CustomKeyPair webshop2 = issue("Webshop2", "webshop", ca);
		
		writeToFile("CA", ca);
		writeToFile("TimeServer", timeServerKeys);
		writeToFile("common", commonKeys);
		writeToFile("Egov1", egov1);
		writeToFile("Egov2", egov2);
		writeToFile("SocNet1", socnet1);
		writeToFile("SocNet2", socnet2);
		writeToFile("Default1", default1);
		writeToFile("Default2", default2);
		writeToFile("Webshop1", webshop1);
		writeToFile("Webshop2", webshop2);
	}
	
	public static void main(String[] args) { 
//		CustomKeyPair cp = fromFile("common.ckeys");
//		BigInteger modulus = cp.getPrivateKey().getModulus();
//		BigInteger exponent = cp.getPrivateKey().getPrivateExponent();
//		System.out.println(modulus.toByteArray().length);
//		System.out.println(exponent);
//		for(byte b : modulus.toByteArray()) {
//			System.out.print("(byte) ");
//			System.out.print(b);
//			System.out.print(", ");
//		}
//		System.out.print("\n");
//		for(byte b : exponent.toByteArray()) {
//			System.out.print("(byte) ");
//			System.out.print(b);
//			System.out.print(", ");
//		}
//		System.out.print("\n");
//		for(byte b : cp.getCertificate()) {
//			System.out.print("(byte) ");
//			System.out.print(b);
//			System.out.print(", ");
//		}
//		System.out.print("\n");
//		printBA(modulus.toByteArray());
//		printBA(exponent.toByteArray());
//		System.out.println(cp.getCertificate().length);
//		System.out.println(verifyCert(cp.getCertificate(), fromFile("CA.ckeys").getPublicKey()));
		
	}
	
}
