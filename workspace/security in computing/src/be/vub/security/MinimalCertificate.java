package be.vub.security;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;

// rewrite required.

public class MinimalCertificate extends Certificate{
	
	//static Path KeyStore = Paths.get("/test");
	
	CertificateAttributes attributes;
	private RSAPublicKey pubkey;
	private RSAPrivateKey privkey;
	private byte[] encoded;
	
	public MinimalCertificate(CertificateAttributes attributes) {
		super("Minimal");
		this.attributes = attributes;
		KeyPairGenerator kpg;
		this.encoded = null;
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
	
	public MinimalCertificate(byte[] signed){
		super("Minimal");
		byte[] attr = Arrays.copyOfRange(signed, 0, CertificateAttributes.total_len);
//		byte[] sign = Arrays.copyOfRange(signed, CertificateAttributes.total_len, signed.length);
		this.encoded = signed;
		
		/*try {
			Signature rsacheck = Signature.getInstance("SHA1withRSA");
			rsacheck.initVerify(pubkey);
			rsacheck.update(attr);
			if (rsacheck.verify(sign)){*/
				this.attributes = new CertificateAttributes(attr);
			/*} else {
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
		}*/
		
		
	}
	
	public byte[] getEncoded() {
		return this.encoded;
	}
	
	
	public void sign(MinimalCertificate c){
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
        
        c.encoded = full_cert;
        
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
	
	@Override
	public PublicKey getPublicKey() {
		// TODO Auto-generated method stub
		return this.pubkey;
	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, SignatureException {
		
		this.verify(key, "SHA1withRSA");
		
	}

	@Override
	public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException,
			InvalidKeyException, NoSuchProviderException, SignatureException {

		byte[] attr = Arrays.copyOfRange(this.encoded, 0, CertificateAttributes.total_len);
		byte[] sign = Arrays.copyOfRange(this.encoded, CertificateAttributes.total_len, this.encoded.length);
		
		Signature rsacheck = Signature.getInstance(sigProvider);
		rsacheck.initVerify(pubkey);
		rsacheck.update(attr);
		if (rsacheck.verify(sign)){
			this.attributes = new CertificateAttributes(attr);
		} else {
			throw new SignatureException("invalid sign");
		}
		
	}
	
	public void Store(MinimalCertificate C) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		KeyStore kS = KeyStore.getInstance("JKS");  
		String password = "password";
		char[] ksPass = password.toCharArray();
		kS.load(null,null);  
		Certificate[] certChain = new Certificate[1];  
		certChain[0] = C;  
		kS.setKeyEntry(this.attributes.name, (Key)this.privkey, ksPass, certChain);
		FileOutputStream writeStream = new FileOutputStream("key.store");
		kS.store(writeStream, ksPass);
	}
	
	public static void main(String[] args) throws Exception {
		MinimalCertificate ca;
		MinimalCertificate ct;
		
		CertificateAttributes c_attr = new CertificateAttributes("CA", 365, "CA");
		
		ca = new MinimalCertificate(c_attr);
		ca.sign(ca); // self signed CA
		CertificateAttributes timeServerAttributes = new CertificateAttributes("TimeServer", 365, "TimeServer");
		MinimalCertificate timeServerCert = new MinimalCertificate(timeServerAttributes);
		timeServerCert.Store(ca);
		
	}
	
}
