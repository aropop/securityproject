package be.vub.serviceprovider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import be.vub.security.CertificateAttributes;
import be.vub.security.CustomKeyPair;

public class ServiceProvider {

	CustomKeyPair kp;
	SecretKeySpec Ks;
	RSAPublicKey ca;
	
	public ServiceProvider(String serviceName){
		this.kp = CustomKeyPair.fromFile(serviceName+".ckeys");
		try{
			FileInputStream fi = new FileInputStream("ca.cert");
			
			// Read ca public key
			byte[] cert = new byte[160];
			fi.read(cert);
			BigInteger exp = new BigInteger(Arrays.copyOfRange(cert, 29, 32));
			BigInteger mod = new BigInteger(Arrays.copyOfRange(cert, 32, 96));
			RSAPublicKeySpec spec = new RSAPublicKeySpec(mod, exp);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			ca = (RSAPublicKey) factory.generatePublic(spec);

		} catch(Exception e) {
			System.out.println("Failed to read CA public key: " + e.getMessage());
		}

	}
	
	public boolean authenticateServiceProvider(){
		try {
			byte[] cert = kp.getCertificate();
			String certStr = new String(Base64.getEncoder().encode(cert));
			HttpResponse<String> res  = Unirest.post(Main.middelware + "authenticatesp").body(certStr).asString();
			if (res.getBody().contains("Error")){
				System.out.println("Got error: " + res.getBody());
				return false;
			} else {
				// Decode base 64 encoding for transferring in http
				byte[] keyMessageBytes = Base64.getDecoder().decode(res.getBody());
				try {
					// Decript symmetric key
					Cipher decrypt=  Cipher.getInstance("RSA");
					decrypt.init(Cipher.DECRYPT_MODE, kp.getPrivateKey());
					byte[] KsBytes = decrypt.doFinal(Arrays.copyOfRange(keyMessageBytes, 0, 64));	
					Ks = new SecretKeySpec(KsBytes, "AES");
					
					// Use ks to decrypt the challenge and the subject
					Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
				    cipher.init(Cipher.DECRYPT_MODE, Ks ,  new IvParameterSpec(new byte[16])); // Card uses zero iv
				    byte[] challengeAndSubject = cipher.doFinal(Arrays.copyOfRange(keyMessageBytes, 64, keyMessageBytes.length-1));
				    
				    // Extract challenge and subject
				    byte[] challenge = Arrays.copyOfRange(challengeAndSubject, 0, 12);
				    byte[] subject = Arrays.copyOfRange(challengeAndSubject, 12, challengeAndSubject.length);
				    
				    // Check if subject is the same
				    String subjectStr = (new String(subject, StandardCharsets.US_ASCII)).trim();
				    if(!(subjectStr.equals(kp.getName()))) {
				    	throw new Exception("Names dont match: " + subjectStr + " != " + kp.getName());
				    }
				    System.out.println("Names match");
				    
				    // Do challenge + 1 -> we just flip second byte since adding is hard on the card
				    challenge[1] = (byte) ~challenge[1];
				    byte[] challengePadded = new byte[16];
				    System.arraycopy(challenge, 0, challengePadded, 0, 12); // Pad to get 16 bytes
				    
				    // Encrypt challenge
				    cipher.init(Cipher.ENCRYPT_MODE, Ks);
				    byte[] encodedChallenge = cipher.doFinal(challengePadded);
				    String encodedChallengeString = new String(Base64.getEncoder().encode(encodedChallenge));
				    
				    // Send challenge to card
				    HttpResponse<String> res2  = Unirest.post(Main.middelware + "authenticatespchallenge").body(encodedChallengeString).asString();
				    
				    // Card response
				    if(res2.getBody().equals("ok")) {
				    	return true;
				    } else {
				    	System.out.println(res2.getBody());
				    	return false;
				    }
				}catch (Exception e) {
					System.out.println("Error on authenticate:" + e.getMessage());
					return false;
				}
			}
		} catch (UnirestException e) {
			System.out.println("REST exception: " + e.getMessage());
			return false;
		}
		
	}
	
	public boolean authenticateCard() {
		// Generate challenge
		SecureRandom random = new SecureRandom();
	    byte[] challenge = new byte[16];158
	    random.nextBytes(challenge);
	    
	    //Encrypt challenge
	    Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/NOPADDING");
			cipher.init(Cipher.ENCRYPT_MODE, Ks);
			byte[] encodedChallenge = cipher.doFinal(challenge);
			String encodedChallengeString = new String(Base64.getEncoder().encode(encodedChallenge));
			
			// Get response from card through middleware
			HttpResponse<String> res  = Unirest.post(Main.middelware + "authenticatecard").body(encodedChallengeString).asString();
			byte[] message = Base64.getDecoder().decode(res.getBody());
			
			// Decrypt message
			cipher.init(Cipher.DECRYPT_MODE, Ks ,  new IvParameterSpec(new byte[16])); // Card uses zero iv
			byte[] decryptedMessage = cipher.doFinal(message);
			
			byte[] certCO = Arrays.copyOfRange(decryptedMessage, 0, 160);
			byte[] signature = Arrays.copyOfRange(decryptedMessage, 160, decryptedMessage.length);
			
			// Verify cert TODO: check validation date
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(ca);
			sig.update(Arrays.copyOfRange(certCO, 0, 96));
			if(!sig.verify(Arrays.copyOfRange(certCO, 96, 160))) {
				throw new Exception("Certificate co incorrect");
			}
			
			// Build the public key in cert co
			BigInteger exp = new BigInteger(Arrays.copyOfRange(certCO, 29, 32));
			BigInteger mod = new BigInteger(Arrays.copyOfRange(certCO, 32, 96));
			RSAPublicKeySpec spec = new RSAPublicKeySpec(mod, exp);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			RSAPublicKey pkco = (RSAPublicKey) factory.generatePublic(spec);
			sig.initVerify(pkco);
			
			// Put hash into signature object
			sig.update();
			if(!sig.verify(signature)) {
				throw new Exception("Signature from card incorrect");
			}
			
			
		} catch (Exception e) {
			System.out.println("Card authentication failed: " + e.getMessage());
		}
	    
	    
		return true;
	}
	
}
