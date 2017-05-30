package be.vub.serviceprovider;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import be.vub.security.CertificateAttributes;
import be.vub.security.CustomKeyPair;

public class ServiceProvider {

	private CustomKeyPair kp;
	private SecretKeySpec Ks;
	private RSAPublicKey ca;
	private String name;
	private String type;
	private byte[] attributes;
	
	
	public ServiceProvider(String serviceName){
		this.kp = CustomKeyPair.fromFile(serviceName+".ckeys");
		this.name = this.kp.getName();
		this.type = this.kp.getType();
		try{
			
			FileInputStream fi = new FileInputStream("CA.cert");
			
			// Read ca public key
			byte[] cert = new byte[160];
			fi.read(cert);
			BigInteger exp = new BigInteger(1, Arrays.copyOfRange(cert, 29, 32));
			BigInteger mod = new BigInteger(1, Arrays.copyOfRange(cert, 32, 96));
			
			RSAPublicKeySpec spec = new RSAPublicKeySpec(mod, exp);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			ca = (RSAPublicKey) factory.generatePublic(spec);
//			ca = CustomKeyPair.fromFile("CA.ckeys").getPublicKey(); // TODO fix certificate to prevent having the full key
			fi.close();
			
		} catch(Exception e) {
			System.out.println("Failed to read CA public key: " + e.getMessage());
		}

	}
	
	public String getName() {
		return name;
	}
	
	public String getType() {
		return type;
	}
	
	public byte[] getRawAttributes() {
		return attributes;
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
				    Cipher cipher2 = Cipher.getInstance("AES/CBC/NOPADDING");
				    cipher2.init(Cipher.ENCRYPT_MODE, Ks, new IvParameterSpec(new byte[16]));
				    byte[] encodedChallenge = cipher2.doFinal(challengePadded);
				    String encodedChallengeString = new String(Base64.getEncoder().encode(encodedChallenge));
				    
				    // Send challenge to card
				    HttpResponse<String> res2  = Unirest.post(Main.middelware + "authenticatespchallenge").body(encodedChallengeString).asString();
				    
				    // Card response
				    if(res2.getBody().equals("ok")) {
				    	System.out.println("Service provider authenticated");
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
	    byte[] challenge = new byte[16];
	    random.nextBytes(challenge);
	    
	    //Encrypt challenge
	    Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/NOPADDING");
			cipher.init(Cipher.ENCRYPT_MODE, Ks,  new IvParameterSpec(new byte[16]));
			byte[] encodedChallenge = cipher.doFinal(challenge);
			String encodedChallengeString = new String(Base64.getEncoder().encode(encodedChallenge));
			
			// Get response from card through middleware
			HttpResponse<String> res  = Unirest.post(Main.middelware + "authenticatecard").body(encodedChallengeString).asString();
			if(res.getBody().contains("Error")) {
				throw new Exception("From card: " +res.getBody());
			}
			byte[] message = Base64.getDecoder().decode(res.getBody());
			message = Arrays.copyOfRange(message, 0, message.length-1);
			
			// Decrypt message
			cipher.init(Cipher.DECRYPT_MODE, Ks ,  new IvParameterSpec(new byte[16])); // Card uses zero iv
			byte[] decryptedMessage = cipher.doFinal(message);
			
			byte[] certCO = Arrays.copyOfRange(decryptedMessage, 0, 160);
			byte[] signature = Arrays.copyOfRange(decryptedMessage, 160, decryptedMessage.length);
			
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(ca);
			sig.update(Arrays.copyOfRange(certCO, 0, 96));
			if(!sig.verify(Arrays.copyOfRange(certCO, 96, 160))) {
				throw new Exception("Certificate co incorrect");
			}
			
			long certValid = CertificateAttributes.bytesToLong(Arrays.copyOfRange(certCO, 21, 29));
			if(System.currentTimeMillis() > certValid) {
				throw new Exception("Certificate CO no longer valid");
			}
			
			// Build the public key in cert co
			BigInteger exp = new BigInteger(Arrays.copyOfRange(certCO, 29, 32));
			BigInteger mod = new BigInteger(Arrays.copyOfRange(certCO, 32, 96));
			RSAPublicKeySpec spec = new RSAPublicKeySpec(mod, exp);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			//RSAPublicKey pkco = (RSAPublicKey) factory.generatePublic(spec);
			RSAPublicKey pkco = CustomKeyPair.fromFile("common.ckeys").getPublicKey();
			sig.initVerify(pkco);
			
			// Create own hash of challenge
			byte[] auth = new byte[] {0x61, 0x75, 0x74, 0x68};
			byte[] challengePlusAuth = new byte[challenge.length+auth.length];
			System.arraycopy(challenge, 0, challengePlusAuth, 0, challenge.length);
			System.arraycopy(auth, 0, challengePlusAuth, challenge.length, auth.length);
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(challengePlusAuth);
			byte[] hash = md.digest();
			
			
			// Put hash into signature object
			sig.update(hash);
			if(!sig.verify(signature)) {
				throw new Exception("Signature from card incorrect");
			} 
			
			return true;
			
			
		} catch (Exception e) {
			System.out.println("Card authentication failed: " + e.getMessage());
			return false;
		}
	}
	
	
	public String getAttributes() {
		try {
			// Call to middleware
			Unirest.setTimeouts(10000, 180000); // Users have 3 minutes to answer
			String typeBt = new String(Base64.getEncoder().encode(Arrays.copyOfRange(kp.getCertificate(), 0, 21)));
			HttpResponse<String> res  = Unirest.post(Main.middelware + "queryattribute").body(typeBt).asString();
			if(res.getBody().contains("Error")) {
				String[] sps = res.getBody().split("Error");
				return "Error retrieving attributes" + sps[sps.length-1];
			}
			byte[] message = Base64.getDecoder().decode(res.getBody());
			
			Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
			cipher.init(Cipher.DECRYPT_MODE, Ks ,  new IvParameterSpec(new byte[16])); // Card uses zero iv
			byte[] decryptedMessage = cipher.doFinal(Arrays.copyOfRange(message, 0, message.length-1));
			this.attributes = decryptedMessage;
			return new String(decryptedMessage, StandardCharsets.US_ASCII);

		} catch (UnirestException e) {
			return "Error connecting to the client";
		} catch (Exception e) {
			return "Error decoding: " + e.getMessage();
		}
	}
	
}
