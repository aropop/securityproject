package be.vub.serviceprovider;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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

	CustomKeyPair kp;
	
	public ServiceProvider(String serviceName){
		this.kp = CustomKeyPair.fromFile(serviceName+".ckeys");

	}
	
	public boolean authenticate(){
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
					SecretKeySpec secretKeySpec = new SecretKeySpec(KsBytes, "AES");
					
					// Use ks to decrypt the challenge and the subject
					Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
				    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec ,  new IvParameterSpec(new byte[16]));
				    System.out.println(keyMessageBytes.length - 64);
				    byte[] challengeAndSubject = cipher.doFinal(Arrays.copyOfRange(keyMessageBytes, 64, keyMessageBytes.length-1));
				    byte[] challenge = Arrays.copyOfRange(challengeAndSubject, 0, 12);
				    byte[] subject = Arrays.copyOfRange(challengeAndSubject, 12, challengeAndSubject.length);
				    
				    String subjectStr = (new String(subject, StandardCharsets.US_ASCII)).trim();
				    if(!(subjectStr.equals(kp.getName()))) {
				    	throw new Exception("Names dont match: " + subjectStr + " != " + kp.getName());
				    }
				    System.out.println("Names match");
				    
				    challenge[1] = (byte) ~challenge[1];
				    byte[] challengePadded = new byte[16];
				    System.arraycopy(challenge, 0, challengePadded, 0, 12);
				    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
				    byte[] encodedChallenge = cipher.doFinal(challengePadded);
				    String encodedChallengeString = new String(Base64.getEncoder().encode(encodedChallenge));
				    
				    HttpResponse<String> res2  = Unirest.post(Main.middelware + "authenticatespchallenge").body(encodedChallengeString).asString();
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
	
}
