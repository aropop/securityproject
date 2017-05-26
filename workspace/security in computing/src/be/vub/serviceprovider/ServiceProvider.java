package be.vub.serviceprovider;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.util.Base64;

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
			System.out.println(res.getBody());
			if (res.getBody().contains("Error")){
				return false;
			}
			else {
				System.out.println("Noerror jaj!");
				return true;
			}
		} catch (UnirestException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		
	}
	
}
