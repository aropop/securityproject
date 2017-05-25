
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import be.vub.security.CertificateAttributes;
import be.vub.security.MinimalCertificate;

public class ServiceProvider {

	MinimalCertificate minimalCert;
	
	public ServiceProvider(String serviceName){

		if (new File(serviceName + ".cer").isFile()){
			Path fileLocation = Paths.get(serviceName + ".cer");
			byte[] data;
			try {
				data = Files.readAllBytes(fileLocation);
				this.minimalCert = new MinimalCertificate(data);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else{
			this.minimalCert = new MinimalCertificate(new CertificateAttributes(serviceName, 365, serviceName.substring(0, serviceName.length()-1).trim()));
			this.minimalCert.sign(Main.CA);
			System.out.println(minimalCert.getEncoded());
			// write to file (or store in an other way)
		}
	}
	
	public boolean Authenticate(){
		try {
			HttpResponse<String> res  = Unirest.post(Main.middelware + "authenticatesp?cert="+minimalCert.getEncoded()).asString();
			System.out.println(res.getBody());
			if (res.getBody().contains("error")){
				return false;
			}
			else {
				//TODO decrypt key and message
				return true;
			}
		} catch (UnirestException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		
	}
	
}
