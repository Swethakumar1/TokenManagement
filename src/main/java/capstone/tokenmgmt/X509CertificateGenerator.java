package capstone.tokenmgmt;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class X509CertificateGenerator {

	public X509CertificateGenerator() {
		// TODO Auto-generated constructor stub
	}
	
	public static Certificate generateCertificate(String pemCertificate)
	{
		if (pemCertificate == null || pemCertificate.length() == 0)
			throw new IllegalArgumentException("Empty stream. Cannot generate certificate.");
		
		Certificate certificate = null;
		
		File temp = null;
		try{
			temp = File.createTempFile("temp", Long.toString(System.nanoTime()));
		}
		catch (IOException ex){
			ex.printStackTrace();
		}
		
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(temp.getAbsolutePath()))){
			bw.write(pemCertificate);
		} catch(IOException ex){
			ex.printStackTrace();
		}
		
		try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(temp.getAbsolutePath()))){
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            certificate = certFactory.generateCertificate(bis);
		} catch (IOException | CertificateException ex) {
			ex.printStackTrace();
		}
		
		return certificate;
	}

}
