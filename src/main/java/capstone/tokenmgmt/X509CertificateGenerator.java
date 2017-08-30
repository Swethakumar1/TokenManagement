package capstone.tokenmgmt;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import com.amazonaws.services.iot.AWSIotClient;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateRequest;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateResult;

public class X509CertificateGenerator {
	private AWSIotClient awsIotClient;
	private final String certificateContentPath = "C:\\Users\\sweth\\Desktop\\TokenManagement-master\\src\\main\\java\\capstone\\tokenmgmt\\DeviceCertificate.txt";
	
	public X509CertificateGenerator(AWSIotClient awsIotClient) {
		this.awsIotClient = awsIotClient;
	}
	
	public static Certificate generateCertificate(String pemCertificate)
	{
		if (pemCertificate == null || pemCertificate.length() == 0)
			throw new IllegalArgumentException("Empty stream. Cannot generate certificate.");
		
		Certificate certificate = null;
		
		try (BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(pemCertificate.getBytes()))){
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            certificate = certFactory.generateCertificate(bis);
		} catch (IOException | CertificateException ex) {
			ex.printStackTrace();
		}                     
		
		return certificate;
	}
	
	public AwsIotGeneratedCertificate readCertificateContents()
	{		
		StringBuilder sb = new StringBuilder();
		try (BufferedReader br= new BufferedReader(new FileReader(certificateContentPath))){
			for (String line = br.readLine(); line != null; line = br.readLine())
			{
				if (line.equals("-----BEGIN CERTIFICATE-----")){
					sb.append(line + "\n");
					continue;
				}
				sb.append(line); 	
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 

		if (sb.length() == 0){
			CreateKeysAndCertificateRequest ckcr = new CreateKeysAndCertificateRequest().withSetAsActive(true);
			CreateKeysAndCertificateResult keysAndCertificate = awsIotClient.createKeysAndCertificate(ckcr);
			writeDeviceCertificateFile(keysAndCertificate);
			return new AwsIotGeneratedCertificate(keysAndCertificate.getCertificateId(), keysAndCertificate.getCertificateArn(),
					keysAndCertificate.getCertificatePem(), keysAndCertificate.getKeyPair().getPublicKey(),
					keysAndCertificate.getKeyPair().getPrivateKey());
		}
		
		String pem = sb.substring(0, sb.indexOf("END DEVICE CERTIFICATE"));
		String publicKey = sb.substring(sb.indexOf("-----BEGIN PUBLIC KEY"), sb.indexOf("END DEVICE PUBLIC KEY"));
		String privateKey = sb.substring(sb.indexOf("-----BEGIN RSA PRIVATE KEY"), sb.indexOf("END DEVICE PRIVATE KEY"));
		String certId = sb.substring(sb.indexOf("CertificateId"), sb.indexOf(",")).split(":")[1];
		String certArn = sb.substring(sb.indexOf("CertificateArn")).split(";")[1];
		return new AwsIotGeneratedCertificate(certId, certArn, pem, publicKey, privateKey);
	}
	
	public void unregisterCertificate(){
		
	}
	
	private void writeDeviceCertificateFile(CreateKeysAndCertificateResult ckcr)
	{
		StringBuilder sb = new StringBuilder();
		sb.append(ckcr.getCertificatePem());
		sb.append("END DEVICE CERTIFICATE \n");
		sb.append(ckcr.getKeyPair().getPublicKey());
		sb.append("END DEVICE PUBLIC KEY \n");
		sb.append(ckcr.getKeyPair().getPrivateKey());
		sb.append("END DEVICE PRIVATE KEY \n");
		sb.append("CertificateId:" + ckcr.getCertificateId() + "," + "CertificateArn;" + ckcr.getCertificateArn());
		
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(certificateContentPath)))
		{
			bw.write(sb.toString());	
		} catch (IOException e) {
			e.printStackTrace();
		}
	}	

	class AwsIotGeneratedCertificate{
		private String certificateId;
		private String certificateArn;
		private String certificatePem;
		private String publicKey;
		private String privateKey;
		
		public AwsIotGeneratedCertificate(String certificateId, String certificateArn, String certificatePem, String publicKey, String privateKey){
			this.certificateId = certificateId;
			this.certificateArn = certificateArn;
			this.certificatePem = certificatePem;
			this.publicKey = publicKey;
			this.privateKey = privateKey;
		}
		
		public String getCertificateId() {
			return certificateId;
		}
	
		public String getCertificateArn() {
			return certificateArn;
		}
	
		public String getCertificatePem() {
			return certificatePem;
		}
	
		public String getPublicKey() {
			return publicKey;
		}
		
		public String getPrivateKey(){
			return privateKey;
		}
	}
}
