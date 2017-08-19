/* 
 * Generates a certificate, private and public keys.
 * Establishes Connection with AWS IoT.  
 * 
 * 
 */
package capstone.tokenmgmt;


import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.UUID;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.iot.AWSIotClient;
import com.amazonaws.services.iot.client.AWSIotDevice;
import com.amazonaws.services.iot.client.AWSIotException;
import com.amazonaws.services.iot.client.AWSIotMqttClient;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateRequest;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateResult; 

public class AWSIoTConnection { 
	private AWSIotMqttClient mqttclient;
	private String clientId;
	
	//  add accessKey, Secret key & endPoint to PROPS file. 
	private final String accessKey = "AKIAJAINA5AZ2TFQ4HTQ";
	private final String secretKey = "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";
	private final String endPoint = "a31txjc29g67t9.iot.us-west-2.amazonaws.com";

	private final AWSIotClient awsIotClient = new AWSIotClient(new BasicAWSCredentials(accessKey, secretKey));
	
	public AWSIoTConnection()
	{	
		this.clientId = UUID.randomUUID().toString();	
		this.awsIotClient.withRegion(Regions.US_WEST_2);
	}
	
	public void Connect()
	{
		// Generate certificate from CertificateKeysAndResult AWS API.
		CreateKeysAndCertificateRequest ckcr = new CreateKeysAndCertificateRequest();
		ckcr.setSetAsActive(true);		
		CreateKeysAndCertificateResult keysAndCertificate = this.awsIotClient.createKeysAndCertificate(ckcr);		
		Certificate certificate = generateCertificate(keysAndCertificate.getCertificatePem()); 
		
		// Generate X.509 certificate from PEM file associated with the device generated via AWS Console.
		//Certificate certificate = generateCertificate("C:\\Users\\sweth\\Downloads\\connect_device_package (1)\\Device1.cert.pem");
		if (certificate == null)
		{
			throw new SecurityException("Could not generate certificate to connect to AWS IoT service.");
		}
		
		// Generate RSA private key from CertificateKeysAndResult AWS API
		 Key key = RsaKeyReader.readRSAKey(keysAndCertificate.getKeyPair().getPrivateKey());
		
		// Generate RSA private key from private key file associated with the device generated via AWS Console.
		// Key key = RsaKeyReader.readRSAKey("C:\\Users\\sweth\\Downloads\\connect_device_package (1)\\Device1.private.key");
		try {
			// Generate KeyStore
			String password = new BigInteger(130, new SecureRandom()).toString(32);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null);
			ks.setCertificateEntry("alias", certificate);
			ks.setKeyEntry("alias", key, password.toCharArray(), new Certificate[] { certificate });
			
			// Instantiate MQTT client & connect
			this.mqttclient = new AWSIotMqttClient(endPoint, this.clientId, ks, password);
			AWSIotDevice device = new AWSIotDevice("Device-2"); 
			this.mqttclient.attach(device);
			this.mqttclient.connect();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | AWSIotException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}    
		
	private static Certificate generateCertificate(String pemCertificate)
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
		// try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(pemCertificate))){
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            certificate = certFactory.generateCertificate(bis); //new ByteArrayInputStream(pemCertificate.getBytes()));
		} catch (IOException | CertificateException ex) {
			ex.printStackTrace();
		}
		
		return certificate;
	}
	
	 class AccessKeyPair
	{
		private KeyStore keyStore;
		private String password;
		
		public AccessKeyPair(KeyStore keyStore, String password)
		{
			if (keyStore == null || password == null)
				throw new IllegalArgumentException("Invalid credentials.");
			
			this.keyStore = keyStore;
			this.password = password;
		}
		
		public KeyStore getKeyStore(){
			return this.keyStore;
		}
		
		public String getPassword(){
			return this.password;
		}
	}
} 