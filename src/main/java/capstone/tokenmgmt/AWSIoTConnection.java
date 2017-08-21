/* 
 * Generates a certificate, private and public keys.
 * Establishes Connection with AWS IoT.  
 * 
 * 
 */
package capstone.tokenmgmt;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
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
	private final String accessKey;
	private final String secretKey;
	private final String endPoint;
	private final AWSIotClient awsIotClient;
	private HashMap<String, String> deviceCertificateMap;
	
	public AWSIoTConnection()
	{	
		Properties properties = new Properties();
		try (InputStream is = new FileInputStream("config.properties")){
			properties.load(is);			
		}
		catch (IOException ex){
			ex.printStackTrace();
		}
		
		accessKey = properties.getProperty("AccessKey");
		secretKey = properties.getProperty("SecretKey");
		endPoint = properties.getProperty("ClientEndPoint");
		awsIotClient = new AWSIotClient(new BasicAWSCredentials(accessKey, secretKey)).withRegion(Regions.US_WEST_2);
		clientId = UUID.randomUUID().toString();
		
		// TODO: Read from the Client Certificate mapping file & populate HashMap.
		deviceCertificateMap = new HashMap<String, String>();
	}
	
	public void Connect()
	{
		CreateKeysAndCertificateRequest ckcr = new CreateKeysAndCertificateRequest().withSetAsActive(true);
		CreateKeysAndCertificateResult keysAndCertificate = deviceCertificateMap.containsKey(clientId) 
				? awsIotClient.createKeysAndCertificate(ckcr).withCertificateId(deviceCertificateMap.get(clientId))
				: awsIotClient.createKeysAndCertificate(ckcr);
		
		if (!deviceCertificateMap.containsKey(clientId)){
			deviceCertificateMap.put(clientId, keysAndCertificate.getCertificateId());
		}
		
		// Generate X.509 certificate from PEM file associated with the device generated via AWS Console.
		Certificate certificate = X509Certificate.generateCertificate(keysAndCertificate.getCertificatePem()); 
		if (certificate == null)
		{
			throw new SecurityException("Could not generate certificate to connect to AWS IoT service.");
		}
		
		// Generate RSA private key from CertificateKeysAndResult AWS API
		Key key = RsaKeyReader.readRSAKey(keysAndCertificate.getKeyPair().getPrivateKey());
		if (key == null)
		{
			throw new SecurityException("Could not generate certificate to connect to AWS IoT service.");
		}
		
		try {
			// Generate KeyStore
			String password = new BigInteger(130, new SecureRandom()).toString(32);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null);
			ks.setCertificateEntry("alias", certificate);
			ks.setKeyEntry("alias", key, password.toCharArray(), new Certificate[] { certificate });

			this.mqttclient = new AWSIotMqttClient(endPoint, this.clientId, ks, password);

			// Attach a device to MQTT client.
			AWSIotDevice device = new AWSIotDevice("Device-2"); 
			this.mqttclient.attach(device);
			
			// Attach a policy to MQTT client.
			
			this.mqttclient.connect();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | AWSIotException e) {
			e.printStackTrace();
		} 
	}    
			
	private void readFromFile(String filePath)
	{
		Map<String,String> certificateTable=new HashMap<String,String>();
		try (BufferedReader br= new BufferedReader(new FileReader(filePath))){
			for (String line = br.readLine(); line != null; line = br.readLine())
			{
				String[] data=line.split(","); 
				certificateTable.put(data[0],data[1]); 	
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
	}
	
	private void writeToFile(String filePath, HashMap<String,String> certificateTable)
	{
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(filePath)))
		{
			for(Map.Entry<String,String> entry: certificateTable.entrySet())
			{
				bw.write(entry.getKey());
				bw.append(",");
				bw.write(entry.getValue());
				bw.append("\n");
			}
				
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	
	
} 