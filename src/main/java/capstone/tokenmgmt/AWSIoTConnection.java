/* 
 * Generates a certificate, private and public keys.
 * Establishes Connection with AWS IoT.  
 * 
 * 
 */
package capstone.tokenmgmt;


import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
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
import java.util.ArrayList;
import java.util.Properties;
import java.util.UUID;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.iot.AWSIotClient;
import com.amazonaws.services.iot.client.AWSIotException;
import com.amazonaws.services.iot.client.AWSIotMqttClient;
import com.amazonaws.services.iot.model.AttachPrincipalPolicyRequest;
import com.amazonaws.services.iot.model.AttachThingPrincipalRequest;
import com.amazonaws.services.iot.model.CreatePolicyRequest;
import com.amazonaws.services.iot.model.CreatePolicyResult;
import com.amazonaws.services.iot.model.CreateThingRequest;
import com.amazonaws.services.iot.model.CreateThingResult;
import com.amazonaws.services.iot.model.GetPolicyRequest;
import com.amazonaws.services.iot.model.GetPolicyResult;
import com.amazonaws.services.iot.model.ResourceNotFoundException;

import capstone.tokenmgmt.X509CertificateGenerator.AwsIotGeneratedCertificate; 

public class AWSIoTConnection { 
	private ArrayList<AWSIotMqttClient> mqttclients;
	private ArrayList<String> clientIds;
	private final String policyName = "DevicePolicy";
	private final String accessKey;
	private final String secretKey;
	private final String endPoint;
	private final AWSIotClient awsIotClient;
	public AWSIoTConnection(int numberOfDevices)
	{	
		Properties properties = new Properties();
		try (InputStream is = new FileInputStream("C:\\Users\\sweth\\Desktop\\TokenManagement-master\\src\\main\\java\\capstone\\tokenmgmt\\config.properties")){
			properties.load(is);			
		}
		catch (IOException ex){
			ex.printStackTrace();
		}
		
		clientIds = new ArrayList<String>(numberOfDevices);
		mqttclients = new ArrayList<AWSIotMqttClient>(numberOfDevices);
		for (int i = 0; i < numberOfDevices; i++){
			clientIds.add(UUID.randomUUID().toString());
		}
			
		accessKey = properties.getProperty("AccessKey");
		secretKey = properties.getProperty("SecretKey");
		endPoint = properties.getProperty("ClientEndPoint");
		awsIotClient = new AWSIotClient(new BasicAWSCredentials(accessKey, secretKey)).withRegion(Regions.US_WEST_2);
	}
	
	public void Connect()
	{
		X509CertificateGenerator certificateGenerator = new X509CertificateGenerator(awsIotClient);
		AwsIotGeneratedCertificate generatedCert = certificateGenerator.readCertificateContents();
		if (generatedCert == null){
			throw new SecurityException("Could not generate certificate from AWS IoT service.");
		}
		
		// Generate X.509 certificate from PEM file associated with the device generated via AWS Console.
		Certificate certificate = X509CertificateGenerator.generateCertificate(generatedCert.getCertificatePem()); 
		if (certificate == null)
		{
			throw new SecurityException("Could not generate certificate to connect to AWS IoT service.");
		}
		
		// Generate RSA private key from CertificateKeysAndResult AWS API
		Key key = RsaKeyReader.readRSAKey(generatedCert.getPrivateKey());
		if (key == null)
		{
			throw new SecurityException("Could not generate certificate to connect to AWS IoT service.");
		}
				
		AttachPrincipalPolicyRequest policyRequest = new AttachPrincipalPolicyRequest().withPrincipal(generatedCert.getCertificateArn());				
		GetPolicyResult policyResult = null;
		try{
			policyResult = awsIotClient.getPolicy(new GetPolicyRequest().withPolicyName(policyName));
		} catch (ResourceNotFoundException ex){
			ex.printStackTrace();
		}
				
		if (policyResult == null){
			CreatePolicyResult policy = awsIotClient.createPolicy(new CreatePolicyRequest()
				.withPolicyName(policyName)
				.withPolicyDocument(readPolicy()));			
			policyRequest.setPolicyName(policy.getPolicyName());
		}
		
		else{
			policyRequest.setPolicyName(policyResult.getPolicyName());
		}
		
		awsIotClient.attachPrincipalPolicy(policyRequest);		

		for (int i = 0; i < clientIds.size(); i++){
			CreateThingResult thingResult = awsIotClient.createThing(new CreateThingRequest()
					.withThingName(clientIds.get(i)));
			
			awsIotClient.attachThingPrincipal(new AttachThingPrincipalRequest()
					.withPrincipal(generatedCert.getCertificateArn())
					.withThingName(thingResult.getThingName()));
		}
		
		
		try {
			// Generate KeyStore
			String password = new BigInteger(130, new SecureRandom()).toString(32);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null);
			ks.setCertificateEntry("alias", certificate);
			ks.setKeyEntry("alias", key, password.toCharArray(), new Certificate[] { certificate });

			for (int i = 0; i < clientIds.size(); i++){
				this.mqttclients.add(new AWSIotMqttClient(endPoint, this.clientIds.get(i), ks, password));
				this.mqttclients.get(i).connect();
			}	
			
			// Write DeviceCertificateMap to file
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | AWSIotException e) {
			e.printStackTrace();
		} 
	}    
			
	private String readPolicy(){
		StringBuilder sb = new StringBuilder();
		try (BufferedReader br= new BufferedReader(new FileReader("C:\\Users\\sweth\\Desktop\\TokenManagement-master\\src\\main\\java\\capstone\\tokenmgmt\\policy.txt"))){
			for (String line = br.readLine(); line != null; line = br.readLine())
			{
				sb.append(line + "\n");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 	
		
		return sb.deleteCharAt(sb.length()-1).toString();
	}
} 