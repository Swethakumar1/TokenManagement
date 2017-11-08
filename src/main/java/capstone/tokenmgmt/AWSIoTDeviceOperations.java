package capstone.tokenmgmt;

import java.io.FileInputStream;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.iot.AWSIot;
import com.amazonaws.services.iot.AWSIotClient;
import com.amazonaws.services.iot.client.AWSIotException;
import com.amazonaws.services.iot.client.AWSIotMqttClient;
import com.amazonaws.services.iot.client.AWSIotQos;
import com.amazonaws.services.iot.client.AWSIotTimeoutException;
import com.amazonaws.services.iot.client.AWSIotTopic;
import com.amazonaws.services.iot.model.AttachPrincipalPolicyRequest;
import com.amazonaws.services.iot.model.AttachThingPrincipalRequest;
import com.amazonaws.services.iot.model.CertificateStatus;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateRequest;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateResult;
import com.amazonaws.services.iot.model.CreatePolicyRequest;
import com.amazonaws.services.iot.model.CreatePolicyResult;
import com.amazonaws.services.iot.model.CreatePolicyVersionRequest;
import com.amazonaws.services.iot.model.CreatePolicyVersionResult;
import com.amazonaws.services.iot.model.CreateThingRequest;
import com.amazonaws.services.iot.model.CreateThingResult;
import com.amazonaws.services.iot.model.DeletePolicyVersionRequest;
import com.amazonaws.services.iot.model.DeletePolicyVersionResult;
import com.amazonaws.services.iot.model.DeleteThingRequest;
import com.amazonaws.services.iot.model.DescribeThingRequest;
import com.amazonaws.services.iot.model.DescribeThingResult;
import com.amazonaws.services.iot.model.DetachPrincipalPolicyRequest;
import com.amazonaws.services.iot.model.DetachThingPrincipalRequest;
import com.amazonaws.services.iot.model.GetPolicyRequest;
import com.amazonaws.services.iot.model.GetPolicyResult;
import com.amazonaws.services.iot.model.ListPolicyVersionsRequest;
import com.amazonaws.services.iot.model.ListPolicyVersionsResult;
import com.amazonaws.services.iot.model.ListPrincipalThingsRequest;
import com.amazonaws.services.iot.model.ListPrincipalThingsResult;
import com.amazonaws.services.iot.model.PolicyVersion;
import com.amazonaws.services.iot.model.ResourceNotFoundException;
import com.amazonaws.services.iot.model.UpdateCertificateRequest;
import com.amazonaws.services.iot.model.UpdateCertificateResult;

public class AWSIoTDeviceOperations {
	private final String accessKey;
	private final String secretKey;
	private final String endPoint;
	private final AWSIot awsIotClient;
	private final long timeout = 15000;

	private PolicyManagement pmanage;
	private HashMap<String, AWSIotMqttClient> mqttClientMap;

	public AWSIoTDeviceOperations(){
		Properties properties = new Properties();
		try (InputStream is = new FileInputStream("C:\\Users\\sweth\\Desktop\\TokenManagement-master\\src\\main\\java\\capstone\\tokenmgmt\\config.properties")){
			properties.load(is);			
		}
		catch (IOException ex){
			ex.printStackTrace();
		}
		
		accessKey = properties.getProperty("AccessKey");
		secretKey = properties.getProperty("SecretKey");
		endPoint = properties.getProperty("ClientEndPoint");
		awsIotClient = AWSIotClient.builder().withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(accessKey, secretKey)))
				.withRegion(Regions.US_WEST_2).build(); 
		pmanage = new PolicyManagement();
		this.mqttClientMap = new HashMap<String, AWSIotMqttClient>();
	}
	
	public HashMap<String, AWSIotMqttClient> getMqttClientMap(){
		return this.mqttClientMap;
	}
	
	public void connect(AwsIoTDeviceCertificate deviceCert, List<Device> devices, boolean shouldReconnect){
		if (deviceCert == null)
			return;
		
		if (!shouldReconnect){
			// Attach devices to Certificate.
			this.attachThingToCertificate(deviceCert, devices);
			
			// Attach default connect policy to Certificate.
			this.attachDefaultPolicyToCertificate(deviceCert, Constants.connectPolicy);
			
			// Attach default connect policy to Certificate.
			this.attachDefaultPolicyToCertificate(deviceCert, Constants.publishPolicy);
			
			// Attach default connect policy to Certificate.
			this.attachDefaultPolicyToCertificate(deviceCert, Constants.subscribePolicy);
						
			// Attach default connect policy to Certificate.
			this.attachDefaultPolicyToCertificate(deviceCert, Constants.receivePolicy);
		}
				
		// Generate X.509 certificate from PEM file associated with the device generated via AWS Console.
		Certificate certificate = X509CertificateGenerator.generateCertificate(deviceCert.getCertPem()); 
		if (certificate == null)
		{
			throw new SecurityException("Could not generate certificate to connect to AWS IoT service.");
		}
		
		// Generate RSA private key from CertificateKeysAndResult AWS API
		Key key = RsaKeyReader.readRSAKey(deviceCert.getPrivateKey());
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
            
			System.out.println("Connecting devices to AWS IoT service using certificate: " + deviceCert.getCertId());
			for (Device device : devices){
				if(this.mqttClientMap.containsKey(device.getDeviceId())){
					continue;
				}
				
				AWSIotMqttClient mqttClient = new AWSIotMqttClient(endPoint, device.getDeviceId(), ks, password);
				mqttClient.connect();
				this.mqttClientMap.put(device.getDeviceId(), mqttClient);
				System.out.println("Successfully connected device: " + device.getDeviceId());
			}				
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | AWSIotException e) {
			System.out.println("Device connection to AWS IOT unsuccessful.");
		} 
	}
	
	public void attachThingToCertificate(AwsIoTDeviceCertificate deviceCert, List<Device> devices){
		for (Device device : devices){
			CreateThingResult thingResult = awsIotClient.createThing(new CreateThingRequest()
					.withThingName(device.getDeviceId()));
			
			awsIotClient.attachThingPrincipal(new AttachThingPrincipalRequest()
					.withPrincipal(deviceCert.getCertArn())
					.withThingName(thingResult.getThingName()));
		}
	}

	public void attachDefaultPolicyToCertificate(AwsIoTDeviceCertificate deviceCert, String policyName){
		AttachPrincipalPolicyRequest policyRequest = new AttachPrincipalPolicyRequest().withPrincipal(deviceCert.getCertArn());				
		GetPolicyResult policyResult = null;
		CreatePolicyResult policy = null;
		try{
			policyResult = awsIotClient.getPolicy(new GetPolicyRequest().withPolicyName(policyName));
		} catch (ResourceNotFoundException ex){
		}
		
		String action = "";
		switch(policyName){
		case Constants.connectPolicy:
			action = Constants.connectAction;
			break;
		case Constants.publishPolicy:
			action = Constants.publishAction;
			break;
		case Constants.subscribePolicy:
			action = Constants.subscribeAction;
			break;
		case Constants.receivePolicy:
			action = Constants.receiveAction;
			break;
		}
		
		if (policyResult == null){
			policy = awsIotClient.createPolicy(new CreatePolicyRequest()
				.withPolicyName(policyName)
				.withPolicyDocument(this.generateDefaultPolicy(action)));			
		}
		
		policyRequest.setPolicyName(policyResult == null ? policy.getPolicyName() : policyResult.getPolicyName());
		awsIotClient.attachPrincipalPolicy(policyRequest);		
	}
	
	public AwsIoTDeviceCertificate getAwsIoTDeviceCertificate(){
		CreateKeysAndCertificateRequest ckcr = new CreateKeysAndCertificateRequest().withSetAsActive(true);
		CreateKeysAndCertificateResult keysAndCertificate = awsIotClient.createKeysAndCertificate(ckcr);
		AwsIoTDeviceCertificate iotDeviceCert = new AwsIoTDeviceCertificate(keysAndCertificate.getCertificateId(), keysAndCertificate.getCertificateArn(), 
				keysAndCertificate.getCertificatePem(), keysAndCertificate.getKeyPair().getPublicKey(), keysAndCertificate.getKeyPair().getPrivateKey(), "active");
		return iotDeviceCert;
	}
	
	public String getPolicyInfo(String policyName){
		GetPolicyResult policyResult = null;
		try{
			policyResult = awsIotClient.getPolicy(new GetPolicyRequest().withPolicyName(policyName));
		} catch (ResourceNotFoundException ex){
		}
		
		if (policyResult == null)
			return "";
		return policyResult.getPolicyDocument();
	}
	
	public void updatePolicy(List<String> resources, String policyName, String action, boolean allow){
		String revPolicy = "";
		String policyJson = getPolicyInfo(policyName);
		if (policyJson == ""){
			policyJson = this.generateDefaultPolicy(action);
		}
		
		// create updated policy.
		if (allow)
			revPolicy = pmanage.allowPolicy(policyJson, action, resources);
		else
			revPolicy = pmanage.denyPolicy(policyJson, action, resources);
				    
		// attach updated policy to device certificate.
		CreatePolicyVersionResult policy = awsIotClient.createPolicyVersion(new CreatePolicyVersionRequest()
				.withPolicyName(policyName)
				.withPolicyDocument(revPolicy)
				.withSetAsDefault(true));	
		try{
			ListPolicyVersionsResult lpvr = awsIotClient.listPolicyVersions(new ListPolicyVersionsRequest().withPolicyName(policyName));
			List<PolicyVersion> pvr =  lpvr.getPolicyVersions();
			DeletePolicyVersionResult dpvr = null;
			for (PolicyVersion pv : pvr){
				if (!pv.isDefaultVersion()){
					dpvr = awsIotClient.deletePolicyVersion(new DeletePolicyVersionRequest()
							.withPolicyName(policyName)
							.withPolicyVersionId(pv.getVersionId()));
				}
			}
		} catch (Exception ex){
			
		}
		
		policy.setIsDefaultVersion(true);
	}

	public void detachAllPoliciesFromCertificate(AwsIoTDeviceCertificate deviceCertificate){
		if (deviceCertificate == null)
			return;
		
		awsIotClient.detachPrincipalPolicy(new DetachPrincipalPolicyRequest()
				.withPolicyName(Constants.connectPolicy).withPrincipal(deviceCertificate.getCertArn()));
	
		awsIotClient.detachPrincipalPolicy(new DetachPrincipalPolicyRequest()
			.withPolicyName(Constants.publishPolicy).withPrincipal(deviceCertificate.getCertArn()));
	
		awsIotClient.detachPrincipalPolicy(new DetachPrincipalPolicyRequest()
			.withPolicyName(Constants.subscribePolicy).withPrincipal(deviceCertificate.getCertArn()));
	
		awsIotClient.detachPrincipalPolicy(new DetachPrincipalPolicyRequest()
			.withPolicyName(Constants.receivePolicy).withPrincipal(deviceCertificate.getCertArn()));
	}
	
	public void detachAllThingsFromCertificate(AwsIoTDeviceCertificate deviceCertificate){
		if (deviceCertificate == null)
			return;
		
		ListPrincipalThingsResult lppr = awsIotClient.listPrincipalThings(new ListPrincipalThingsRequest()
				.withPrincipal(deviceCertificate.getCertArn()));
		
		for (String deviceId : lppr.getThings()){
			 awsIotClient.detachThingPrincipal(new DetachThingPrincipalRequest().withPrincipal(deviceCertificate.getCertArn())
					 .withThingName(deviceId));
		}
	}
	
	public void updateCertificate(AwsIoTDeviceCertificate deviceCertificate){
		UpdateCertificateResult updateCertResult = awsIotClient.updateCertificate(new UpdateCertificateRequest()
				.withCertificateId(deviceCertificate.getCertId()).withNewStatus(CertificateStatus.INACTIVE));
		
		if (updateCertResult == null){
			System.out.println("Deactivating certificate unsuccessful");
		}
	}
	
	public void attachThingsToCertificate(AwsIoTDeviceCertificate deviceCertificate){
		if (deviceCertificate == null)
			return;
		
		ListPrincipalThingsResult lppr = awsIotClient.listPrincipalThings(new ListPrincipalThingsRequest()
				.withPrincipal(deviceCertificate.getCertArn()));
		
		for (String deviceId : lppr.getThings()){
			awsIotClient.attachThingPrincipal(new AttachThingPrincipalRequest()
					.withPrincipal(deviceCertificate.getCertArn())
					.withThingName(deviceId));
		}
	}
	
	public boolean describeThing(String deviceId){
		try{
			awsIotClient.describeThing(new DescribeThingRequest().withThingName(deviceId));
		} catch (Exception ex){
			return false;
		}
		
		return true;
	}
	
	public void detachThingFromCertificate(AwsIoTDeviceCertificate deviceCert, Device device){
		try{
			awsIotClient.detachThingPrincipal(new DetachThingPrincipalRequest().withPrincipal(deviceCert.getCertArn())
				 .withThingName(device.getDeviceId()));
		} catch (Exception ex){
			System.out.println("Cannot detach device: " + device.getDeviceId() + " from certificate: " + deviceCert.getCertId());
		}
		
		System.out.println("Successfully detached device: "+ device.getDeviceId() + " from certificate: " + deviceCert.getCertId());
	}
	
	public List<Device> getAllowedDevicesFromConnectPolicy(String policyJson, List<Device> devices){
		return pmanage.getResources(policyJson, Constants.connectAction, devices);
	}
	
	public String generateDefaultPolicy(String action){
		return pmanage.generateDefaultPolicy(action);
	}
	
	public void deleteDevice(String deviceId){
		awsIotClient.deleteThing(new DeleteThingRequest().withThingName(deviceId));
	}
	
	public boolean disconnectDevice(String deviceId){
		if (!this.getMqttClientMap().containsKey(deviceId)){
			System.out.println("Device: " + deviceId + " not connected. Only connected devices can be disconnected." );
		}
		else{
			AWSIotMqttClient mqttClient = this.getMqttClientMap().get(deviceId);
			try {
				mqttClient.disconnect();				
				this.getMqttClientMap().remove(deviceId);
			} catch (AWSIotException e) {
				// TODO Auto-generated catch block
				return false;
			}
		}
		
		return true;
	}
	
	public boolean subscribeTopic(String deviceId, String topic){
		AWSIotMqttClient awsIotMqttClient = this.getMqttClientMap().get(deviceId);
		AWSIotTopic awsIotTopic = new TopicListener(deviceId, topic);
		try {
			awsIotMqttClient.subscribe(awsIotTopic, true);
		} catch (AWSIotException e) {
			// TODO Auto-generated catch block
			return false;
		}
		
		return true;
	}
	
	public boolean publishTopic(String deviceId, String topic, String message){
		AWSIotMqttClient awsIotMqttClient = this.getMqttClientMap().get(deviceId);
		try {
			int i = 0;
			while (i < 1){
				System.out.println(deviceId + " published message: " + message);
				awsIotMqttClient.publish(topic, AWSIotQos.QOS0, message);		
				Thread.sleep(timeout);
				i++;
			}
		} catch (AWSIotException | InterruptedException e) {
			// TODO Auto-generated catch block
			return false;
		}
		
		return true;
	}
	
	public boolean unsubscribeFromTopic(String deviceId, String topic){
		AWSIotMqttClient awsIotMqttClient = this.getMqttClientMap().get(deviceId);
		try {
			awsIotMqttClient.unsubscribe(topic, timeout);
		} catch (AWSIotException | AWSIotTimeoutException e) {
			// TODO Auto-generated catch block
			return false;
		}
		
		return true;
	}
	
	public List<Device> disconnectAllConnectedDevices(){
		List<Device> devices = new ArrayList<Device>();
		for (Map.Entry<String, AWSIotMqttClient> entry : this.getMqttClientMap().entrySet()){
			try {
				Device device = new Device(entry.getKey(), "", "");
				devices.add(device);
				entry.getValue().disconnect();
			} catch (AWSIotException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		return devices;
	}
}
