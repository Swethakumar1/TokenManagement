/* 
 * Generates a certificate, private and public keys.
 * Establishes Connection with AWS IoT.  
 * 
 * 
 */
package capstone.tokenmgmt;


import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.iot.AWSIot;
import com.amazonaws.services.iot.AWSIotClient;
import com.amazonaws.services.iot.client.AWSIotException;
import com.amazonaws.services.iot.client.AWSIotMqttClient;
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
import com.amazonaws.services.iot.model.DeletePolicyRequest;
import com.amazonaws.services.iot.model.DeletePolicyResult;
import com.amazonaws.services.iot.model.DeletePolicyVersionRequest;
import com.amazonaws.services.iot.model.DeletePolicyVersionResult;
import com.amazonaws.services.iot.model.DeleteThingRequest;
import com.amazonaws.services.iot.model.DescribeThingRequest;
import com.amazonaws.services.iot.model.DescribeThingResult;
import com.amazonaws.services.iot.model.DetachPrincipalPolicyRequest;
import com.amazonaws.services.iot.model.DetachPrincipalPolicyResult;
import com.amazonaws.services.iot.model.DetachThingPrincipalRequest;
import com.amazonaws.services.iot.model.DetachThingPrincipalResult;
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


public class AWSIoTConnection {//implements IDeviceManagement {
	private final String connectPolicy = "ConnectPolicy";
	private final String publishPolicy = "PublishPolicy";	
	private final String subscribePolicy = "SubscribePolicy";
	private final String receivePolicy = "ReceivePolicy";
	private final String connectAction = "iot:Connect";
	private final String publishAction = "iot:Publish";
	private final String subscribeAction = "iot:Subscribe";
	private final String receiveAction = "iot:Receive";
	private final long timeout = 6000;
	private DeviceCertificateManagement deviceCertManagement;
	private HashMap<String, AWSIotMqttClient> mqttClientMap;
	private final String accessKey;
	private final String secretKey;
	private final String endPoint;
	private final AWSIot awsIotClient;
	private PolicyManagement pmanage;
	public AWSIoTConnection(String accessKey, String secretKey, String endPoint){
		this.accessKey = accessKey;
		this.secretKey = secretKey;
		this.endPoint = endPoint;
		awsIotClient = AWSIotClient.builder().withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(accessKey, secretKey)))
				.withRegion(Regions.US_WEST_2).build(); 
		deviceCertManagement = new DeviceCertificateManagement();
		pmanage = new PolicyManagement();
		this.mqttClientMap = new HashMap<String, AWSIotMqttClient>();
	}
	
	public void connectDevicesInGroups(List<Integer> devicesPerGroup){
		if (devicesPerGroup == null || devicesPerGroup.size() == 0)
			throw new IllegalArgumentException("Specify the number of devices per group.");
		
		List<AwsIoTDeviceCertificate> iotDeviceCerts = new ArrayList<AwsIoTDeviceCertificate>();
		for (int count = 0; count < devicesPerGroup.size(); count++){
			iotDeviceCerts.add(getAwsIoTDeviceCertificate());
		}
		
		List<Device> deviceGroups = new ArrayList<Device>();
		for (int count = 0; count < devicesPerGroup.size(); count++){
			System.out.println("Number of devices in group: " + (count + 1) + ": " + devicesPerGroup.get(count));
			List<Device> devices = new ArrayList<Device>();
			for (int i = 0; i < devicesPerGroup.get(count); i++){
				String deviceId = UUID.randomUUID().toString();
				devices.add(new Device(deviceId, iotDeviceCerts.get(count).getCertId(), "connected"));
			}
			
			connect(iotDeviceCerts.get(count), devices, false);
			deviceGroups.addAll(devices);
		}		
		
		// Insert certificates & devices into DB.
		insertCertificate(iotDeviceCerts);
		insertDevices(deviceGroups);
	}
	
	// connect new device using new certificate.
	public void connectDevice(String deviceId){
		List<Device> devices = new ArrayList<Device>();
		List<AwsIoTDeviceCertificate> iotDeviceCerts = new ArrayList<AwsIoTDeviceCertificate>();
		AwsIoTDeviceCertificate iotDeviceCert = getAwsIoTDeviceCertificate();
		iotDeviceCerts.add(iotDeviceCert);
		devices.add(new Device(deviceId, iotDeviceCert.getCertId(), "connected"));		
        
        // Connect to MQTT client.
        connect(iotDeviceCert, devices, false);
        
        // Insert certificates & devices into DB.
        insertCertificate(iotDeviceCerts);
        insertDevices(devices);
	}
	
	// connect new devices using existing certificate.
	public void connectDevicesWithExistingCertificate(String certificateId, int numberOfDevices){
		AwsIoTDeviceCertificate deviceCert = null;
		try{
			deviceCert = deviceCertManagement.retrieveCert(certificateId);		
		} catch (SQLException ex){
			ex.printStackTrace();
			return;
		}

		if (!deviceCert.getStatus().equalsIgnoreCase("active")){
			return;
		}
		
		List<Device> devices = new ArrayList<Device>();
		for (int count = 0; count < numberOfDevices; count++){
			String deviceId = UUID.randomUUID().toString();
			devices.add(new Device(deviceId, certificateId, "connected"));
		}
		        
        // Connect to MQTT client.
		connect(deviceCert, devices, false);		
		
		// insert device data in DB.
		insertDevices(devices);
	}
	
	// Connect existing devices with existing certificate.
	public void reconnectAllDevicesWithExistingCertificate(String certificateId){
		List<Device> devices = null;
		AwsIoTDeviceCertificate deviceCert = null;
		
		// Retrieve device & certificate details
		try{
	        devices = deviceCertManagement.getDevices(certificateId, "disconnected");
	        deviceCert = deviceCertManagement.retrieveCert(certificateId);
		} catch (SQLException ex){
			ex.printStackTrace();
		}
		
		 // Connect to MQTT client.
		if (deviceCert != null && devices != null){		
			String policyJson = getPolicyInfo(connectPolicy);
			
			devices = pmanage.getResources(policyJson, connectAction, devices);
			
			connect(deviceCert, devices, true);
			
			// update device status in DB
			updateDevices(devices, "connected", true);
		}
	}
	
	public void reconnectDevice(String deviceId){
		if (deviceId == null || deviceId.length() == 0)
			return;
		
		List<Device> devices = null;
		AwsIoTDeviceCertificate deviceCert = null;
		
		// Retrieve device
		try{
	        devices = deviceCertManagement.getDevices(deviceId);
	        deviceCert = deviceCertManagement.retrieveCert(devices.get(0).getCertId());
		} catch (SQLException ex){
			ex.printStackTrace();
		}
        
		if (deviceCert != null && devices != null){
	        // Connect to MQTT client.
			connect(deviceCert, devices, true);
			
			// update device status in DB
			updateDevices(devices, "connected", true);
		}		
	}
	
	public void getConnectedDevices(){
		getConnectedDevices(null);
	}
	
	public void getConnectedDevices(String certificateId){
		System.out.println("List of connected Devices " + certificateId == null  
				?  ""
				: "for certificate: " + certificateId);
		try{
			for (Device device : deviceCertManagement.getDevices(certificateId, "connected")){
				System.out.println(device.getDeviceId());
			}
		} catch (SQLException ex){
			ex.printStackTrace();
		}
	}
	
	public void getDisconnectedDevices(){
		getDisconnectedDevices(null);
	}
	
	public void getDisconnectedDevices(String certificateId){
		System.out.println("List of disconnected Devices " + certificateId == null  
				? ""
				: "for certificate: " + certificateId );
		try{
			for (Device device : deviceCertManagement.getDevices(certificateId, "disconnected")){
				System.out.println(device.getDeviceId());
			}
		} catch (SQLException ex){
			ex.printStackTrace();
		}
	}
	
	public void deactivateCertificate(String certificateId){
		AwsIoTDeviceCertificate deviceCertificate = null;
		try{
			deviceCertificate = deviceCertManagement.retrieveCert(certificateId);
		} catch (SQLException ex){
			ex.printStackTrace();
		}
		
		if (deviceCertificate == null || deviceCertificate.getStatus().equalsIgnoreCase("inactive")){
			System.out.println("Invalid operation.");
			return;
		}
				
		
		// detach policies from existing certificate
		awsIotClient.detachPrincipalPolicy(new DetachPrincipalPolicyRequest()
					.withPolicyName(connectPolicy).withPrincipal(deviceCertificate.getCertArn()));
		
		awsIotClient.detachPrincipalPolicy(new DetachPrincipalPolicyRequest()
				.withPolicyName(publishPolicy).withPrincipal(deviceCertificate.getCertArn()));
		
		awsIotClient.detachPrincipalPolicy(new DetachPrincipalPolicyRequest()
				.withPolicyName(subscribePolicy).withPrincipal(deviceCertificate.getCertArn()));
		
		awsIotClient.detachPrincipalPolicy(new DetachPrincipalPolicyRequest()
				.withPolicyName(receivePolicy).withPrincipal(deviceCertificate.getCertArn()));
		
		// detach things from existing certificate
		ListPrincipalThingsResult lppr = awsIotClient.listPrincipalThings(new ListPrincipalThingsRequest()
				.withPrincipal(deviceCertificate.getCertArn()));
		
		for (String deviceId : lppr.getThings()){
			 awsIotClient.detachThingPrincipal(new DetachThingPrincipalRequest().withPrincipal(deviceCertificate.getCertArn())
					 .withThingName(deviceId));
		}
		
		// Deactivate certificate with certificateId.
		UpdateCertificateResult updateCertResult = awsIotClient.updateCertificate(new UpdateCertificateRequest().withCertificateId(certificateId).withNewStatus(CertificateStatus.INACTIVE));
		if (updateCertResult == null){
			System.out.println("Deactivating certificate unsuccessful");
		}
		
		// generate new certificate.
		List<AwsIoTDeviceCertificate> iotDeviceCerts = new ArrayList<AwsIoTDeviceCertificate>();
		iotDeviceCerts.add(getAwsIoTDeviceCertificate());
		
		// attach policies to new certificate.
		this.attachDefaultPolicyToCertificate(iotDeviceCerts.get(0), connectPolicy);
		this.attachDefaultPolicyToCertificate(iotDeviceCerts.get(0), publishPolicy);
		this.attachDefaultPolicyToCertificate(iotDeviceCerts.get(0), subscribePolicy);
		this.attachDefaultPolicyToCertificate(iotDeviceCerts.get(0), receivePolicy);
		
		// attach things to new certificate.
		for (String deviceId : lppr.getThings()){
			awsIotClient.attachThingPrincipal(new AttachThingPrincipalRequest()
					.withPrincipal(iotDeviceCerts.get(0).getCertArn())
					.withThingName(deviceId));
		}
		
		// Insert new certificate into DB.
		insertCertificate(iotDeviceCerts);
		
		// Update devices connected to AWS with CertificateId: certificateId using new certificate.
		updateCertificate(deviceCertificate, "inactive");
		updateDeviceCertificate(deviceCertificate, iotDeviceCerts.get(0));
		System.out.println("Certificate " + certificateId + " successfully deactivated.");
		System.out.println("New certificate generated with Certificate id: " + iotDeviceCerts.get(0).getCertId());
	}
	
	public void disconnectDevice(String deviceId){
		if (deviceId == null || deviceId.length() == 0 || !this.mqttClientMap.containsKey(deviceId)){
			return;
		}
		
		AWSIotMqttClient mqttClient = this.mqttClientMap.get(deviceId);
		try {
			mqttClient.disconnect();
			System.out.println("Succesfully disconnected device: " + deviceId);
			
			this.mqttClientMap.remove(deviceId);
		} catch (AWSIotException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		List<Device> devices = new ArrayList<Device>();
		devices.add(new Device(deviceId, "", ""));
		
		// update device status in DB
		updateDevices(devices, "disconnected", false);
	}
	
	public void disconnectDevices(String certificateId){
		if (certificateId == null || certificateId.length() == 0)
			return;
		
		List<Device> devices = null;
		try{
			devices = deviceCertManagement.getDevices(certificateId, "connected");
		} catch (SQLException ex){
			ex.printStackTrace();
			return;
		}
		
		for (Device device : devices){
			if (!this.mqttClientMap.containsKey(device.getDeviceId())){
				System.out.println("Device: " + device.getDeviceId() + " not connected. Only connected devices can be disconnected." );
			}
			else{
				AWSIotMqttClient mqttClient = this.mqttClientMap.get(device.getDeviceId());
				try {
					mqttClient.disconnect();
					System.out.println("Succesfully disconnected device: " + device.getDeviceId());
					
					this.mqttClientMap.remove(device.getDeviceId());
				} catch (AWSIotException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
		// update device status in DB
		updateDevices(devices, "disconnected", false);
	}
	
	public void deleteDevice(String deviceId){
		if (mqttClientMap.containsKey(deviceId)){
			AWSIotMqttClient mqttClient = mqttClientMap.get(deviceId);
			try{
				mqttClient.disconnect();
			} catch(AWSIotException ex){
				ex.printStackTrace();
				return;
			}
		}
		else{
			System.out.println("Device: " + deviceId + " not connected.");
		}
		
		List<Device> devices = null;
		AwsIoTDeviceCertificate deviceCert = null;
		
		// Retrieve device
		try{
	        devices = deviceCertManagement.getDevices(deviceId);
	        deviceCert = deviceCertManagement.retrieveCert(devices.get(0).getCertId());
		} catch (SQLException ex){
			ex.printStackTrace();
		}
		
		if (devices == null || deviceCert == null)
			return;
		
		try{
			DescribeThingResult dtr = awsIotClient.describeThing(new DescribeThingRequest().withThingName(deviceId));
		} catch (Exception ex){
			System.out.println("Device: " + deviceId + " does not exist.");
			return;
		}
		
		awsIotClient.detachThingPrincipal(new DetachThingPrincipalRequest().withPrincipal(deviceCert.getCertArn())
				 .withThingName(devices.get(0).getDeviceId()));
		
		awsIotClient.deleteThing(new DeleteThingRequest().withThingName(devices.get(0).getDeviceId()));
		
		System.out.println("Device: " + deviceId + " successfully deleted.");
		
		try{
			deviceCertManagement.deleteDevices(devices);
		}catch (SQLException ex){
			ex.printStackTrace();
		}
	}
	
	public void deleteDevices (String certificateId){
		if (certificateId == null || certificateId.length() == 0)
			return;
		
		List<Device> devices = null;
		AwsIoTDeviceCertificate deviceCert = null;
		
		try{
			deviceCert = deviceCertManagement.retrieveCert(certificateId);
			devices = deviceCertManagement.getDevicesAssociatedWithCert(certificateId);
		} catch (SQLException ex){
			ex.printStackTrace();
			return;
		}
		
		for(Device device : devices){
			if (mqttClientMap.containsKey(device.getDeviceId())){
				AWSIotMqttClient mqttClient = mqttClientMap.get(device.getDeviceId());
				try{
					mqttClient.disconnect();
				} catch(AWSIotException ex){
					ex.printStackTrace();
					return;
				}
			}
			
			try{
				DescribeThingResult dtr = awsIotClient.describeThing(new DescribeThingRequest().withThingName(device.getDeviceId()));
			} catch (Exception ex){
				System.out.println("Device: " + device.getDeviceId() + " does not exist.");
				continue;
			}
			
			awsIotClient.detachThingPrincipal(new DetachThingPrincipalRequest().withPrincipal(deviceCert.getCertArn())
					 .withThingName(device.getDeviceId()));
			
			awsIotClient.deleteThing(new DeleteThingRequest().withThingName(devices.get(0).getDeviceId()));
			
			System.out.println("Device: " + device.getDeviceId() + " successfully deleted.");
		}
		
		try{
			deviceCertManagement.deleteDevices(devices);
		} catch(SQLException ex){
			ex.printStackTrace();
		}
	}
	
	public void allowConnectPolicyDevice(String deviceId){
		List<Device> devices = null;
		String certArn = "";
		try{
			devices = deviceCertManagement.getDevices(deviceId);
			if (devices.size() == 0 || devices.size() > 1){
				System.out.println("Invalid DeviceId. Can't update Connect Policy for device.");;
			}	
			
			certArn = deviceCertManagement.getCertArn(devices.get(0).getCertId());
		}catch (SQLException ex){
			ex.printStackTrace();
		}
		
		List<String> res = new ArrayList<String>();
		res.add(deviceId);
		updatePolicy(res, connectPolicy, connectAction, true);
	}
	
	public void allowConnectPolicyDevices(String certId){
		List<Device> devices = null;
		String certArn = "";
		try{
			devices = deviceCertManagement.getDevicesAssociatedWithCert(certId);
			if (devices.size() == 0){
				System.out.println("No devices attached with this Certificate.");;
			}	
			
			certArn = deviceCertManagement.getCertArn(certId);

		}catch (SQLException ex){
			ex.printStackTrace();
		}		
		
		List<String> resources = new ArrayList<String>();
		for (Device device : devices){
			resources.add(device.getDeviceId());
		}
		
		updatePolicy(resources, connectPolicy, connectAction, true);
	}
	
	public void denyConnectPolicyDevice(String deviceId){
		List<Device> devices = null;
		String certArn = "";
		try{
			devices = deviceCertManagement.getDevices(deviceId);
			if (devices.size() == 0 || devices.size() > 1){
				System.out.println("Invalid DeviceId. Can't update Connect Policy for device.");;
			}	
			
			certArn = deviceCertManagement.getCertArn(devices.get(0).getCertId());
		}catch (SQLException ex){
			ex.printStackTrace();
		}
		
		List<String> res = new ArrayList<String>();
		res.add(deviceId);
		updatePolicy(res, connectPolicy, connectAction, false);
	}
	
	public void denyConnectPolicyDevices(String certId){
		List<Device> devices = null;
		String certArn = "";
		try{
			devices = deviceCertManagement.getDevicesAssociatedWithCert(certId);
			if (devices.size() == 0){
				System.out.println("No devices attached with this Certificate.");;
			}	
			
			certArn = deviceCertManagement.getCertArn(certId);

		}catch (SQLException ex){
			ex.printStackTrace();
		}		
		
		List<String> resources = new ArrayList<String>();
		for (Device device : devices){
			resources.add(device.getDeviceId());
		}
		
		updatePolicy(resources, connectPolicy, connectAction, false);
	}
	
	public void publishTopic(String deviceId, String topic, String message){
		if(!this.mqttClientMap.containsKey(deviceId)){
			System.out.println("Device not connected. Cannot publish message to topic. Connect device to publish messages to topic.");
			return;			
		}
		
		AWSIotMqttClient awsIotMqttClient = this.mqttClientMap.get(deviceId);
		try {
			awsIotMqttClient.publish(topic, message);
		} catch (AWSIotException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void subscribeTopic(String deviceId, String topic){
		if(!this.mqttClientMap.containsKey(deviceId)){
			System.out.println("Device not connected. Cannot publish message to topic. Connect device to publish messages to topic.");
			return;			
		}
		
		AWSIotMqttClient awsIotMqttClient = this.mqttClientMap.get(deviceId);
		AWSIotTopic awsIotTopic = new TopicListener(topic);
		try {
			awsIotMqttClient.subscribe(awsIotTopic, true);;
		} catch (AWSIotException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void unsubscribe(String deviceId, String topic){
		if(!this.mqttClientMap.containsKey(deviceId)){
			System.out.println("Device not connected. Cannot publish message to topic. Connect device to publish messages to topic.");
			return;			
		}
		
		AWSIotMqttClient awsIotMqttClient = this.mqttClientMap.get(deviceId);
		try {
			awsIotMqttClient.unsubscribe(topic, timeout);
		} catch (AWSIotException | AWSIotTimeoutException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void denyPublishingToTopic(String deviceId, String topic){
		List<String> resources = new ArrayList<String>();
		resources.add(topic);
		updatePolicy(resources, publishPolicy, publishAction, false);
	}
	
	public void denySubscribingToTopic(String deviceId, String topic){
		List<String> resources = new ArrayList<String>();
		resources.add(topic);
		updatePolicy(resources, subscribePolicy, subscribeAction, false);
	}
	
	public void denyReceivingMessageFromTopic(String deviceId, String topic){
		List<String> resources = new ArrayList<String>();
		resources.add(topic);
		updatePolicy(resources, receivePolicy, receiveAction, false);
	}
	
	public void disconnectAllDevices(){
		List<Device> devices = new ArrayList<Device>();
		for (Map.Entry<String, AWSIotMqttClient> entry : this.mqttClientMap.entrySet()){
			try {
				Device device = new Device(entry.getKey(), "", "");
				devices.add(device);
				entry.getValue().disconnect();
			} catch (AWSIotException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		updateDevices(devices, "disconnected", false);
	}
	
	private void connect(AwsIoTDeviceCertificate deviceCert, List<Device> devices, boolean shouldReconnect){
		if (deviceCert == null)
			return;
		
		if (!shouldReconnect){
			// Attach devices to Certificate.
			this.attachThingToCertificate(deviceCert, devices);
			
			// Attach default connect policy to Certificate.
			this.attachDefaultPolicyToCertificate(deviceCert, connectPolicy);
			
			// Attach default connect policy to Certificate.
			this.attachDefaultPolicyToCertificate(deviceCert, publishPolicy);
			
			// Attach default connect policy to Certificate.
			this.attachDefaultPolicyToCertificate(deviceCert, subscribePolicy);
						
			// Attach default connect policy to Certificate.
			this.attachDefaultPolicyToCertificate(deviceCert, receivePolicy);
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
				AWSIotMqttClient mqttClient = new AWSIotMqttClient(endPoint, device.getDeviceId(), ks, password);
				this.mqttClientMap.put(device.getDeviceId(), mqttClient);
				mqttClient.connect();
				System.out.println("Successfully connected device: " + device.getDeviceId());
			}				
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | AWSIotException e) {
			e.printStackTrace();
		} 
	}
	
	private void attachThingToCertificate(AwsIoTDeviceCertificate deviceCert, List<Device> devices){
		for (Device device : devices){
			CreateThingResult thingResult = awsIotClient.createThing(new CreateThingRequest()
					.withThingName(device.getDeviceId()));
			
			awsIotClient.attachThingPrincipal(new AttachThingPrincipalRequest()
					.withPrincipal(deviceCert.getCertArn())
					.withThingName(thingResult.getThingName()));
		}
	}

	private void attachDefaultPolicyToCertificate(AwsIoTDeviceCertificate deviceCert, String policyName){
		AttachPrincipalPolicyRequest policyRequest = new AttachPrincipalPolicyRequest().withPrincipal(deviceCert.getCertArn());				
		GetPolicyResult policyResult = null;
		CreatePolicyResult policy = null;
		try{
			policyResult = awsIotClient.getPolicy(new GetPolicyRequest().withPolicyName(policyName));
		} catch (ResourceNotFoundException ex){
			// ex.printStackTrace();
		}
		
		String action = "";
		switch(policyName){
		case connectPolicy:
			action = connectAction;
			break;
		case publishPolicy:
			action = publishAction;
			break;
		case subscribePolicy:
			action = subscribeAction;
			break;
		case receivePolicy:
			action = receiveAction;
			break;
		}
		
		if (policyResult == null){
			policy = awsIotClient.createPolicy(new CreatePolicyRequest()
				.withPolicyName(policyName)
				.withPolicyDocument(pmanage.genereateDefaultPolicy(action)));			
		}
		
		policyRequest.setPolicyName(policyResult == null ? policy.getPolicyName() : policyResult.getPolicyName());
		awsIotClient.attachPrincipalPolicy(policyRequest);		
	}
	
	private AwsIoTDeviceCertificate getAwsIoTDeviceCertificate(){
		CreateKeysAndCertificateRequest ckcr = new CreateKeysAndCertificateRequest().withSetAsActive(true);
		CreateKeysAndCertificateResult keysAndCertificate = awsIotClient.createKeysAndCertificate(ckcr);
		AwsIoTDeviceCertificate iotDeviceCert = new AwsIoTDeviceCertificate(keysAndCertificate.getCertificateId(), keysAndCertificate.getCertificateArn(), 
				keysAndCertificate.getCertificatePem(), keysAndCertificate.getKeyPair().getPublicKey(), keysAndCertificate.getKeyPair().getPrivateKey(), "active");
		return iotDeviceCert;
	}
	
	private String getPolicyInfo(String policyName){
		GetPolicyResult policyResult = null;
		try{
			policyResult = awsIotClient.getPolicy(new GetPolicyRequest().withPolicyName(connectPolicy));
		} catch (ResourceNotFoundException ex){
			ex.printStackTrace();
		}
		
		return policyResult.getPolicyDocument();
	}
	
	private void updatePolicy(List<String> resources, String policyName, String action, boolean allow){
		String revPolicy = "";
		String policyJson = getPolicyInfo(policyName);
		
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
	}
	
	private void insertDevices(List<Device> devices){
		for (Iterator<Device> iterator = devices.iterator(); iterator.hasNext();){
			Device device = (Device)iterator.next();
			if (!this.mqttClientMap.containsKey(device.getDeviceId())){	
				System.out.println("Device: " + device.getDeviceId() + " not connected.");
				iterator.remove();
			}
		}
		
		try{
			deviceCertManagement.insertDevices(devices);
		} catch (SQLException ex){
			ex.printStackTrace();
		}
	}
	
	private void updateDevices(List<Device> devices, String status, boolean shouldCheckInMap){
		if (shouldCheckInMap){
			for (Iterator<Device> iterator = devices.iterator(); iterator.hasNext();){
				Device device = (Device)iterator.next();
				if (!this.mqttClientMap.containsKey(device.getDeviceId())){	
					System.out.println("Device: " + device.getDeviceId() + " not connected.");
					iterator.remove();
				}
			}
		}
		
		try{
			deviceCertManagement.updateDeviceStatus(devices, status);
		} catch (SQLException ex){
			ex.printStackTrace();
		}
	}
	
	private void insertCertificate(List<AwsIoTDeviceCertificate> iotDeviceCerts){
		try{
			deviceCertManagement.insertCertificates(iotDeviceCerts);
		}
		catch(SQLException ex){
			ex.printStackTrace();
		}
	}
	
	private void updateCertificate(AwsIoTDeviceCertificate iotDeviceCert, String status){
		try{
			deviceCertManagement.updateCertificateStatus(iotDeviceCert.getCertId(), status);
		}
		catch(SQLException ex){
			ex.printStackTrace();
		}
	}
	
	private void updateDeviceCertificate(AwsIoTDeviceCertificate oIotDeviceCert, AwsIoTDeviceCertificate nIotDeviceCert){
		try{
			deviceCertManagement.updateDeviceCertificate(oIotDeviceCert.getCertId(), nIotDeviceCert.getCertId());
		}
		catch(SQLException ex){
			ex.printStackTrace();
		}
	}
} 