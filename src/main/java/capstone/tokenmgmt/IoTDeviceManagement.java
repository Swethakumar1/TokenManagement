/* 
 * Generates a certificate, private and public keys.
 * Establishes Connection with AWS IoT.  
 * 
 * 
 */
package capstone.tokenmgmt;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

public class IoTDeviceManagement implements IDeviceManagement, IPolicyManagement {
	private DeviceCertificateManagement deviceCertManagement;
	private AWSIoTDeviceOperations deviceOperations;
	
	public IoTDeviceManagement(){
		deviceOperations = new AWSIoTDeviceOperations();
		deviceCertManagement = new DeviceCertificateManagement();
	}
	
	public String getDeviceId(){
		return UUID.randomUUID().toString();
	}
	
	public void getCertificateIdAndArnForConnectedDevice(String deviceId){
		String certDetails = "";
		try{
			List<Device> device = deviceCertManagement.getDevices(deviceId);
			certDetails += "CertificateId: " + device.get(0).getCertId() + "\n";
			String certArn = deviceCertManagement.getCertArn(device.get(0).getCertId());	
			certDetails += "CertificateArn: " + certArn;
		} catch (SQLException ex){
			System.out.println("Invalid deviceId.");
		}
		
		System.out.println(certDetails);
	}
	
	public void connectDeviceToCertificate(String deviceId, String certificateId){
		AwsIoTDeviceCertificate deviceCert = null;
		try{
			deviceCert = deviceCertManagement.retrieveCert(certificateId);		
		} catch (SQLException ex){
			ex.printStackTrace();
			return;
		}
		
		List<Device> devices = new ArrayList<Device>();
		Device device = new Device(deviceId, certificateId, "connected");
		devices.add(device);
		deviceOperations.connect(deviceCert, devices, false);
		
		this.insertDevices(devices);
	}
	
	public AwsIoTDeviceCertificate generateAwsCertificate(){
		AwsIoTDeviceCertificate certificate = deviceOperations.getAwsIoTDeviceCertificate();
		List<AwsIoTDeviceCertificate> certs = new ArrayList<AwsIoTDeviceCertificate>();
		certs.add(certificate);
		this.insertCertificate(certs);		
		return certificate;
	}
	
	public void connectDevicesInGroups(List<Integer> devicesPerGroup){
		if (devicesPerGroup == null || devicesPerGroup.size() == 0)
			throw new IllegalArgumentException("Specify the number of devices per group.");
		
		List<AwsIoTDeviceCertificate> iotDeviceCerts = new ArrayList<AwsIoTDeviceCertificate>();
		for (int count = 0; count < devicesPerGroup.size(); count++){
			iotDeviceCerts.add(deviceOperations.getAwsIoTDeviceCertificate());
		}
		
		List<Device> deviceGroups = new ArrayList<Device>();
		for (int count = 0; count < devicesPerGroup.size(); count++){
			System.out.println("Number of devices in group: " + (count + 1) + ": " + devicesPerGroup.get(count));
			List<Device> devices = new ArrayList<Device>();
			for (int i = 0; i < devicesPerGroup.get(count); i++){
				String deviceId = UUID.randomUUID().toString();
				devices.add(new Device(deviceId, iotDeviceCerts.get(count).getCertId(), "connected"));
			}
			
			deviceOperations.connect(iotDeviceCerts.get(count), devices, false);
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
		AwsIoTDeviceCertificate iotDeviceCert = deviceOperations.getAwsIoTDeviceCertificate();
		iotDeviceCerts.add(iotDeviceCert);
		devices.add(new Device(deviceId, iotDeviceCert.getCertId(), "connected"));		
        
        // Connect to MQTT client.
		deviceOperations.connect(iotDeviceCert, devices, false);
        
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
		deviceOperations.connect(deviceCert, devices, false);		
		
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
		
		if (devices == null){
			System.out.println("Can reconnect only disconnected devices.");
			return;
		}
		
		 // Connect to MQTT client.
		if (deviceCert != null && devices != null){		
			String policyJson = deviceOperations.getPolicyInfo(Constants.connectPolicy);
			
			if (policyJson == ""){
				System.out.println("Connect policy does not exist. Creating new Connect policy.");
				policyJson = deviceOperations.generateDefaultPolicy(Constants.connectAction);
			}
			else{
				devices = deviceOperations.getAllowedDevicesFromConnectPolicy(policyJson, devices);
				
				if (devices.size() == 0){
					System.out.println("Cannot connect devices. Policy restrictions in place.");
					return;
				}
			}
			
			deviceOperations.connect(deviceCert, devices, true);
			
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
		
		if (devices == null){
			System.out.println("Can reconnect only disconnected devices.");
			return;
		}
        
		if (deviceCert != null && devices != null){
			String policyJson = deviceOperations.getPolicyInfo(Constants.connectPolicy);
			
			if (policyJson == ""){
				System.out.println("Connect policy does not exist. Creating new Connect policy.");
				policyJson = deviceOperations.generateDefaultPolicy(Constants.connectAction);
			}
			else{
				devices = deviceOperations.getAllowedDevicesFromConnectPolicy(policyJson, devices);
				
				if (devices.size() == 0){
					System.out.println("Cannot connect devices. Policy restrictions in place.");
					return;
				}
			}
			
	        // Connect to MQTT client.
			deviceOperations.connect(deviceCert, devices, true);
			
			// update device status in DB
			this.updateDevices(devices, "connected", true);
		}		
	}
	
	public void getConnectedDevices(){
		getConnectedDevices(null);
	}
	
	public void getConnectedDevices(String certificateId){
		System.out.println("Generating list of connected Devices " + certificateId == null  
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
		System.out.println("Generating list of disconnected Devices " + certificateId == null  
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
		deviceOperations.detachAllPoliciesFromCertificate(deviceCertificate);
		
		// detach things from existing certificate
		deviceOperations.detachAllThingsFromCertificate(deviceCertificate);		
		
		// Deactivate certificate with certificateId.
		deviceOperations.updateCertificate(deviceCertificate);
		
		// generate new certificate.
		List<AwsIoTDeviceCertificate> iotDeviceCerts = new ArrayList<AwsIoTDeviceCertificate>();
		iotDeviceCerts.add(deviceOperations.getAwsIoTDeviceCertificate());
		
		// attach policies to new certificate.
		deviceOperations.attachDefaultPolicyToCertificate(iotDeviceCerts.get(0), Constants.connectPolicy);
		deviceOperations.attachDefaultPolicyToCertificate(iotDeviceCerts.get(0), Constants.publishPolicy);
		deviceOperations.attachDefaultPolicyToCertificate(iotDeviceCerts.get(0), Constants.subscribePolicy);
		deviceOperations.attachDefaultPolicyToCertificate(iotDeviceCerts.get(0), Constants.receivePolicy);
		
		// attach things to new certificate.
		deviceOperations.attachThingsToCertificate(iotDeviceCerts.get(0));
		
		// Insert new certificate into DB.
		this.insertCertificate(iotDeviceCerts);
		
		// update old certificate status.
		this.updateCertificate(deviceCertificate, "inactive");
		
		// Update devices connected to AWS using new certificate.
		this.updateDeviceCertificate(deviceCertificate, iotDeviceCerts.get(0));
		System.out.println("Certificate " + certificateId + " successfully deactivated.");
		System.out.println("New certificate generated with Certificate id: " + iotDeviceCerts.get(0).getCertId());
	}
	
	public void disconnectDevice(String deviceId){
		if (deviceId == null || deviceId.length() == 0 || !deviceOperations.getMqttClientMap().containsKey(deviceId)){
			return;
		}
		
		if (deviceOperations.disconnectDevice(deviceId)){
			System.out.println("Succesfully disconnected device: " + deviceId);
		}
		else {
			System.out.println("Device: " + deviceId + " disconnection unsuccessful.");
		}
		
		List<Device> devices = new ArrayList<Device>();
		devices.add(new Device(deviceId, "", ""));
		
		// update device status in DB
		this.updateDevices(devices, "disconnected", false);
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
		
		if (devices == null){
			System.out.println("Devices not connected. Can reconnect only connected devices.");
			return;
		}
		
		for (Device device : devices){
			if (deviceOperations.disconnectDevice(device.getDeviceId())){
				System.out.println("Succesfully disconnected device: " + device.getDeviceId());
			}
			else {
				System.out.println("Device: " + device.getDeviceId() + " disconnection unsuccessful.");
			}
		}
		
		// update device status in DB
		updateDevices(devices, "disconnected", false);
	}
	
	public void deleteDevice(String deviceId){
		if (deviceOperations.getMqttClientMap().containsKey(deviceId)){
			boolean isDisconnectSuccessful = deviceOperations.disconnectDevice(deviceId);
			if (!isDisconnectSuccessful){
				System.out.println("Error disconnecting device. Cannot delete.");
				return;
			}
		}
		else{
			System.out.println("Device: " + deviceId + " not connected.");
		}
		
		System.out.println("Proceeding to delete device");
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
		
		boolean deviceExists = deviceOperations.describeThing(deviceId);
		
		if (!deviceExists){
			System.out.println("Device: " + deviceId + " does not exist.");
			return;
		}
		
		deviceOperations.detachThingFromCertificate(deviceCert, devices.get(0));
		
		deviceOperations.deleteDevice(devices.get(0).getDeviceId());
		
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
		
		if (devices == null){
			System.out.println("Certificate is not associated with any device.");
			return;
		}
		
		for(Device device : devices){		
			boolean deviceExists = deviceOperations.describeThing(device.getDeviceId());
			
			if (!deviceExists){
				System.out.println("Device: " + device.getDeviceId() + " does not exist.");
				continue;
			}			
			
			// detach device from certificate
			deviceOperations.detachThingFromCertificate(deviceCert, device);

			// delete device
			deviceOperations.deleteDevice(device.getDeviceId());
			
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
		try{
			devices = deviceCertManagement.getDevices(deviceId);
			if (devices.size() == 0 || devices.size() > 1){
				System.out.println("Invalid DeviceId. Can't update Connect Policy for device.");;
			}	
		}catch (SQLException ex){
			ex.printStackTrace();
		}
		
		List<String> res = new ArrayList<String>();
		res.add(deviceId);
		deviceOperations.updatePolicy(res, Constants.connectPolicy, Constants.connectAction, true);
	}
	
	public void allowConnectPolicyDevices(String certId){
		List<Device> devices = null;
		try{
			devices = deviceCertManagement.getDevicesAssociatedWithCert(certId);
			if (devices.size() == 0){
				System.out.println("No devices attached with this Certificate.");;
			}	
		}catch (SQLException ex){
			ex.printStackTrace();
		}		
		
		List<String> resources = new ArrayList<String>();
		for (Device device : devices){
			resources.add(device.getDeviceId());
		}
		
		deviceOperations.updatePolicy(resources, Constants.connectPolicy, Constants.connectAction, true);
	}
	
	public void denyConnectPolicyDevice(String deviceId){
		List<Device> devices = null;
		try{
			devices = deviceCertManagement.getDevices(deviceId);
			if (devices.size() == 0 || devices.size() > 1){
				System.out.println("Invalid DeviceId. Can't update Connect Policy for device.");;
			}	
		}catch (SQLException ex){
			ex.printStackTrace();
		}
		
		List<String> res = new ArrayList<String>();
		res.add(deviceId);
		deviceOperations.updatePolicy(res, Constants.connectPolicy, Constants.connectAction, false);
	}
	
	public void denyConnectPolicyDevices(String certId){
		List<Device> devices = null;
		try{
			devices = deviceCertManagement.getDevicesAssociatedWithCert(certId);
			if (devices.size() == 0){
				System.out.println("No devices attached with this Certificate.");;
			}	
		}catch (SQLException ex){
			ex.printStackTrace();
		}		
		
		List<String> resources = new ArrayList<String>();
		for (Device device : devices){
			resources.add(device.getDeviceId());
		}
		
		deviceOperations.updatePolicy(resources, Constants.connectPolicy, Constants.connectAction, false);
	}
	
	public void publishTopic(String deviceId, String topic, String message){
		if(!deviceOperations.getMqttClientMap().containsKey(deviceId)){
			System.out.println("Device not connected. Cannot publish message to topic. Connect device to publish messages to topic.");
			return;			
		}
		
		if (deviceOperations.publishTopic(deviceId, topic, message)){
			System.out.println("Publish operation successful");
		} else{
			System.out.print("Publish operation unsuccessful");
		}
	}
	
	public void subscribeTopic(String deviceId, String topic){
		if(!deviceOperations.getMqttClientMap().containsKey(deviceId)){
			System.out.println("Device not connected. Cannot publish message to topic. Connect device to publish messages to topic.");
			return;			
		}
		
		boolean subscribeStatus = deviceOperations.subscribeTopic(deviceId, topic);
		if (subscribeStatus){
			System.out.println("Successfully subscribed to topic: " + topic + " by device: " + deviceId);
		} else{
			System.out.println("Topic subscription unsucessful");
		}
	}
	
	public void unsubscribe(String deviceId, String topic){
		if(!deviceOperations.getMqttClientMap().containsKey(deviceId)){
			System.out.println("Device not connected. Cannot publish message to topic. Connect device to publish messages to topic.");
			return;			
		}
		
		boolean successfullyUnsubscribed = deviceOperations.unsubscribeFromTopic(deviceId, topic);
		if (successfullyUnsubscribed){
			System.out.println("Device: " + deviceId + " unsuccessfully unsubscribed from topic: " + topic);
		}else {
			System.out.println("Topic unsubscription by device: " + deviceId + " unsuccessful");
		}
	}
	
	public void denyPublishingToTopic(String topic){
		List<String> resources = new ArrayList<String>();
		resources.add(topic);
		deviceOperations.updatePolicy(resources, Constants.publishPolicy, Constants.publishAction, false);
	}
	
	public void denySubscribingToTopic(String topic){
		List<String> resources = new ArrayList<String>();
		resources.add(topic);
		deviceOperations.updatePolicy(resources, Constants.subscribePolicy, Constants.subscribeAction, false);
	}
	
	public void denyReceivingMessageFromTopic(String topic){
		List<String> resources = new ArrayList<String>();
		resources.add(topic);
		deviceOperations.updatePolicy(resources, Constants.receivePolicy, Constants.receiveAction, false);
	}
	
	public void allowPublishingToTopic(String topic){
		List<String> resources = new ArrayList<String>();
		resources.add(topic);
		deviceOperations.updatePolicy(resources, Constants.publishPolicy, Constants.publishAction, true);
	}
	
	public void allowSubscribingToTopic(String topic){
		List<String> resources = new ArrayList<String>();
		resources.add(topic);
		deviceOperations.updatePolicy(resources, Constants.subscribePolicy, Constants.subscribeAction, true);
	}
	
	public void allowReceivingMessageFromTopic(String topic){
		List<String> resources = new ArrayList<String>();
		resources.add(topic);
		deviceOperations.updatePolicy(resources, Constants.receivePolicy, Constants.receiveAction, true);
	}
	
	public void disconnectAllDevices(){
		List<Device> devices = deviceOperations.disconnectAllConnectedDevices();		
		this.updateDevices(devices, "disconnected", false);
	}
	
		
	private void insertDevices(List<Device> devices){
		for (Iterator<Device> iterator = devices.iterator(); iterator.hasNext();){
			Device device = (Device)iterator.next();
			if (!deviceOperations.getMqttClientMap().containsKey(device.getDeviceId())){	
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
				if (!deviceOperations.getMqttClientMap().containsKey(device.getDeviceId())){	
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