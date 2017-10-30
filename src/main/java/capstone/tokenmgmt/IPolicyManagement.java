package capstone.tokenmgmt;

public interface IPolicyManagement {
	public void allowConnectPolicyDevice(String deviceID); 
	
	public void allowConnectPolicyDevices(String certificateId); 
	
	public void allowPublishingToTopic(String deviceId, String topic);
	
	public void allowSubscribingToTopic(String deviceId, String topic);
	
	public void allowReceivingMessageFromTopic(String deviceId, String topic);
		
	public void denyConnectPolicyDevice(String deviceId);
	
	public void denyConnectPolicyDevices(String certificateId);
	
	public void denyPublishingToTopic(String deviceId, String topic);
	
	public void denySubscribingToTopic(String deviceId, String topic);
	
	public void denyReceivingMessageFromTopic(String deviceId, String topic);
	
}
