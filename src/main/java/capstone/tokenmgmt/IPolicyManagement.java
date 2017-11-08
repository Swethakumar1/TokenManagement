package capstone.tokenmgmt;

public interface IPolicyManagement {
	public void allowConnectPolicyDevice(String deviceID); 
	
	public void allowConnectPolicyDevices(String certificateId); 
	
	public void allowPublishingToTopic(String topic);
	
	public void allowSubscribingToTopic(String topic);
	
	public void allowReceivingMessageFromTopic(String topic);
		
	public void denyConnectPolicyDevice(String deviceId);
	
	public void denyConnectPolicyDevices(String certificateId);
	
	public void denyPublishingToTopic(String topic);
	
	public void denySubscribingToTopic(String topic);
	
	public void denyReceivingMessageFromTopic(String topic);
	
}
