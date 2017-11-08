package capstone.tokenmgmt;

import com.amazonaws.services.iot.client.AWSIotMessage;
import com.amazonaws.services.iot.client.AWSIotQos;
import com.amazonaws.services.iot.client.AWSIotTopic;

public class TopicListener extends AWSIotTopic {
    private String deviceId;
	public TopicListener(String deviceId, String topic){
		super(topic, AWSIotQos.QOS0);
		this.deviceId = deviceId;
	}
	
	@Override
	public void onMessage(AWSIotMessage iotMessage){
		System.out.println(this.deviceId + " received message:  " + iotMessage.getStringPayload());
	}
	
	@Override
	public void onSuccess(){
		System.out.println("Successfully subscribed to topic.");
	}
}
