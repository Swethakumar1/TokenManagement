package capstone.tokenmgmt;

import com.amazonaws.services.iot.client.AWSIotMessage;
import com.amazonaws.services.iot.client.AWSIotQos;
import com.amazonaws.services.iot.client.AWSIotTopic;

public class TopicListener extends AWSIotTopic {

	public TopicListener(String topic){
		super(topic, AWSIotQos.QOS0);
	}
	
	@Override
	public void onMessage(AWSIotMessage iotMessage){
		System.out.println(iotMessage.getStringPayload());
	}
}
