package capstone.tokenmgmt;

import java.security.KeyStoreException;
import java.util.UUID;

/**
 * 
 *
 */
public class App 
{
    public static void main( String[] args ) throws KeyStoreException
    {
    	IoTDeviceManagement aws  = new IoTDeviceManagement();
        
        // Connect operations - Batch 1
        
        // Connect single device. Can be a random physical device. -> User/Administrator operation.
        aws.connectDevice(UUID.randomUUID().toString());
        
        // All the below operations can be solely done by administrator.
        // Connect groups of devices.
       // aws.connectDevicesInGroups(deviceGroup);

        // connect devices using existing certificate.
        aws.connectDevicesWithExistingCertificate("1f75aa1ba1dc479184383244be9dece1509ed40c87829258bd10956937b3f27c", 2);
        
        // Get connected devices
        aws.getConnectedDevices();

        // Disconnect all devices
        aws.disconnectAllDevices();
        
        // get all disconnected devices
        aws.getDisconnectedDevices();
        
        
        // Batch 2
        // Reconnect operations.
        aws.reconnectDevice("045eb46b-fdda-431c-9909-fc4824257cad");
        
        // reconnect devices associated with a cert.
        aws.reconnectAllDevicesWithExistingCertificate("b5902f7a92c315d649f838b5f1fb9a15cd6b42331221d7b74adfda4ec438faee");
        
        // get connected devices for a cert.
        aws.getConnectedDevices("b5902f7a92c315d649f838b5f1fb9a15cd6b42331221d7b74adfda4ec438faee");
        
        // disconnect device(s)
        aws.disconnectDevice("045eb46b-fdda-431c-9909-fc4824257cad");
        aws.disconnectDevices("b5902f7a92c315d649f838b5f1fb9a15cd6b42331221d7b74adfda4ec438faee");
        
        // get disconnected devices for certificate
        aws.getDisconnectedDevices("b5902f7a92c315d649f838b5f1fb9a15cd6b42331221d7b74adfda4ec438faee");
        
        // policy operations.
        aws.denyConnectPolicyDevice("045eb46b-fdda-431c-9909-fc4824257cad");
        aws.denyConnectPolicyDevices("b5902f7a92c315d649f838b5f1fb9a15cd6b42331221d7b74adfda4ec438faee");
        
        aws.reconnectDevice("045eb46b-fdda-431c-9909-fc4824257cad");
        aws.reconnectAllDevicesWithExistingCertificate("b5902f7a92c315d649f838b5f1fb9a15cd6b42331221d7b74adfda4ec438faee");
        
        // after the above operations, check in console.
        aws.allowConnectPolicyDevice("045eb46b-fdda-431c-9909-fc4824257cad");
        aws.allowConnectPolicyDevices("b5902f7a92c315d649f838b5f1fb9a15cd6b42331221d7b74adfda4ec438faee");
       
        aws.reconnectDevice("045eb46b-fdda-431c-9909-fc4824257cad");
        aws.reconnectAllDevicesWithExistingCertificate("b5902f7a92c315d649f838b5f1fb9a15cd6b42331221d7b74adfda4ec438faee");
        
        aws.subscribeTopic("d999817c-3e28-4ae8-af30-37d4ea26cb42", "news/finance");
        aws.publishTopic("045eb46b-fdda-431c-9909-fc4824257cad", "news/finance", "India jumps 30 spots in ease of business ranking.");
        aws.disconnectAllDevices();
        
        // Batch 3
        // delete device
        aws.deleteDevice("6db21fdf-0e16-4a5b-9673-dc9d704aa9dd");
        
        // delete devices associated with cert.
        aws.deleteDevices("1f75aa1ba1dc479184383244be9dece1509ed40c87829258bd10956937b3f27c");
        
        // deactivate certificate - after this operation check in console.
        aws.deactivateCertificate("1f75aa1ba1dc479184383244be9dece1509ed40c87829258bd10956937b3f27c");
        
        
        // Policy actions related to Publish, Subscribe, Receive
        aws.denyPublishingToTopic("News/Finance");
        aws.denySubscribingToTopic("News/Finance");
        aws.denyReceivingMessageFromTopic("News/Finance"); 
        aws.allowSubscribingToTopic("News/Finance");
        aws.allowPublishingToTopic("News/Finance");
        aws.allowReceivingMessageFromTopic("News/Finance");
    }
} 
  




