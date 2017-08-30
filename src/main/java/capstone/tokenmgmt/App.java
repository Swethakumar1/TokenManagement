package capstone.tokenmgmt;

import java.security.KeyStoreException;

/**
 * 
 *
 */
public class App 
{
    public static void main( String[] args ) throws KeyStoreException
    {
        AWSIoTConnection aws  = new AWSIoTConnection(5);
        aws.Connect();     
    }
}
