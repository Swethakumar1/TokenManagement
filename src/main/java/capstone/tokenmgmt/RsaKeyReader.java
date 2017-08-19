package capstone.tokenmgmt;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Enumeration;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

public class RsaKeyReader {

	public RsaKeyReader() {
		// TODO Auto-generated constructor stub
	}

	public static Key readRSAKey(String privateKey)
	{
		// Reading from private key file associated with the device.
		/*StringBuilder sb = new StringBuilder();
		try
		{
			DataInputStream dis = new DataInputStream(new FileInputStream(privateKey));
			BufferedReader br = new BufferedReader(new InputStreamReader(dis, "UTF-8"));
			for (String line = br.readLine(); line != null; line = br.readLine()){
				sb.append(line);
			}
		}
		catch (IOException ex)
		{
			ex.printStackTrace();
		}*/
		
		Key key = null;		
		
		// When reading from file.
		// String rsaPrivateKey = getPrivateKey(sb.toString());

		// When not reading from file.
		 String rsaPrivateKey = getPrivateKey(privateKey);
		
		// Generate RSA Key
		try {
 			ASN1Sequence primitive= (ASN1Sequence) ASN1Sequence.fromByteArray(DatatypeConverter.parseBase64Binary(rsaPrivateKey));		
		    Enumeration<?> e = primitive.getObjects();
		    BigInteger v = ((ASN1Integer) e.nextElement()).getValue();
	
		    int version = v.intValue();
		    if (version != 0 && version != 1) {
		        throw new IllegalArgumentException("wrong version for RSA private key");
		    }
		    
		    BigInteger modulus = ((ASN1Integer) e.nextElement()).getValue();
		    BigInteger publicExponent = ((ASN1Integer) e.nextElement()).getValue();
		    BigInteger privateExponent = ((ASN1Integer) e.nextElement()).getValue();
		    BigInteger prime1 = ((ASN1Integer) e.nextElement()).getValue();
		    BigInteger prime2 = ((ASN1Integer) e.nextElement()).getValue();
		    BigInteger exponent1 = ((ASN1Integer) e.nextElement()).getValue();
		    BigInteger exponent2 = ((ASN1Integer) e.nextElement()).getValue();
		    BigInteger coefficient = ((ASN1Integer) e.nextElement()).getValue();
	
		    RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
			key = kf.generatePrivate(spec);
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		return key;
	}
	
	private static String getPrivateKey(String priKey)
	{
		final String startKey = "-----BEGIN RSA PRIVATE KEY-----";
		final String endKey = "-----END RSA PRIVATE KEY----";
		
		if (priKey == null || priKey.length() == 0)
			throw new IllegalArgumentException("Empty private key");
		
		return priKey.replace("\n","").replace(startKey,"").replace(endKey, "");  
	}
}
