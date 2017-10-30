package capstone.tokenmgmt;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class DeviceCertificateManagement {
	private Connection dbConnection = null;
    
	public DeviceCertificateManagement() {
	}
	
	 public void insertCertificates(List<AwsIoTDeviceCertificate> deviceCerts) throws SQLException{
		 dbConnection = getConnection();
		 PreparedStatement preparedStatement = null;
		 String query = "insert into Certificates (CertificateId, CertificateArn, CertificatePem, PublicKey, PrivateKey, Status) values (?, ?, ?, ?, ?, ?)";
		 try{
			 preparedStatement = dbConnection.prepareStatement(query);
			 dbConnection.setAutoCommit(false);
			 for (AwsIoTDeviceCertificate deviceCert : deviceCerts){
				 preparedStatement.setString(1, deviceCert.getCertId());
				 preparedStatement.setString(2, deviceCert.getCertArn());
				 preparedStatement.setString(3, deviceCert.getCertPem());
				 preparedStatement.setString(4, deviceCert.getPublicKey());
				 preparedStatement.setString(5, deviceCert.getPrivateKey());
				 preparedStatement.setString(6, deviceCert.getStatus());
				 preparedStatement.addBatch();
			 }
			 
			 preparedStatement.executeBatch();
			 dbConnection.commit();
		 }catch(SQLException ex){
			 ex.printStackTrace();
		 }finally{
			 if (preparedStatement != null){
				 preparedStatement.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
	 }
	 
	 public void insertDevices(List<Device> devices) throws SQLException{
		 dbConnection = getConnection();
		 PreparedStatement ps = null;
		 String query = "insert into Devices (DeviceId, CertificateId, DeviceStatus) values (?, ?, ?)";
		 try{
			 ps = dbConnection.prepareStatement(query);
			 dbConnection.setAutoCommit(false);
			 for (Device device : devices){
				 ps.setString(1, device.getDeviceId());
				 ps.setString(2, device.getCertId());
				 ps.setString(3, device.getDeviceStatus());
				 ps.addBatch();
			 }
			 
			 ps.executeBatch();
			 dbConnection.commit();
		 } catch (SQLException ex){
			 ex.printStackTrace();
		 }finally{
			 if (ps != null){
				 ps.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
	 }
	 
	 public void deleteDevices(List<Device> devices) throws SQLException{
		 dbConnection = getConnection();
		 PreparedStatement ps = null;
		 String query = "delete from Devices where DeviceId = ?";
		 try{
			 ps = dbConnection.prepareStatement(query);
			 dbConnection.setAutoCommit(false);
			 for (Device device : devices){
				 ps.setString(1, device.getDeviceId());
				 ps.addBatch();
			 }
			 
			 ps.executeBatch();
			 dbConnection.commit();
		 } catch (SQLException ex){
			 ex.printStackTrace();
		 }finally{
			 if (ps != null){
				 ps.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
	 }
	 
	 
	 public void updateDeviceStatus(List<Device> devices, String status) throws SQLException{
		 dbConnection = getConnection();
		 PreparedStatement ps = null;
		 String query = "update Devices set DeviceStatus = ? WHERE DeviceId = ?";
		 try{
			 ps = dbConnection.prepareStatement(query);
			 dbConnection.setAutoCommit(false);
			 for (Device device : devices){
				 ps.setString(1, status);
				 ps.setString(2, device.getDeviceId());
				 ps.addBatch();
			 }
			 
			 ps.executeBatch();
			 dbConnection.commit();
		 } catch (SQLException ex){
			 ex.printStackTrace();
		 } finally{
			 if (ps != null){
				 ps.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
	 }
	 
	 public void updateDeviceStatus(String deviceId, String status) throws SQLException{
		 dbConnection = getConnection();
		 PreparedStatement ps = null;
		 String query = "update Devices set DeviceStatus = ? WHERE DeviceId = ?";
		 try{
			 ps = dbConnection.prepareStatement(query);
			 dbConnection.setAutoCommit(false);
			 ps.setString(1, status);
			 ps.setString(2, deviceId);
			 ps.executeUpdate();
			 dbConnection.commit();
		 } catch (SQLException ex){
			 ex.printStackTrace();
		 } finally{
			 if (ps != null){
				 ps.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
	 }
	 
	 public void updateDeviceCertificate(String oldCertificateId, String newCertificateId) throws SQLException{
		 dbConnection = getConnection();
		 PreparedStatement ps = null;
		 String query = "update Devices set CertificateId = ? WHERE CertificateId = ?";
		 try{
			 ps = dbConnection.prepareStatement(query);
			 dbConnection.setAutoCommit(false);
			 ps.setString(1, newCertificateId);
			 ps.setString(2, oldCertificateId);			 
			 ps.executeUpdate();
			 dbConnection.commit();
		 } catch (SQLException ex){
			 ex.printStackTrace();
		 } finally{
			 if (ps != null){
				 ps.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
	 }
	  
	 public AwsIoTDeviceCertificate retrieveCert(String certificateId) throws SQLException{
		 dbConnection = getConnection();
		 AwsIoTDeviceCertificate awsIoTDeviceCertificate = null;
		 PreparedStatement ps = null;
		 String query = "select CertificateId, CertificateArn, CertificatePem, PublicKey, PrivateKey, Status from Certificates where CertificateId = ?";
		 try{
			 ps = dbConnection.prepareStatement(query);
			 ps.setString(1, certificateId);
			 ResultSet rs = ps.executeQuery();
			 while (rs.next()){
				 String certId = rs.getString("CertificateId");
				 String certArn = rs.getString("CertificateArn");
				 String certPem = rs.getString("CertificatePem");
				 String pubKey = rs.getString("PublicKey");
				 String priKey = rs.getString("PrivateKey");
				 String status = rs.getString("Status");
				 awsIoTDeviceCertificate = new AwsIoTDeviceCertificate(certId, certArn, certPem, pubKey, priKey, status);
			 }
			 
		 } catch (SQLException ex){
			 ex.printStackTrace();
		 } finally {
			 if (ps != null){
				 ps.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
		 
		 return awsIoTDeviceCertificate;
	 }
	 
	 public void updateCertificateStatus(String certId, String status) throws SQLException{
		 dbConnection = getConnection();
		 PreparedStatement preparedStatement = null;
		 String query = "update Certificates set Status = ? WHERE CertificateId = ?";
		 try{
			 preparedStatement = dbConnection.prepareStatement(query);
			 preparedStatement.setString(1, status);
			 preparedStatement.setString(2, certId);
			 preparedStatement.executeUpdate();
		 }catch(SQLException ex){
			 ex.printStackTrace();
		 }finally{
			 if (preparedStatement != null){
				 preparedStatement.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
	 }

	 
	 public List<Device> getDevices(String certId, String status) throws SQLException{
		 dbConnection = getConnection();
	     String query = "";	
		 PreparedStatement ps = null;
		 List<Device> devices = new ArrayList<Device>();
		 try{
			 if (certId == null || certId.length() == 0){
				 query = "select DeviceId, CertificateId, DeviceStatus from Devices where DeviceStatus = ?";
				 ps = dbConnection.prepareStatement(query);
				 ps.setString(1, status);
			 }
			 else {
				 query = "select DeviceId, CertificateId, DeviceStatus from Devices where CertificateId = ? and DeviceStatus = ?";
				 ps = dbConnection.prepareStatement(query);
				 ps.setString(1, certId);
				 ps.setString(2, status);
			 }
			
			 ResultSet rs = ps.executeQuery();
			 while (rs.next()){
				 String deviceId = rs.getString("DeviceId");
				 String cerificateId = rs.getString("CertificateId");
				 String deviceStatus = rs.getString("DeviceStatus");
				 Device device = new Device(deviceId, cerificateId, deviceStatus);
				 devices.add(device);
			 }
			 
		 } catch (SQLException ex){
			 ex.printStackTrace();
		 } finally {
			 if (ps != null){
				 ps.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
		 
		 return devices;
	 }
	 
	 public List<Device> getDevicesAssociatedWithCert(String certId) throws SQLException{
		 dbConnection = getConnection();
		 PreparedStatement ps = null;
		 List<Device> devices = new ArrayList<Device>();
		 try{		
			 String query = "select DeviceId, CertificateId, DeviceStatus from Devices where CertificateId = ?";
			 ps = dbConnection.prepareStatement(query);
			 ps.setString(1, certId);			
			 ResultSet rs = ps.executeQuery();
			 while (rs.next()){
				 String deviceId = rs.getString("DeviceId");
				 String cerificateId = rs.getString("CertificateId");
				 String status = rs.getString("DeviceStatus");
				 Device device = new Device(deviceId, cerificateId, status);
				 devices.add(device);
			 }
			 
		 } catch (SQLException ex){
			 ex.printStackTrace();
		 } finally {
			 if (ps != null){
				 ps.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
		 
		 return devices;
	 }
	 
	 public List<Device> getDevices(String devId) throws SQLException{ 	 
		 dbConnection = getConnection();
		 PreparedStatement ps = null;
		 List<Device> devices = new ArrayList<Device>();
		 try{
			
			 String query = "select DeviceId, CertificateId, DeviceStatus from Devices where DeviceId = ?";
			 ps = dbConnection.prepareStatement(query);
			 ps.setString(1, devId);			
			 ResultSet rs = ps.executeQuery();
			 while (rs.next()){
				 String deviceId = rs.getString("DeviceId");
				 String cerificateId = rs.getString("CertificateId");
				 String status = rs.getString("DeviceStatus");
				 Device device = new Device(deviceId, cerificateId, status);
				 devices.add(device);
			 }
			 
		 } catch (SQLException ex){
			 ex.printStackTrace();
		 } finally {
			 if (ps != null){
				 ps.close();
			 }
			 if (dbConnection != null){
				 dbConnection.close();
			 }
		 }
		 
		 return devices;
	 }
	 
     public String getCertArn(String certId) throws SQLException{
		 dbConnection = getConnection();
    	 String certArn = "";
		 PreparedStatement ps = null;
		 try{
			 String query = "select CertificateArn from Certificates where CertificateId = ?";
			 ps = dbConnection.prepareStatement(query);
			 ps.setString(1, certId);			
			 ResultSet rs = ps.executeQuery();
			 while (rs.next()){
				 certArn = rs.getString("CertificateArn");
			 }
		 } catch(SQLException ex){
			 ex.printStackTrace();
		 } finally{
			 if (ps != null)
				 ps.close();
			 if (dbConnection != null)
				 dbConnection.close();
		 }
		
		return certArn;
     }
	 
	 private static Connection getConnection(){
		    Connection dbConnection = null;
			try {
				Class.forName("com.mysql.jdbc.Driver");
				dbConnection = DriverManager.getConnection("jdbc:mysql://localhost:3306/TokenManagement","root", "root");
			} catch (SQLException | ClassNotFoundException e) {
				e.printStackTrace();
			}
			
			return dbConnection;
		}
}
