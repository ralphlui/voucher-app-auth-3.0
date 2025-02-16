package voucher.management.app.auth.service;

public interface IAuditService {
	
	void sendAuditLogToSqs(String statusCode, String userId, String username, String activityType, String activityDescription,
			String requestActionEndpoint, String responseStatus, String requestType, String remarks);
}
