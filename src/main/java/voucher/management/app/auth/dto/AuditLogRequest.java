package voucher.management.app.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuditLogRequest {

	private String statusCode;
	private String userId;
	private String username;
	private String activityType;
	private String activityDescription;
	private String requestActionEndpoint;
	private String responseStatus;
	private String requestType;
	private String remarks;
}
