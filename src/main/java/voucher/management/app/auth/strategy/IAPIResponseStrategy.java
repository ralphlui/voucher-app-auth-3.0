package voucher.management.app.auth.strategy;
 
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;

import voucher.management.app.auth.dto.APIResponse;
import voucher.management.app.auth.dto.AuditLogRequest;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.ValidationResult;

public interface IAPIResponseStrategy {

	ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForValidationFailure(
			ValidationResult validationResult, String activityType, String activityDesc, String apiEndPoint,
			String httpMethod, String userId, String userName);

	<T> ResponseEntity<APIResponse<T>> handleResponseAndsendAuditLogForExceptionCase(Exception e,
			HttpStatusCode htpStatuscode, String activityType, String activityDesc, String apiEndPoint,

			String httpMethod, String userId, String userName);
	

	ResponseEntity<APIResponse<UserDTO>> handleResponseAndSendAuditLogForSuccessCase(
	        UserDTO userDTO,
	        String message,
	        AuditLogRequest auditLogRequest
	);

}
