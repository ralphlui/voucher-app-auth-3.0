package voucher.management.app.auth.strategy.impl;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import voucher.management.app.auth.dto.APIResponse;
import voucher.management.app.auth.dto.AuditLogRequest;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.ValidationResult;
import voucher.management.app.auth.enums.AuditLogResponseStatus;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.service.impl.AuditLogService;
import voucher.management.app.auth.strategy.IAPIResponseStrategy;

@Service
public class APIResponseStrategy implements IAPIResponseStrategy{
	
	private static final Logger logger = LoggerFactory.getLogger(AuditLogService.class);

	@Autowired
	private AuditLogService auditLogService;
	
	private String auditLogResponseSuccess = AuditLogResponseStatus.SUCCESS.toString();
	private String auditLogResponseFailure = AuditLogResponseStatus.FAILED.toString();
	private String genericErrorMessage = "An error occurred while processing your request. Please try again later.";
	

	
	@Override
	public ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForValidationFailure(
			ValidationResult validationResult, String activityType, String activityDesc, String apiEndPoint,
			String httpMethod, String userId, String userName) {
		String message = validationResult.getMessage();
		logger.error(message);
		activityDesc = activityDesc.concat(message);
		auditLogService.sendAuditLogToSqs(Integer.toString(validationResult.getStatus().value()),
				userId, userName, activityType, activityDesc, apiEndPoint,
				auditLogResponseFailure, httpMethod, message);
		return ResponseEntity.status(validationResult.getStatus())
				.body(APIResponse.error(validationResult.getMessage()));
	}

	/*@Override
	public ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForSuccessCase(UserDTO userDTO,
			String activityType, String message, String apiEndPoint, String httpMethod, String userId, String userName) {
		logger.error(message);
		HttpStatus httpStatus = HttpStatus.OK;
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userId,
				userName, activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
		return ResponseEntity.status(httpStatus).body(APIResponse.success(userDTO, message));
	}*/

	@Override
	public <T> ResponseEntity<APIResponse<T>> handleResponseAndsendAuditLogForExceptionCase(Exception e,
			HttpStatusCode htpStatuscode, String activityType, String activityDesc, String apiEndPoint,
			String httpMethod, String userId, String userName) {
		String message = e.getMessage();
		String responseMessage = e instanceof UserNotFoundException ? e.getMessage() : genericErrorMessage;
		logger.error(message);
		activityDesc = activityDesc.concat(message);
		auditLogService.sendAuditLogToSqs(Integer.toString(htpStatuscode.value()), userId, userName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, message);
		return ResponseEntity.status(htpStatuscode).body(APIResponse.error(responseMessage));
	}
	
	
    public ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForSuccessCase(UserDTO userDTO, String activityType, String message, String apiEndPoint, String httpMethod, HttpHeaders headers, String userId, String userName) {
		logger.info(message);
		HttpStatus httpStatus = HttpStatus.OK;
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userId, userName, activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
		return ResponseEntity.status(httpStatus).headers(headers).body(APIResponse.success(userDTO, message));
	}
	
    public ResponseEntity<APIResponse<List<UserDTO>>> handleResponseListAndsendAuditLogForSuccessCase(List<UserDTO> userDTOList, String activityType, String message, String apiEndPoint, String httpMethod, String userId, String userName, long totalRecord) {
		logger.info(message);
		HttpStatus httpStatus = HttpStatus.OK;
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userId, userName, activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
		return ResponseEntity.status(httpStatus).body(
				APIResponse.success(userDTOList, message, totalRecord));
	}
	
    public ResponseEntity<APIResponse<List<UserDTO>>> handleEmptyResponseListAndsendAuditLogForSuccessCase(List<UserDTO> userDTOList, String activityType, String message, String apiEndPoint, String httpMethod, String userId, String userName, long totalRecord) {
		logger.info(message);
		HttpStatus httpStatus = HttpStatus.OK;
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userId, userName, activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
		return ResponseEntity.status(httpStatus).body(APIResponse.noList(userDTOList, message));
	}
	
    public ResponseEntity<APIResponse<List<UserDTO>>> handleResponseListAndsendAuditLogForExceptionCase(Exception e, String activityType, String activityDesc, String apiEndPoint, String httpMethod, String userId, String userName) {
		String message = e.getMessage();
		String responseMessage = e instanceof UserNotFoundException ? e.getMessage() : genericErrorMessage;
		logger.error("Error: " + message);
		activityDesc = activityDesc.concat(message);
		auditLogService.sendAuditLogToSqs(Integer.toString(HttpStatus.NOT_FOUND.value()), userId, userName, activityType, activityDesc, apiEndPoint, auditLogResponseSuccess, httpMethod, message);
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(APIResponse.error(responseMessage));
	}
	
    public <T> ResponseEntity<APIResponse<T>> handleResponseListAndsendAuditLogForJWTFailure(HttpStatus httpStatus, String userID, String userName, String activityType, String activityDesc, String apiEndPoint, String httpMethod, String message) {
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userID, userName,
				activityType, message, apiEndPoint, auditLogResponseFailure, httpMethod, "");
		return ResponseEntity.status(httpStatus).body(APIResponse.error(message));
	}  
    
    public ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForFailedCase(UserDTO userDTO,
			String activityType,String activityDesc, String message, String apiEndPoint, String httpMethod, HttpStatusCode httpStatus, String userID, String userName) {
		 auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userID,
				 userName, activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod,
					message);
			return ResponseEntity.status(httpStatus).body(APIResponse.error(message));
	}

	@Override
	public ResponseEntity<APIResponse<UserDTO>> handleResponseAndSendAuditLogForSuccessCase(UserDTO userDTO,
			String message, AuditLogRequest auditLogRequest) {
		String activityType = auditLogRequest.getActivityType();
	    String apiEndPoint = auditLogRequest.getRequestActionEndpoint();
	    String httpMethod = auditLogRequest.getRequestType();
	    String userId = userDTO.getUserID();
	    String userName = userDTO.getUsername();

	    logger.info(message);
		HttpStatus httpStatus = HttpStatus.OK;
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userId,
				userName, activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
		return ResponseEntity.status(httpStatus).body(APIResponse.success(userDTO, message));
	}
    

}