package voucher.management.app.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import voucher.management.app.auth.dto.APIResponse;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.dto.ValidationResult;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuditLogInvalidUser;
import voucher.management.app.auth.enums.AuditLogResponseStatus;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.service.impl.AuditLogService;
import voucher.management.app.auth.service.impl.OTPStorageService;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.strategy.impl.UserValidationStrategy;

@RestController
@RequestMapping("/api/otp")
public class OTPController {

	private static final Logger logger = LoggerFactory.getLogger(UserController.class);

	@Autowired
	private OTPStorageService otpService;

	@Autowired
	private UserValidationStrategy userValidationStrategy;

	@Autowired
	private UserService userService;

	@Autowired
	private AuditLogService auditLogService;

	private String auditLogResponseSuccess = AuditLogResponseStatus.SUCCESS.toString();
	private String auditLogResponseFailure = AuditLogResponseStatus.FAILED.toString();
	private String auditLogUserId = AuditLogInvalidUser.InvalidUserID.toString();
	private String auditLogUserName = AuditLogInvalidUser.InvalidUserName.toString();
	private String genericErrorMessage = "An error occurred while processing your request. Please try again later.";

	@PostMapping("/generate")
	public ResponseEntity<APIResponse<UserDTO>> generateOtp(@RequestHeader("X-User-Id") String userID,
			@RequestBody UserRequest userRequest) {

		String message = "";
		String activityType = "Authentication-GenerateOTP";
		String apiEndPoint = "api/opt";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Generating OTP is failed due to ";

		try {
			// check userEmail is valid
			logger.info("Reset Password : " + userRequest.getEmail());
			ValidationResult validationResult = userValidationStrategy.validateObject(userRequest.getEmail());
			if (!validationResult.isValid()) {

				logger.error("Generate OTP validation is not successful");
				return handleResponseAndsendAuditLogForValidationFailure(validationResult, activityType, activityDesc,
						apiEndPoint, httpMethod);
			}

			int otp = otpService.generateAndStoreOTP(userRequest.getEmail());
			// otpService.sendOTPEmail(email, otp);

			if (otp > 0) {
				message = "OTP sent to "+ userRequest.getEmail() + ". It is valid for 10 minutes.";
			}
			// otpService.sendOTPEmail(email, otp);
			UserDTO userDTO = userService.checkSpecificActiveUser(userID);

			return handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message, apiEndPoint, httpMethod);

		} catch (Exception e) {
			message = "OTP code generation failed.";
			logger.error("generateOtp Error: " + message);
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
					apiEndPoint, httpMethod);
		}
	}

	@PostMapping("/validate")
	public ResponseEntity<APIResponse<UserDTO>> validateOtp(@RequestHeader("X-User-Id") String userID,
			@RequestBody UserRequest userRequest) {

		String message = "";
		String activityType = "Authentication-GenerateOTP";
		String apiEndPoint = "api/opt";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Validating OTP is failed due to ";

		try {

			logger.info("Reset Password : " + userRequest.getEmail());
			ValidationResult validationResult = userValidationStrategy.validateObject(userRequest.getEmail());
			if (!validationResult.isValid()) {

				logger.error("Generate OTP validation is not successful");
				return handleResponseAndsendAuditLogForValidationFailure(validationResult, activityType, activityDesc,
						apiEndPoint, httpMethod);
			}

			message = "";
			boolean isValid = otpService.validateOTP(userRequest.getEmail(), userRequest.getOtp());
			if (isValid) {
				message = "OTP is valid.";
			} else {
				message = "OTP expired or incorrect";
			}

			UserDTO userDTO = userService.checkSpecificActiveUser(userID);

			return handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message, apiEndPoint, httpMethod);

		} catch (Exception e) {
			message = "OTP code validation failed.";

			logger.error("validateOtp Error: " + message);
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
					apiEndPoint, httpMethod);

		}
	}

	private ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForValidationFailure(
			ValidationResult validationResult, String activityType, String activityDesc, String apiEndPoint,
			String httpMethod) {
		String message = validationResult.getMessage();
		logger.error(message);
		activityDesc = activityDesc.concat(message);
		auditLogService.sendAuditLogToSqs(Integer.toString(validationResult.getStatus().value()),
				validationResult.getUserId(), validationResult.getUserName(), activityType, activityDesc, apiEndPoint,
				auditLogResponseFailure, httpMethod, message);
		return ResponseEntity.status(validationResult.getStatus())
				.body(APIResponse.error(validationResult.getMessage()));

	}

	private ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForSuccessCase(UserDTO userDTO,
			String activityType, String message, String apiEndPoint, String httpMethod) {
		logger.info(message);
		HttpStatus httpStatus = HttpStatus.OK;
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userDTO.getUserID(),
				userDTO.getUsername(), activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
		return ResponseEntity.status(httpStatus).body(APIResponse.success(userDTO, message));
	}

	private <T> ResponseEntity<APIResponse<T>> handleResponseAndsendAuditLogForExceptionCase(Exception e,
			HttpStatusCode htpStatuscode, String activityType, String activityDesc, String apiEndPoint,
			String httpMethod) {
		String message = e.getMessage();
		String responseMessage = e instanceof UserNotFoundException ? e.getMessage() : genericErrorMessage;
		logger.error("Error: " + message);
		activityDesc = activityDesc.concat(message);
		auditLogService.sendAuditLogToSqs(Integer.toString(htpStatuscode.value()), auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, message);
		return ResponseEntity.status(htpStatuscode).body(APIResponse.error(responseMessage));
	}

}
