package voucher.management.app.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import voucher.management.app.auth.dto.*;
import voucher.management.app.auth.enums.AuditLogInvalidUser;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.service.impl.*;
import voucher.management.app.auth.strategy.impl.*;
import voucher.management.app.auth.utility.CookieUtils;
import voucher.management.app.auth.utility.GeneralUtility;

@RestController
@RequestMapping("/api/users/otp")
public class OTPController {

	private static final Logger logger = LoggerFactory.getLogger(OTPController.class);

	private final OTPService otpService;

	private final UserValidationStrategy userValidationStrategy;

	private final UserService userService;

	private final CookieUtils cookieUtils;

	private final APIResponseStrategy apiResponseStrategy;

	public OTPController(OTPService otpService, UserValidationStrategy userValidationStrategy, UserService userService,
			CookieUtils cookieUtils, APIResponseStrategy apiResponseStrategy) {
		this.otpService = otpService;
		this.userValidationStrategy = userValidationStrategy;
		this.userService = userService;
		this.cookieUtils = cookieUtils;
		this.apiResponseStrategy = apiResponseStrategy;
	}

	private String auditLogUserId = AuditLogInvalidUser.InvalidUserID.toString();
	private String auditLogUserName = AuditLogInvalidUser.InvalidUserName.toString();

	@PostMapping(value = "/generate", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> generateOtp(@RequestBody UserRequest userRequest) {

		String message = "";
		String activityType = "Authentication-GenerateOTP";
		String apiEndPoint = "api/otp";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Generating OTP is failed due to ";
		
        AuditLogRequest auditReq = new AuditLogRequest(activityDesc, activityDesc, message, activityType, activityDesc, apiEndPoint, activityType, apiEndPoint, activityDesc);

		try {
			// Check if userEmail is valid
			logger.info("Generate OTP request received.");

			ValidationResult validationResult = userValidationStrategy.validateObject(userRequest.getEmail());
			if (!validationResult.isValid()) {

				logger.error("Generate OTP validation is not successful");
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod, validationResult.getUserId(),
						validationResult.getUserName());
			}

			auditLogUserId = validationResult.getUserId();
			auditLogUserName = validationResult.getUserName();

			String otp = otpService.generateOTP(userRequest.getEmail());

			if (!GeneralUtility.makeNotNull(otp).equals("")) {
				message = "OTP sent to " +userRequest.getEmail() + ". It is valid for 10 minutes.";
			}

			// TO Sent Email...

			boolean isSent = otpService.sendOTPEmail(otp, userRequest.getEmail());
			UserDTO userDTO = userService.checkSpecificActiveUserByEmail(userRequest.getEmail());

			if (isSent) {
				auditReq.setActivityDescription(message);
				
				
				return apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(userDTO, message, auditReq);
				
			} else {
				message = "OTP email sending failed.";
				return apiResponseStrategy.handleResponseAndsendAuditLogForFailedCase(userDTO, activityType,
						activityDesc, message, apiEndPoint, httpMethod, HttpStatus.INTERNAL_SERVER_ERROR,
						userDTO.getUserID(), userDTO.getUsername());
			}

		} catch (Exception e) {
			message = "OTP code generation failed.";
			logger.error("generateOtp Error: " + message);
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
	}

	@PostMapping(value = "/validate", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> validateOtp(@RequestBody UserRequest userRequest) {

		String message = "";
		String activityType = "Authentication-ValidateOTP";
		String apiEndPoint = "api/otp";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Validating OTP is failed due to ";

		try {

			logger.info("OTP validation request received.");

			ValidationResult validationResult = userValidationStrategy.validateObject(userRequest.getEmail());
			if (!validationResult.isValid()) {

				logger.error("Generate OTP validation is not successful");
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod, validationResult.getUserId(),
						validationResult.getUserName());
			}

			
			auditLogUserId = validationResult.getUserId();
			auditLogUserName = validationResult.getUserName();
			boolean isValid = otpService.validateOTP(userRequest.getEmail(), userRequest.getOtp());
			UserDTO userDTO = userService.checkSpecificActiveUserByEmail(userRequest.getEmail());

			if (isValid) {
				message = "OTP is valid.";
				HttpHeaders headers = cookieUtils.createCookies(userDTO.getUsername(), userDTO.getEmail(),
						userDTO.getUserID(), null);
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message,
						apiEndPoint, httpMethod, headers, userDTO.getUserID(), userDTO.getUsername());
			} else {
				message = "OTP expired or incorrect";
				return apiResponseStrategy.handleResponseAndsendAuditLogForFailedCase(userDTO, activityType,
						activityDesc, message, apiEndPoint, httpMethod, HttpStatus.BAD_REQUEST, userDTO.getUserID(),
						userDTO.getUsername());
			}

		} catch (Exception e) {
			message = "OTP code validation failed.";

			logger.error("validateOtp Error: " + message);
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);

		}
	}

}