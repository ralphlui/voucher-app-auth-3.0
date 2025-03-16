package voucher.management.app.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import voucher.management.app.auth.dto.*;
import voucher.management.app.auth.exception.UserNotFoundException; 
import voucher.management.app.auth.service.impl.*;
import voucher.management.app.auth.strategy.impl.*;
import voucher.management.app.auth.utility.CookieUtils;
import voucher.management.app.auth.utility.GeneralUtility;

@RestController
@RequestMapping("/api/otp")
public class OTPController {

	private static final Logger logger = LoggerFactory.getLogger(UserController.class);

	@Autowired
	private OTPService otpService;

	@Autowired
	private UserValidationStrategy userValidationStrategy;

	@Autowired
	private UserService userService;
	
	@Autowired
	private CookieUtils cookieUtils;
	
	@Autowired
	private APIResponseStrategy apiResponseStrategy;

	@PostMapping(value = "/generate", produces = "application/json")
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
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod);
			}

			String otp = otpService.generateOTP(userRequest.getEmail());
			

			if (!GeneralUtility.makeNotNull(otp).equals("")) {
				message = "OTP sent to "+ userRequest.getEmail() + ". It is valid for 10 minutes.";
			}
			
			//TO Sent Email...
			
			boolean isSent = otpService.sendOTPEmail(otp, userRequest.getEmail());
			UserDTO userDTO = userService.checkSpecificActiveUser(userID);
			
			if (isSent) {
				
				HttpHeaders headers = cookieUtils.createCookies(userDTO.getUsername(),userDTO.getEmail(), userDTO.getUserID(), null);
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message, apiEndPoint, httpMethod, headers);
			} else {
				message = "OTP email sending failed.";
				return apiResponseStrategy.handleResponseAndsendAuditLogForFailedCase(userDTO, activityType, activityDesc, message,
						apiEndPoint, httpMethod,HttpStatus.INTERNAL_SERVER_ERROR);
			}
			

		} catch (Exception e) {
			message = "OTP code generation failed.";
			logger.error("generateOtp Error: " + message);
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod);
		}
	}

	@PostMapping(value = "/validate", produces = "application/json")
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
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod);
			}

			message = "";
			boolean isValid = otpService.validateOTP(userRequest.getEmail(), userRequest.getOtp());
			UserDTO userDTO = userService.checkSpecificActiveUser(userID);
			
			if (isValid) {
				message = "OTP is valid.";
				HttpHeaders headers = cookieUtils.createCookies(userDTO.getUsername(),userDTO.getEmail(), userDTO.getUserID(), null);
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message, apiEndPoint, httpMethod, headers);
			} else {
				message = "OTP expired or incorrect";
				return apiResponseStrategy.handleResponseAndsendAuditLogForFailedCase(userDTO, activityType, activityDesc, message,
						apiEndPoint, httpMethod,HttpStatus.BAD_REQUEST);
			}
			

		} catch (Exception e) {
			message = "OTP code validation failed.";

			logger.error("validateOtp Error: " + message);
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod);

		}
	}
	
}
