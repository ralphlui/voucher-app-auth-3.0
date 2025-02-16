package voucher.management.app.auth.controller;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import voucher.management.app.auth.dto.APIResponse;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.dto.ValidationResult;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuditLogInvalidUser;
import voucher.management.app.auth.enums.AuditLogResponseStatus;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.service.impl.AuditLogService;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.strategy.impl.UserValidationStrategy;
import voucher.management.app.auth.utility.DTOMapper;
import voucher.management.app.auth.utility.GeneralUtility;

import org.springframework.data.domain.Sort;

@RestController
@RequestMapping("/api/users")
public class UserController {

	private static final Logger logger = LoggerFactory.getLogger(UserController.class);

	@Autowired
	private UserService userService;

	@Autowired
	private UserValidationStrategy userValidationStrategy;
	
	@Autowired
	private AuditLogService auditLogService;
	
	private String auditLogResponseSuccess = AuditLogResponseStatus.SUCCESS.toString();
	private String auditLogResponseFailure = AuditLogResponseStatus.FAILED.toString();
	private String auditLogUserId = AuditLogInvalidUser.InvalidUserID.toString();
	private String auditLogUserName = AuditLogInvalidUser.InvalidUserName.toString();
	private String genericErrorMessage = "An error occurred while processing your request. Please try again later.";
	

	@GetMapping(value = "", produces = "application/json")
	public ResponseEntity<APIResponse<List<UserDTO>>> getAllActiveUsers(@RequestHeader("X-User-Id") String userID,
			@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "500") int size) {
		logger.info("Call user getAll API with page={}, size={}", page, size);
		String message = "";
		String activityType = "Authentication-RetrieveAllActiveUsers";
		String apiEndPoint = "api/users";
		String httpMethod = HttpMethod.GET.name();
		String activityDesc = "Retreving active user list is failed due to ";
		

		try {
			getUserByUserID(userID);
			
			Pageable pageable = PageRequest.of(page, size, Sort.by("username").ascending());
			Map<Long, List<UserDTO>> resultMap = userService.findActiveUsers(pageable);
			logger.info("all active user list size " + resultMap.size());

			Map.Entry<Long, List<UserDTO>> firstEntry = resultMap.entrySet().iterator().next();
			long totalRecord = firstEntry.getKey();
			List<UserDTO> userDTOList = firstEntry.getValue();

			logger.info("totalRecord: " + totalRecord);
			logger.info("userDTO List: " + userDTOList);
			

			if (userDTOList.size() > 0) {
				message = "Successfully get all active verified user.";
				return handleResponseListAndsendAuditLogForSuccessCase(userDTOList,
						activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName, totalRecord);

			} else {
			    message = "No Active User List.";
			    return handleEmptyResponseListAndsendAuditLogForSuccessCase(userDTOList,
						activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName, totalRecord);

			}		

		} catch (Exception e) {
			return handleResponseListAndsendAuditLogForExceptionCase(e,
					activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
	}

	@PostMapping(value = "", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> createUser(@RequestBody UserRequest userRequest) {
		logger.info("Call user create API...");
		String message;
		String activityType = "Authentication-CreateUser";
		String apiEndPoint = "api/users";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "User registration is failed due to ";

		try {
			ValidationResult validationResult = userValidationStrategy.validateCreation(userRequest);
			auditLogUserName = validationResult.getUserName();
			if (validationResult.isValid()) {

				UserDTO userDTO = userService.createUser(userRequest);
				message = userRequest.getEmail() + " is created successfully";
				return handleResponseAndsendAuditLogForSuccessCase(userDTO,
						activityType, message, apiEndPoint, httpMethod);
			} else {
				return handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}
		} catch (Exception e) {
			return handleResponseAndsendAuditLogForExceptionCase(e,
					HttpStatus.INTERNAL_SERVER_ERROR, activityType, activityDesc, apiEndPoint, httpMethod);
		}

	}

	@PostMapping(value = "/login", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> loginUser(@RequestBody UserRequest userRequest) {
		logger.info("Call user login API...");
		String message = "";
		String activityType = "Authentication-LoginUser";
		String apiEndPoint = "api/users/login";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "User failed to login due to ";

		try {
			ValidationResult validationResult =  userValidationStrategy.validateObject(userRequest.getEmail());
			auditLogUserId = validationResult.getUserId();
			auditLogUserName = validationResult.getUserName();
					
			if (!validationResult.isValid()) {
				
				logger.error("Login Validation Error: " + validationResult.getMessage());
				return handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}

			UserDTO userDTO = userService.loginUser(userRequest.getEmail(), userRequest.getPassword());
			message = userDTO.getEmail() + " login successfully";
			return handleResponseAndsendAuditLogForSuccessCase(userDTO,
					activityType, message, apiEndPoint, httpMethod);
			
		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.UNAUTHORIZED : HttpStatus.INTERNAL_SERVER_ERROR;
			return handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod);
		}
	}

	@PatchMapping(value = "/verify/{verifyid}", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> verifyUser(@RequestHeader("X-User-Id") String userID,
			@PathVariable("verifyid") String verifyid) {

		logger.info("Call user verify API with verifyToken={}", verifyid);
		verifyid = GeneralUtility.makeNotNull(verifyid);
		String message = "";
		String activityType = "Authentication-VerifyUser";
		String apiEndPoint = String.format("api/users/verify/%s", verifyid);
		String httpMethod = HttpMethod.PATCH.name();
		String activityDesc = "User verification is failed due to ";

		try {
			getUserByUserID(userID);
			
			if (!verifyid.isEmpty()) {
				UserDTO verifiedUserDTO = userService.verifyUser(verifyid);
				message = "User successfully verified.";
				return handleResponseAndsendAuditLogForSuccessCase(verifiedUserDTO, activityType, message, apiEndPoint,
						httpMethod);
			} else {

				message = "Vefriy Id could not be blank.";
				logger.error(message);
				auditLogService.sendAuditLogToSqs(Integer.toString(HttpStatus.BAD_REQUEST.value()), auditLogUserId,
						auditLogUserName, activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod,
						message);
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(APIResponse.error(message));
			}
		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
					apiEndPoint, httpMethod);
		}

	}

	@PatchMapping(value = "/{id}/resetPassword", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> resetPassword(@RequestHeader("X-User-Id") String userID, @PathVariable("id") String id, @RequestBody UserRequest resetPwdReq) {

		logger.info("Call user resetPassword API...");

		logger.info("Reset Password : " + resetPwdReq.getEmail());
		
		String activityType = "Authentication-ResetPassword";
		String apiEndPoint =  String.format("api/users/%s/resetPassword", id);
		String httpMethod = HttpMethod.PATCH.name();
		String activityDesc = "Reset password is failed due to ";
	

		String message = "";
		try {
			ValidationResult validationResult = validateObjectByUseId(userID, id);
			if (!validationResult.isValid()) {
				logger.error("Reset passwrod validation is not successful");
				return handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}

			UserDTO userDTO = userService.resetPassword(id, resetPwdReq.getPassword());
			message = "Reset Password is completed.";
			return handleResponseAndsendAuditLogForSuccessCase(userDTO,
					activityType, message, apiEndPoint, httpMethod);

		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND : HttpStatus.INTERNAL_SERVER_ERROR;
			return handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod);
		}

	}

	@PutMapping(value = "/{id}", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> updateUser(@RequestHeader("X-User-Id") String userID,
			@PathVariable("id") String id, @RequestBody UserRequest userRequest) {
		logger.info("Call user update API...");
		String message;
		String activityType = "Authentication-UpdateUser";
		String apiEndPoint = String.format("api/users/%s", id);
		String httpMethod = HttpMethod.PUT.name();
		String activityDesc = "Update User failed due to ";

		try {
			String userId = id.isEmpty() ? userID : id;
			ValidationResult validationResult = userValidationStrategy.validateUpdating(userId);
			auditLogUserId = validationResult.getUserId();
			auditLogUserName = validationResult.getUserName();

			if (validationResult.isValid()) {

				userRequest.setUserId(userId);
				UserDTO userDTO = userService.update(userRequest);
				message = "User updated successfully.";
				return handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message, apiEndPoint,
						httpMethod);

			} else {
				return handleResponseAndsendAuditLogForValidationFailure(validationResult, activityType, activityDesc,
						apiEndPoint, httpMethod);
			}
		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
					apiEndPoint, httpMethod);

		}
	}

	@GetMapping(value = "/{id}/active", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> checkSpecificActiveUser(@RequestHeader("X-User-Id") String userID, @PathVariable("id") String id) {
		logger.info("Call user active API...");
		logger.info("User ID" + id);
		String message = "";
		String activityType = "Authentication-RetrieveActiveUserByUserId";
		String apiEndPoint = String.format("api/users/%s/active", id);
		String httpMethod = HttpMethod.GET.name();
		String activityDesc = "Retrieving active user by id failed due to ";

		try {
			ValidationResult validationResult = validateObjectByUseId(userID, id);
			
			if (!validationResult.isValid()) {
				
				logger.error("Active user validation is not successful");
				return handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
				
			}

			UserDTO userDTO = userService.checkSpecificActiveUser(validationResult.getUserId());
			message = userDTO.getEmail() + " is Active";	
			return  handleResponseAndsendAuditLogForSuccessCase(userDTO,
					activityType, message, apiEndPoint, httpMethod);
			

		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod);
		}
	}

	@GetMapping(value = "/preferences/{name}", produces = "application/json")
	public ResponseEntity<APIResponse<List<UserDTO>>> getAllUsersByPreferences(@RequestHeader("X-User-Id") String userID,
			@PathVariable("name") String name, @RequestParam(defaultValue = "0") int page,
			@RequestParam(defaultValue = "500") int size) {
		logger.info("Call user getAll API By Preferences with page={}, size={}", page, size);
		
		String activityType = "Authentication-RetrieveActiveUserListByPreference";
		String apiEndPoint = String.format("api/users/preferences/%s", name);
		String httpMethod = HttpMethod.GET.name();
		String activityDesc = "Retreving active user list by preference name is failed due to ";

		try {
			getUserByUserID(userID);
			String message = "";
			
			Pageable pageable = PageRequest.of(page, size, Sort.by("username").ascending());
			Map<Long, List<UserDTO>> resultMap = userService.findUsersByPreferences(name, pageable);
			
			Map.Entry<Long, List<UserDTO>> firstEntry = resultMap.entrySet().iterator().next();
			long totalRecord = firstEntry.getKey();
			List<UserDTO> userDTOList = firstEntry.getValue();
			
			logger.info("totalRecord: " + totalRecord);
			logger.info("userDTO List: " + userDTOList);

			if (userDTOList.size() > 0) {
			    message = "Successfully get all active users by this preference.";
				return handleResponseListAndsendAuditLogForSuccessCase(userDTOList,
						activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName, totalRecord);
			} else {
			    message = "No user list by this preference.";
			    return handleEmptyResponseListAndsendAuditLogForSuccessCase(userDTOList,
						activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName, totalRecord);
			}

		} catch (Exception e) {
			return handleResponseListAndsendAuditLogForExceptionCase(e,
					activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
	}
	
	@DeleteMapping(value = "/{id}/preferences", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> deletePreferenceByUser(@RequestHeader("X-User-Id") String userID,
			@PathVariable("id") String id, @RequestBody UserRequest userRequest) {
		logger.info("Call user Delete Preferences API...");
		String message;
		String activityType = "Authentication-DeleteUserPreferenceByUserId";
		String apiEndPoint = String.format("api/users/%s/preferences", id);
		String httpMethod = HttpMethod.DELETE.name();
		String activityDesc = "Delete user preference by preference is failed due to ";

		try {
			ValidationResult validationResult = validateObjectByUseId(userID, id);

			if (validationResult.isValid()) {

				UserDTO userDTO = userService.deletePreferencesByUser(validationResult.getUserId(),
						userRequest.getPreferences());
				message = "Preferences are deleted successfully.";
				return handleResponseAndsendAuditLogForSuccessCase(userDTO,
						activityType, message, apiEndPoint, httpMethod);
			} else {
				return handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}
		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.BAD_REQUEST;
			return handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod);
		}

	}
	
	
	@PatchMapping(value = "/{id}/preferences", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> updatePreferenceByUser(@RequestHeader("X-User-Id") String userID,
			@PathVariable("id") String id, @RequestBody UserRequest userRequest) {
		logger.info("Call user update Preferences API...");
		String message;
		String activityType = "Authentication-UpdateUserPreferenceByUserId";
		String apiEndPoint = String.format("api/users/%s/preferences", id);
		String httpMethod = HttpMethod.PATCH.name();
		String activityDesc = "Update user preference by preference is failed due to ";

		try {
			ValidationResult validationResult = validateObjectByUseId(userID, id);

			if (validationResult.isValid()) {

				UserDTO userDTO = userService.updatePreferencesByUser(validationResult.getUserId(),
						userRequest.getPreferences());
				message = "Preferences are updated successfully.";
				return handleResponseAndsendAuditLogForSuccessCase(userDTO,
						activityType, message, apiEndPoint, httpMethod);
			} else {
				return handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}
		} catch (Exception e) {

			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.BAD_REQUEST;
			return handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod);
		}

	}
	
	
	@PostMapping(value = "/logout", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> lgoutUser(@RequestHeader("X-User-Id") String userID) {
		logger.info("Call user update Preferences API...");
		String message;
		String activityType = "Authentication-Logout";
		String apiEndPoint = "/api/users/logout";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Logging out user is failed due to ";

		try {
			User user = userService.findByUserId(userID);
			if (user != null) {
				message = "User logout successfully";
				return handleResponseAndsendAuditLogForSuccessCase(DTOMapper.toUserDTO(user),
						activityType, message, apiEndPoint, httpMethod);
			} else {
				message = "User not found";
				logger.error(message);
				auditLogService.sendAuditLogToSqs(Integer.toString(HttpStatus.NOT_FOUND.value()), userID, auditLogUserName, activityType, activityDesc.concat(message), apiEndPoint, auditLogResponseFailure, httpMethod, message);
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(APIResponse.error(message));
				

			}
		} catch (Exception e) {
		   return handleResponseAndsendAuditLogForExceptionCase(e,
				   HttpStatus.INTERNAL_SERVER_ERROR, activityType, activityDesc, apiEndPoint, httpMethod);
		}

	}
	
	

	
	private ValidationResult validateObjectByUseId(String userID, String id) {
		
		String userId = id.isEmpty() ? userID : id;
		ValidationResult validationResult = userValidationStrategy.validateObjectByUserId(userId);
		auditLogUserId = validationResult.getUserId();
		auditLogUserName = validationResult.getUserName();
		return validationResult;
	}
	
	private ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForValidationFailure(ValidationResult validationResult, String activityType, String activityDesc, String apiEndPoint, String httpMethod) {
		String message = validationResult.getMessage();
		logger.error(message);
		activityDesc = activityDesc.concat(message);
		auditLogService.sendAuditLogToSqs(Integer.toString(validationResult.getStatus().value()), validationResult.getUserId(), validationResult.getUserName(), activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, message);
		return ResponseEntity.status(validationResult.getStatus()).body(APIResponse.error(validationResult.getMessage()));
		
	}
	
	private ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForExceptionCase(Exception e, HttpStatusCode htpStatuscode, String activityType, String activityDesc, String apiEndPoint, String httpMethod ) {
		String message = e.getMessage();
		String responseMessage = e instanceof UserNotFoundException ? e.getMessage() : genericErrorMessage;
		logger.error("Error: " + message);
		activityDesc = activityDesc.concat(message);
		auditLogService.sendAuditLogToSqs(Integer.toString(htpStatuscode.value()), auditLogUserId, auditLogUserName, activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, message);	
		return ResponseEntity.status(htpStatuscode).body(APIResponse.error(responseMessage));
	}
	
	private ResponseEntity<APIResponse<UserDTO>> handleResponseAndsendAuditLogForSuccessCase(UserDTO userDTO, String activityType, String message, String apiEndPoint, String httpMethod) {
		logger.info(message);
		HttpStatus httpStatus = HttpStatus.OK;
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userDTO.getUserID(), userDTO.getUsername(), activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
		return ResponseEntity.status(httpStatus).body(APIResponse.success(userDTO, message));
	}
	
	private ResponseEntity<APIResponse<List<UserDTO>>> handleResponseListAndsendAuditLogForSuccessCase(List<UserDTO> userDTOList, String activityType, String message, String apiEndPoint, String httpMethod, String userId, String userName, long totalRecord) {
		logger.info(message);
		HttpStatus httpStatus = HttpStatus.OK;
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userId, userName, activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
		return ResponseEntity.status(httpStatus).body(
				APIResponse.success(userDTOList, message, totalRecord));
	}
	
	private ResponseEntity<APIResponse<List<UserDTO>>> handleEmptyResponseListAndsendAuditLogForSuccessCase(List<UserDTO> userDTOList, String activityType, String message, String apiEndPoint, String httpMethod, String userId, String userName, long totalRecord) {
		logger.info(message);
		HttpStatus httpStatus = HttpStatus.OK;
		auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), userId, userName, activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
		return ResponseEntity.status(httpStatus).body(APIResponse.noList(userDTOList, message));
	}
	
	private ResponseEntity<APIResponse<List<UserDTO>>> handleResponseListAndsendAuditLogForExceptionCase(Exception e, String activityType, String activityDesc, String apiEndPoint, String httpMethod, String userId, String userName) {
		String message = e.getMessage();
		String responseMessage = e instanceof UserNotFoundException ? e.getMessage() : genericErrorMessage;
		logger.error("Error: " + message);
		activityDesc = activityDesc.concat(message);
		auditLogService.sendAuditLogToSqs(Integer.toString(HttpStatus.NOT_FOUND.value()), userId, userName, activityType, activityDesc, apiEndPoint, auditLogResponseSuccess, httpMethod, message);
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(APIResponse.error(responseMessage));
	}
	
	private void getUserByUserID(String userID) {
		auditLogUserId = userID;
		
		if (!userID.isEmpty()) {
			User user = userService.findByUserId(userID);
			if (user != null) {
				auditLogUserId = user.getUserId();
				auditLogUserName = user.getUsername();
			}
		} 
	}

}
