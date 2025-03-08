package voucher.management.app.auth.controller;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.InvalidKeyException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import voucher.management.app.auth.dto.*;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuditLogInvalidUser;
import voucher.management.app.auth.enums.AuditLogResponseStatus;
import voucher.management.app.auth.enums.AuthProvider;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.service.impl.*;
import voucher.management.app.auth.strategy.impl.APIResponseStrategy;
import voucher.management.app.auth.strategy.impl.UserValidationStrategy;
import voucher.management.app.auth.utility.CookieUtils;
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
	
	@Autowired
	private JWTService jwtService;
	
	@Autowired
	private CookieUtils cookieUtils;
	
	@Autowired
	private RefreshTokenService refreshTokenService;
	
	@Autowired
	private APIResponseStrategy apiResponseStrategy;

	
	private String auditLogResponseSuccess = AuditLogResponseStatus.SUCCESS.toString();
	private String auditLogResponseFailure = AuditLogResponseStatus.FAILED.toString();
	private String auditLogUserId = AuditLogInvalidUser.InvalidUserID.toString();
	private String auditLogUserName = AuditLogInvalidUser.InvalidUserName.toString();
	private String genericErrorMessage = "An error occurred while processing your request. Please try again later.";
	

	@GetMapping(value = "", produces = "application/json")
	public ResponseEntity<APIResponse<List<UserDTO>>> getAllActiveUsers(@RequestHeader("X-User-Id") String userID, @RequestHeader("Authorization") String authorizationHeader,
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
				return apiResponseStrategy.handleResponseListAndsendAuditLogForSuccessCase(userDTOList,
						activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName, totalRecord);

			} else {
			    message = "No Active User List.";
			    return apiResponseStrategy.handleEmptyResponseListAndsendAuditLogForSuccessCase(userDTOList,
						activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName, totalRecord);

			}		

		} catch (Exception e) {
			return apiResponseStrategy.handleResponseListAndsendAuditLogForExceptionCase(e,
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
				userRequest.setAuthProvider(AuthProvider.NATIVE);
				UserDTO userDTO = userService.createUser(userRequest);
				message = userRequest.getEmail() + " is created successfully";
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
						activityType, message, apiEndPoint, httpMethod);
			} else {
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}
		} catch (Exception e) {
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
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
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}

			UserDTO userDTO = userService.loginUser(userRequest.getEmail(), userRequest.getPassword());
			message = userDTO.getEmail() + " login successfully";    
	    	HttpHeaders headers = createCookies(userDTO.getUsername(),userDTO.getEmail(), userDTO.getUserID(), null);
	    
			return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message, apiEndPoint, httpMethod, headers);		
		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.UNAUTHORIZED : HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
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
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(verifiedUserDTO, activityType, message, apiEndPoint,
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
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
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
			ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(userID, id);
			if (!validationResult.isValid()) {
				logger.error("Reset passwrod validation is not successful");
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}

			UserDTO userDTO = userService.resetPassword(id, resetPwdReq.getPassword());
			message = "Reset Password is completed.";
			return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
					activityType, message, apiEndPoint, httpMethod);

		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND : HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod);
		}

	}

	@PutMapping(value = "/{id}", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> updateUser(@RequestHeader("X-User-Id") String userID, @RequestHeader("Authorization") String authorizationHeader,
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
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message, apiEndPoint,
						httpMethod);

			} else {
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult, activityType, activityDesc,
						apiEndPoint, httpMethod);
			}
		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
					apiEndPoint, httpMethod);

		}
	}

	@GetMapping(value = "/{id}/active", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> checkSpecificActiveUser(@RequestHeader("X-User-Id") String userID, @RequestHeader("Authorization") String authorizationHeader, @PathVariable("id") String id) {
		logger.info("Call user active API...");
		logger.info("User ID" + id);
		String message = "";
		String activityType = "Authentication-RetrieveActiveUserByUserId";
		String apiEndPoint = String.format("api/users/%s/active", id);
		String httpMethod = HttpMethod.GET.name();
		String activityDesc = "Retrieving active user by id failed due to ";

		try {
			ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(userID, id);
			
			if (!validationResult.isValid()) {
				
				logger.error("Active user validation is not successful");
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
				
			}

			UserDTO userDTO = userService.checkSpecificActiveUser(validationResult.getUserId());
			message = userDTO.getEmail() + " is Active";	
			return  apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
					activityType, message, apiEndPoint, httpMethod);
			

		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod);
		}
	}

	@GetMapping(value = "/preferences/{name}", produces = "application/json")
	public ResponseEntity<APIResponse<List<UserDTO>>> getAllUsersByPreferences(@RequestHeader("X-User-Id") String userID, @RequestHeader("Authorization") String authorizationHeader,
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
				return apiResponseStrategy.handleResponseListAndsendAuditLogForSuccessCase(userDTOList,
						activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName, totalRecord);
			} else {
			    message = "No user list by this preference.";
			    return apiResponseStrategy.handleEmptyResponseListAndsendAuditLogForSuccessCase(userDTOList,
						activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName, totalRecord);
			}

		} catch (Exception e) {
			return apiResponseStrategy.handleResponseListAndsendAuditLogForExceptionCase(e,
					activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
	}
	
	@DeleteMapping(value = "/{id}/preferences", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> deletePreferenceByUser(@RequestHeader("X-User-Id") String userID, @RequestHeader("Authorization") String authorizationHeader,
			@PathVariable("id") String id, @RequestBody UserRequest userRequest) {
		logger.info("Call user Delete Preferences API...");
		String message;
		String activityType = "Authentication-DeleteUserPreferenceByUserId";
		String apiEndPoint = String.format("api/users/%s/preferences", id);
		String httpMethod = HttpMethod.DELETE.name();
		String activityDesc = "Delete user preference by preference is failed due to ";

		try {
			ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(userID, id);

			if (validationResult.isValid()) {

				UserDTO userDTO = userService.deletePreferencesByUser(validationResult.getUserId(),
						userRequest.getPreferences());
				message = "Preferences are deleted successfully.";
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
						activityType, message, apiEndPoint, httpMethod);
			} else {
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}
		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.BAD_REQUEST;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod);
		}

	}
	
	
	@PatchMapping(value = "/{id}/preferences", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> updatePreferenceByUser(@RequestHeader("X-User-Id") String userID, @RequestHeader("Authorization") String authorizationHeader,
			@PathVariable("id") String id, @RequestBody UserRequest userRequest) {
		logger.info("Call user update Preferences API...");
		String message;
		String activityType = "Authentication-UpdateUserPreferenceByUserId";
		String apiEndPoint = String.format("api/users/%s/preferences", id);
		String httpMethod = HttpMethod.PATCH.name();
		String activityDesc = "Update user preference by preference is failed due to ";

		try {
			ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(userID, id);

			if (validationResult.isValid()) {

				UserDTO userDTO = userService.updatePreferencesByUser(validationResult.getUserId(),
						userRequest.getPreferences());
				message = "Preferences are updated successfully.";
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
						activityType, message, apiEndPoint, httpMethod);
			} else {
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
			}
		} catch (Exception e) {

			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.BAD_REQUEST;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod);
		}

	}
	
	
	@PostMapping(value = "/logout", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> lgoutUser(@RequestHeader("X-User-Id") String userID, HttpServletRequest request) {
		logger.info("Call user update Preferences API...");
		String message;
		String activityType = "Authentication-Logout";
		String apiEndPoint = "/api/users/logout";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Logging out user is failed due to ";

		try {
			User user = userService.findByUserId(userID);
			if (user != null) {
				
				ResponseCookie accessTokenCookie = cookieUtils.createCookie("access_token", "", true, 0);
				ResponseCookie refreshTokenCookie = cookieUtils.createCookie("refresh_token", "", true, 0);
				HttpHeaders headers = createHttpHeader(accessTokenCookie, refreshTokenCookie);
				
				
				String refreshToken = cookieUtils.getRefreshTokenFromCookies(request, "refresh_token").orElse(null);   
				refreshTokenService.updateRefreshToken(refreshToken, true);
				
				message = "User logout successfully";
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(DTOMapper.toUserDTO(user),
						activityType, message, apiEndPoint, httpMethod, headers);
			} else {
				message = "User not found";
				logger.error(message);
				auditLogService.sendAuditLogToSqs(Integer.toString(HttpStatus.NOT_FOUND.value()), userID, auditLogUserName, activityType, activityDesc.concat(message), apiEndPoint, auditLogResponseFailure, httpMethod, message);
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(APIResponse.error(message));
				

			}
		} catch (Exception e) {
		   return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
				   HttpStatus.INTERNAL_SERVER_ERROR, activityType, activityDesc, apiEndPoint, httpMethod);
		}

	}
	

	@PostMapping("/refreshToken")
	public <T> ResponseEntity<APIResponse<T>> refreshToken(@RequestHeader("X-User-Id") String userID,
			HttpServletRequest request, HttpServletResponse response) {
		// Extract refresh token from cookies
		String refreshToken = cookieUtils.getRefreshTokenFromCookies(request, "refresh_token").orElse(null);
  	    String message = "";
		String activityType = "Authentication-RefreshToken";
		String apiEndPoint = "/api/users/refreshToken";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Requesting new access token is failed due to ";

		try {

			User user = userService.findByUserId(userID);
			auditLogUserName = user == null ? auditLogUserName : user.getUsername();

			if (refreshToken == null) {
				message = "Refresh token is missing";
				logger.info("Requesting new access Token: " + message);
				HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
				return apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(httpStatus, userID, activityType, activityDesc,
						apiEndPoint, httpMethod, message);

			}
			if (refreshTokenService.verifyRefreshToken(refreshToken)) {
				Claims claims = jwtService.extractAllClaims(refreshToken);
				String userid = claims.getSubject();
				String userName = claims.get("userName", String.class);
				String userEmail = claims.get("userEmail", String.class);
				// Add cookie to headers
				HttpHeaders headers = createCookies(userName, userEmail, userid, null);

				HttpStatus httpStatus = HttpStatus.OK;
				message = "Refresh token is successful.";
				
				refreshTokenService.updateRefreshToken(refreshToken, true);
				auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()),
				 userID, auditLogUserName, activityType, message,
				 apiEndPoint, auditLogResponseSuccess, httpMethod, "");
				return ResponseEntity.status(httpStatus).headers(headers).body(APIResponse.successWithNoData(message));

			} else {
				HttpStatus httpStatus = HttpStatus.UNAUTHORIZED;
				message = "Invalid or expired refresh token";
				logger.info("Requesting refresh Token: " + message);
				return apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(httpStatus, userID, activityType, activityDesc,
						apiEndPoint, httpMethod, message);
			}

		} catch (Exception e) {
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, HttpStatus.INTERNAL_SERVER_ERROR, activityType,
					activityDesc, apiEndPoint, httpMethod);

		}

	}
	
	@GetMapping("/validateToken")
	public <T> ResponseEntity<APIResponse<T>> verifyToken(@RequestHeader("X-User-Id") String userID) {
		
		String activityType = "Authentication-VerifyToken";
		String apiEndPoint = "/api/users/validateToken";
		String httpMethod = HttpMethod.GET.name();
		String message = "";
		String activityDesc = "Verifying access token is failed due to ";
		
		try {
			User user = userService.findByUserId(userID);
			auditLogUserName = user == null ? auditLogUserName : user.getUsername();
			
			HttpStatus httpStatus = HttpStatus.OK;
			auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()),
					 userID, auditLogUserName, activityType, message,
					 apiEndPoint, auditLogResponseSuccess, httpMethod, "");
			message = "Token is valid.";
			
			return ResponseEntity.status(HttpStatus.OK).body(APIResponse.successWithNoData(message));
		} catch (Exception e) {
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, HttpStatus.INTERNAL_SERVER_ERROR, activityType,
					activityDesc, apiEndPoint, httpMethod);
		}
		
	}
	
	
	@PutMapping(value = "/{id}/roles", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> updateUserRole(@RequestHeader("X-User-Id") String userID, @RequestHeader("Authorization") String authorizationHeader,
	        @PathVariable("id") String id, @RequestBody UserRequest roleReq) {
	    logger.info("Call user updateUserRole API...");
	    String message;
	    String activityType = "Authentication-UpdateUserRole";
	    String apiEndPoint = String.format("api/users/%s/roles", id);
	    String httpMethod = HttpMethod.PUT.name();
	    String activityDesc = "Update User-Role failed due to ";

	    try {
	    	RoleType role = roleReq.getRole();
	        

	        if (role.equals(null) || role.equals("")) {
	            message = "User Role is invalid.";
	            logger.info("updateUserRole: " + message);
	            HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
	            ValidationResult validationResult = new ValidationResult();
	            validationResult.setMessage(message);
	            validationResult.setStatus(httpStatus);
	            validationResult.setUserId(id);
	            validationResult.setUserName(userID);
	            return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
	                    validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
	        }

	        // Validate User ID
	        ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(userID, id);

	        if (validationResult.isValid()) {
	        	// Get RoleType enum value
	            // Update User Role
	            UserDTO userDTO = userService.updateRoleByUser(validationResult.getUserId(), role);
	            message = "Role is updated successfully.";
	            return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
	                    activityType, message, apiEndPoint, httpMethod);
	        } else {
	        	
	            return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
	                    validationResult, activityType, activityDesc, apiEndPoint, httpMethod);
	        }

	    } catch (Exception e) {
	        // Exception handling
	        HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
	                : HttpStatus.INTERNAL_SERVER_ERROR;
	        return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
	                apiEndPoint, httpMethod);
	    }
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
	
	private HttpHeaders createCookies(String userName, String email, String userid, String refreshToken) throws InvalidKeyException, Exception {	
		String newAccessToken = jwtService.generateToken(userName, email, userid, false);
		String newRefreshToken = refreshToken == null ? jwtService.generateToken(userName, email, userid, true) : refreshToken;

		ResponseCookie accessTokenCookie = cookieUtils.createCookie("access_token", newAccessToken, false, 1);
		ResponseCookie refreshTokenCookie = cookieUtils.createCookie("refresh_token", newRefreshToken, true, 1);

		// Add cookie to headers
		HttpHeaders headers = createHttpHeader(accessTokenCookie, refreshTokenCookie);
		if (refreshToken == null) {
			refreshTokenService.saveRefreshToken(userid, newRefreshToken);
		}
			
		return headers;
	}
	
	
	private HttpHeaders createHttpHeader(ResponseCookie accessTokenCookie, ResponseCookie responseTokenCookie) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
		headers.add(HttpHeaders.SET_COOKIE, responseTokenCookie.toString());
		return headers;
	}

}
