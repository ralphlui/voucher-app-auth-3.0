package voucher.management.app.auth.controller;

import java.util.List;
import java.util.Map;
import java.util.Optional;

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
import io.jsonwebtoken.JwtException;
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
	

	@GetMapping(value = "", produces = "application/json")
	public ResponseEntity<APIResponse<List<UserDTO>>> getAllActiveUsers(@RequestHeader("Authorization") String authorizationHeader,
			@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "500") int size) {
		logger.info("Call user getAll API with page={}, size={}", page, size);
		String message = "";
		String activityType = "Authentication-RetrieveAllActiveUsers";
		String apiEndPoint = "api/users";
		String httpMethod = HttpMethod.GET.name();
		String activityDesc = "Retreving active user list is failed due to ";
		

		try {
			retrieveUserIDAndNameFromToken(authorizationHeader);
			
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
			auditLogUserId = validationResult.getUserId();
			if (validationResult.isValid()) {
				userRequest.setAuthProvider(AuthProvider.NATIVE);
				UserDTO userDTO = userService.createUser(userRequest);
				message = userRequest.getEmail() + " is created successfully";
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
						activityType, message, apiEndPoint, httpMethod, userDTO.getUserID(), userDTO.getUsername());
			} else {
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod, validationResult.getUserId(), validationResult.getUserName());
			}
		} catch (Exception e) {
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					HttpStatus.INTERNAL_SERVER_ERROR, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
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
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
			}

			UserDTO userDTO = userService.loginUser(userRequest.getEmail(), userRequest.getPassword());
			message = userDTO.getEmail() + " login successfully";    
	    	HttpHeaders headers = createCookies(userDTO.getUsername(),userDTO.getEmail(), userDTO.getUserID(), null);
	    
			return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message, apiEndPoint, httpMethod, headers, auditLogUserId, auditLogUserName);		

		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.UNAUTHORIZED : HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
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
						httpMethod, auditLogUserId, auditLogUserName);
			} else {

				message = "Vefriy Id could not be blank.";
				logger.error(message);
				// To Do
				auditLogService.sendAuditLogToSqs(Integer.toString(HttpStatus.BAD_REQUEST.value()), auditLogUserId,
						auditLogUserName, activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod,
						message);
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(APIResponse.error(message));
			}
		} catch (Exception e) {
			// To Do
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
					apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
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
			getUserByUserID(userID);
			ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(id);
			if (!validationResult.isValid()) {
				logger.error("Reset passwrod validation is not successful");
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
			}

			UserDTO userDTO = userService.resetPassword(id, resetPwdReq.getPassword());
			message = "Reset Password is completed.";
			return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
					activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);

		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND : HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}

	}

	@PutMapping(value = "/{id}", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> updateUser(@RequestHeader("Authorization") String authorizationHeader,
			@PathVariable("id") String id, @RequestBody UserRequest userRequest) {
		logger.info("Call user update API...");
		String message;
		String activityType = "Authentication-UpdateUser";
		String apiEndPoint = String.format("api/users/%s", id);
		String httpMethod = HttpMethod.PUT.name();
		String activityDesc = "Update User failed due to ";

		try {
			retrieveUserIDAndNameFromToken(authorizationHeader);
			ValidationResult validationResult = userValidationStrategy.validateUpdating(id);

			if (validationResult.isValid()) {

				userRequest.setUserId(id);
				UserDTO userDTO = userService.update(userRequest);
				message = "User updated successfully.";
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO, activityType, message, apiEndPoint,
						httpMethod, auditLogUserId, auditLogUserName);

			} else {
				// To Do
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult, activityType, activityDesc,
						apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
			}
		} catch (Exception e) {
			// To Do
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
					apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);

		}
	}

	@GetMapping(value = "/{id}/active", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> checkSpecificActiveUser(@RequestHeader("Authorization") String authorizationHeader, @PathVariable("id") String id) {
		logger.info("Call user active API...");
		logger.info("User ID" + id);
		String message = "";
		String activityType = "Authentication-RetrieveActiveUserByUserId";
		String apiEndPoint = String.format("api/users/%s/active", id);
		String httpMethod = HttpMethod.GET.name();
		String activityDesc = "Retrieving active user by id failed due to ";

		try {
			retrieveUserIDAndNameFromToken(authorizationHeader);
			ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(id);
			
			if (!validationResult.isValid()) {
				
				logger.error("Active user validation is not successful");
				// To Do
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
						validationResult, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
				
			}

			UserDTO userDTO = userService.checkSpecificActiveUser(validationResult.getUserId());
			message = userDTO.getEmail() + " is Active";
			return  apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
					activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
			

		} catch (Exception e) {
			// To Do
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					htpStatuscode, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
	}

	
	@PostMapping(value = "/logout", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> lgoutUser(@RequestHeader("Authorization") String authorizationHeader,
			HttpServletRequest request) {
		logger.info("Call user update Preferences API...");
		String message;
		String activityType = "Authentication-Logout";
		String apiEndPoint = "/api/users/logout";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Logging out user is failed due to ";

		try {
			String userID = retrieveUserID(authorizationHeader);
			User user = userService.findByUserId(userID);
			retrieveUserIDAndNameFromToken(authorizationHeader);
			if (user != null) {
				
				ResponseCookie accessTokenCookie = cookieUtils.createCookie("access_token", "", true, 0);
				ResponseCookie refreshTokenCookie = cookieUtils.createCookie("refresh_token", "", true, 0);
				HttpHeaders headers = createHttpHeader(accessTokenCookie, refreshTokenCookie);
				
				
				String refreshToken = cookieUtils.getRefreshTokenFromCookies(request, "refresh_token").orElse(null);   
				refreshTokenService.updateRefreshToken(refreshToken, true);
				
				message = "User logout successfully";
				return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(DTOMapper.toUserDTO(user),
						activityType, message, apiEndPoint, httpMethod, headers, auditLogUserId, auditLogUserName);
			} else {
				message = "User not found";
				logger.error(message);
				// To Do
				auditLogService.sendAuditLogToSqs(Integer.toString(HttpStatus.NOT_FOUND.value()), userID, auditLogUserName, activityType, activityDesc.concat(message), apiEndPoint, auditLogResponseFailure, httpMethod, message);
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(APIResponse.error(message));
				

			}
		} catch (Exception e) {
		   return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
				   HttpStatus.INTERNAL_SERVER_ERROR, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
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
			auditLogUserName = Optional.ofNullable(user)
                    .map(User::getUsername)
                    .orElse(auditLogUserName);

			if (refreshToken == null) {
				message = "Refresh token is missing";
				logger.info("Requesting new access Token: " + message);
				HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
				return apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(httpStatus, userID, auditLogUserName, activityType, activityDesc,
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
				return apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(httpStatus, userID,auditLogUserName, activityType, activityDesc,
						apiEndPoint, httpMethod, message);
			}

		} catch (Exception e) {
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, HttpStatus.INTERNAL_SERVER_ERROR, activityType,
					activityDesc, apiEndPoint, httpMethod, userID, auditLogUserName);

		}

	}
	
	@GetMapping("/validateToken")
	public <T> ResponseEntity<APIResponse<T>> verifyToken(@RequestHeader("Authorization") String authorizationHeader) {
		
		String activityType = "Authentication-VerifyToken";
		String apiEndPoint = "/api/users/validateToken";
		String httpMethod = HttpMethod.GET.name();
		String message = "";
		String activityDesc = "Verifying access token is failed due to ";
		
		try {
			retrieveUserIDAndNameFromToken(authorizationHeader);
			
			HttpStatus httpStatus = HttpStatus.OK;
			message = "Token is valid.";
			auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()),
					auditLogUserId, auditLogUserName, activityType, message,
					 apiEndPoint, auditLogResponseSuccess, httpMethod, "");
			
			return ResponseEntity.status(HttpStatus.OK).body(APIResponse.successWithNoData(message));
		} catch (Exception e) {
			// To Do
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, HttpStatus.INTERNAL_SERVER_ERROR, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
		
	}
	
	
	@PutMapping(value = "/{id}/roles", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> updateUserRole(@RequestHeader("Authorization") String authorizationHeader,
	        @PathVariable("id") String id, @RequestBody UserRequest roleReq) {
	    logger.info("Call user updateUserRole API...");
	    String message;
	    String activityType = "Authentication-UpdateUserRole";
	    String apiEndPoint = String.format("api/users/%s/roles", id);
	    String httpMethod = HttpMethod.PUT.name();
	    String activityDesc = "Update User-Role failed due to ";

	    try {
	    	RoleType role = roleReq.getRole();
	    	retrieveUserIDAndNameFromToken(authorizationHeader);

	        if (role.equals(null) || role.equals("")) {
	            message = "User Role is invalid.";
	            logger.info("updateUserRole: " + message);
	            HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
	            ValidationResult validationResult = new ValidationResult();
	            validationResult.setMessage(message);
	            validationResult.setStatus(httpStatus);
	            validationResult.setUserId(id);
	            validationResult.setUserName(id);
	            return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
	                    validationResult, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
	        }

	        // Validate User ID
	        ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(id);

	        if (validationResult.isValid()) {
	        	// Get RoleType enum value
	            // Update User Role
	            UserDTO userDTO = userService.updateRoleByUser(validationResult.getUserId(), role);
	            message = "Role is updated successfully.";
	            return apiResponseStrategy.handleResponseAndsendAuditLogForSuccessCase(userDTO,
	                    activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
	        } else {
	        	
	            return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(
	                    validationResult, activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
	        }

	    } catch (Exception e) {
	        // Exception handling
	        HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
	                : HttpStatus.INTERNAL_SERVER_ERROR;
	        return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType, activityDesc,
	                apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
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
	
	private void retrieveUserIDAndNameFromToken(String authorizationHeader) throws JwtException, IllegalArgumentException, Exception {
		String jwtToken = authorizationHeader.substring(7);
		auditLogUserId =  retrieveUserID(authorizationHeader);
		auditLogUserName = jwtService.retrieveUserName(jwtToken);
	}
	
	private String retrieveUserID(String authorizationHeader) throws JwtException, IllegalArgumentException, Exception {
		String jwtToken = authorizationHeader.substring(7);
		return jwtService.retrieveUserID(jwtToken);
	}
	
	
}
