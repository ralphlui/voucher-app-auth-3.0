package voucher.management.app.auth.controller;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import voucher.management.app.auth.dto.*;
import voucher.management.app.auth.entity.RefreshToken;
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
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {

	private static final Logger logger = LoggerFactory.getLogger(UserController.class);

	@Value("${pentest.enable}")
	private String pentestEnable;



	private final UserService userService;
	private final UserValidationStrategy userValidationStrategy;
	private final AuditLogService auditLogService;
	private final JWTService jwtService;
	private final CookieUtils cookieUtils;
	private final RefreshTokenService refreshTokenService;
	private final APIResponseStrategy apiResponseStrategy;
	private final GoogleAuthService googleAuthService;


	private String auditLogResponseSuccess = AuditLogResponseStatus.SUCCESS.toString();
	private String auditLogResponseFailure = AuditLogResponseStatus.FAILED.toString();
	private String auditLogUserId = AuditLogInvalidUser.INVALID_USER_ID.toString();
	private String auditLogUserName = AuditLogInvalidUser.INVALID_USER_NAME.toString();
	private String genericErrorMessage = "An error occurred while processing your request. Please try again later.";

	private static final String ACCESS_TOKEN_COOKIE = "access_token";
	private static final String REFRESH_TOKEN_COOKIE = "refresh_token";
	private static final String API_ENDPOINT = "api/users";



	@GetMapping(value = "", produces = "application/json")
	public ResponseEntity<APIResponse<List<UserDTO>>> getAllActiveUsers(
			@RequestHeader("Authorization") String authorizationHeader, @RequestParam(defaultValue = "0") int page,
			@RequestParam(defaultValue = "500") int size) {
		logger.info("Call user getAll API with page={}, size={}", page, size);
		String message = "";
		String activityType = "Authentication-RetrieveAllActiveUsers";
		String apiEndPoint = API_ENDPOINT;
		String httpMethod = HttpMethod.GET.name();
		String activityDesc = "Retreving active user list is failed due to ";
		
		
		try {
			retrieveUserIDAndNameFromToken(authorizationHeader);

			Pageable pageable = PageRequest.of(page, size, Sort.by("username").ascending());
			Map<Long, List<UserDTO>> resultMap = userService.findActiveUsers(pageable);
			logger.info("all active user list size {}", resultMap.size());

			Map.Entry<Long, List<UserDTO>> firstEntry = resultMap.entrySet().iterator().next();
			long totalRecord = firstEntry.getKey();
			List<UserDTO> userDTOList = firstEntry.getValue();

			logger.info("totalRecord: {}", totalRecord);
			logger.info("userDTO List");

			if (!userDTOList.isEmpty()) {
				message = "Successfully get all active verified user.";
				return apiResponseStrategy.handleResponseListAndsendAuditLogForSuccessCase(userDTOList, activityType,
						message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName, totalRecord);

			} else {
				message = "No Active User List.";
				return apiResponseStrategy.handleEmptyResponseListAndsendAuditLogForSuccessCase(userDTOList,
						activityType, message, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);

			}

		} catch (Exception e) {
			return apiResponseStrategy.handleResponseListAndsendAuditLogForExceptionCase(e, activityType, activityDesc,
					apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
	}

	@PostMapping(value = "", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> createUser(@RequestBody UserRequest userRequest) {
		logger.info("Call user create API...");
		String message;
		String activityType = "Authentication-CreateUser";
		String apiEndPoint = API_ENDPOINT;
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "User registration is failed due to ";
		AuditLogRequest auditReq = new AuditLogRequest("", auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, "");
		
		try {
			ValidationResult validationResult = userValidationStrategy.validateCreation(userRequest);
			auditLogUserName = validationResult.getUserName();
			auditLogUserId = validationResult.getUserId();
			if (validationResult.isValid()) {
				userRequest.setAuthProvider(AuthProvider.NATIVE);
				UserDTO userDTO = userService.createUser(userRequest);
				message = userRequest.getEmail() + " is created successfully";
                auditReq.setActivityDescription(message);
                auditReq.setStatusCode("200");
                auditReq.setResponseStatus(auditLogResponseSuccess);
				return apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(userDTO, message, auditReq);
				
			} else {
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod, validationResult.getUserId(),
						validationResult.getUserName());
			}
		} catch (Exception e) {
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					HttpStatus.INTERNAL_SERVER_ERROR, activityType, activityDesc, apiEndPoint, httpMethod,
					auditLogUserId, auditLogUserName);
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
		AuditLogRequest auditReq = new AuditLogRequest("", auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, "");
		
		try {
			ValidationResult validationResult = userValidationStrategy.validateObject(userRequest.getEmail());
			auditLogUserId = validationResult.getUserId();
			auditLogUserName = validationResult.getUserName();

			if (!validationResult.isValid()) {

				logger.error("Login Validation Error: {}", validationResult.getMessage());
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod, validationResult.getUserId(),
						validationResult.getUserName());
			}

			UserDTO userDTO = userService.loginUser(userRequest.getEmail(), userRequest.getPassword());
			message = userDTO.getEmail() + " login successfully";

			if (pentestEnable.equalsIgnoreCase("true")) {
				HttpHeaders headers = cookieUtils.buildAuthHeadersWithCookies(userDTO.getUsername(), userDTO.getEmail(),
						userDTO.getUserID(), null);
				auditReq.setActivityDescription(message);
				return apiResponseStrategy.handleResponseWithHeaderAndSendAuditLogForSuccessCase(userDTO, message, auditReq, headers);
				
			} else {

				auditReq.setActivityDescription(message);
                auditReq.setStatusCode("200");
                auditReq.setResponseStatus(auditLogResponseSuccess);
				return apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(userDTO, message, auditReq);
				
				
			}

		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.UNAUTHORIZED
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
	}

	@PatchMapping(value = "/verify", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> verifyUser(@RequestBody UserRequest userRequest) {

		String verifyid = userRequest.getAccountVerificationCode();
		logger.info("Call user verify API with verifyToken");
		verifyid = GeneralUtility.makeNotNull(verifyid);
		String message = "";
		String activityType = "Authentication-VerifyUser";
		String apiEndPoint = String.format("api/users/verify");
		String httpMethod = HttpMethod.PATCH.name();
		String activityDesc = "User verification is failed due to ";
		AuditLogRequest auditReq = new AuditLogRequest("", auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, "");
		
		try {

			if (!verifyid.isEmpty()) {
				UserDTO verifiedUserDTO = userService.verifyUser(verifyid);
				auditLogUserId = verifiedUserDTO.getUserID();
				auditLogUserName = verifiedUserDTO.getUsername();
				message = "User successfully verified.";
				auditReq.setActivityDescription(message);
                auditReq.setStatusCode("200");
                auditReq.setResponseStatus(auditLogResponseSuccess);
				return apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(verifiedUserDTO, message, auditReq);
				
								
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
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}

	}

	@PatchMapping(value = "/resetPassword", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> resetPassword(@RequestBody UserRequest resetPwdReq) {

		logger.info("Call user resetPassword API...");

		String activityType = "Authentication-ResetPassword";
		String apiEndPoint = String.format("api/users/resetPassword");
		String httpMethod = HttpMethod.PATCH.name();
		String activityDesc = "Reset password is failed due to ";

		String message = "";
		
		AuditLogRequest auditReq = new AuditLogRequest("", auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, "");
		
		try {
			ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(resetPwdReq.getUserId());
			if (!validationResult.isValid()) {
				logger.error("Reset passwrod validation is not successful");
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
			}

			String id = resetPwdReq.getUserId();
			getUserByUserID(id);
			UserDTO userDTO = userService.resetPassword(id, resetPwdReq.getPassword());
			message = "Reset Password is completed.";
			auditReq.setActivityDescription(message);
            auditReq.setStatusCode("200");
            auditReq.setResponseStatus(auditLogResponseSuccess);
			return apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(userDTO, message, auditReq);
			
			

		} catch (Exception e) {
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}

	}

	@PutMapping(value = "", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> updateUser(@RequestHeader("Authorization") String authorizationHeader,
			@RequestBody UserRequest userRequest) {
		logger.info("Call user update API...");
		String message;
		String activityType = "Authentication-UpdateUser";
		String apiEndPoint = String.format(API_ENDPOINT);
		String httpMethod = HttpMethod.PUT.name();
		String activityDesc = "Update User failed due to ";
		String userID = userRequest.getUserId();
		AuditLogRequest auditReq = new AuditLogRequest("", auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, "");
		
		try {
			retrieveUserIDAndNameFromToken(authorizationHeader);
			ValidationResult validationResult = userValidationStrategy.validateUpdating(userID);

			if (validationResult.isValid()) {

				userRequest.setUserId(userID);
				UserDTO userDTO = userService.update(userRequest);
				message = "User updated successfully.";
				auditReq.setActivityDescription(message);
	            auditReq.setStatusCode("200");
	            auditReq.setResponseStatus(auditLogResponseSuccess);
				return apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(userDTO, message, auditReq);
				
				

			} else {
				// To Do
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
			}
		} catch (Exception e) {
			// To Do
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);

		}
	}

	@PostMapping(value = "/active", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> checkSpecificActiveUser(
			@RequestHeader("Authorization") String authorizationHeader, @RequestBody UserRequest userRequest) {
		logger.info("Call user active API...");
		String message = "";
		String activityType = "Authentication-RetrieveActiveUserByUserId";
		String apiEndPoint = String.format("api/users/active");
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Retrieving active user by id failed due to ";
		
		AuditLogRequest auditReq = new AuditLogRequest("", auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, "");
		
		try {
			retrieveUserIDAndNameFromToken(authorizationHeader);
			ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(userRequest.getUserId());

			if (!validationResult.isValid()) {

				logger.error("Active user validation is not successful");
				// To Do
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);

			}

			UserDTO userDTO = userService.checkSpecificActiveUser(validationResult.getUserId());
			message = userDTO.getEmail() + " is Active";
			auditReq.setActivityDescription(message);
            auditReq.setStatusCode("200");
            auditReq.setResponseStatus(auditLogResponseSuccess);
			return apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(userDTO, message, auditReq);
			
		

		} catch (Exception e) {
			// To Do
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
	}

	@PostMapping(value = "/logout", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> lgoutUser(HttpServletRequest request) {
		logger.info("Call user update Preferences API...");
		String message;
		String activityType = "Authentication-Logout";
		String apiEndPoint = "/api/users/logout";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Logging out user is failed due to ";
		String userID = AuditLogInvalidUser.INVALID_USER_ID.toString();
		AuditLogRequest auditReq = new AuditLogRequest("", auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, "");

		String tokenFromCookie = cookieUtils.getTokenFromCookies(request, ACCESS_TOKEN_COOKIE).orElse(null);

		ResponseCookie accessTokenCookie = cookieUtils.createCookie(ACCESS_TOKEN_COOKIE, "", true, 0);
		ResponseCookie refreshTokenCookie = cookieUtils.createCookie(REFRESH_TOKEN_COOKIE, "", true, 0);
		HttpHeaders headers = cookieUtils.createHttpHeader(accessTokenCookie, refreshTokenCookie);

		try {
			userID = jwtService.extractUserIdAllowExpiredToken(tokenFromCookie);
			User user = userService.findByUserId(userID);
			auditLogUserName = jwtService.extractUserNameAllowExpiredToken(tokenFromCookie);

			
			String refreshToken = cookieUtils.getTokenFromCookies(request, REFRESH_TOKEN_COOKIE).orElse(null);

			refreshTokenService.updateRefreshToken(refreshToken, true);

			if (user != null) {

				message = "User logout successfully";
				auditReq.setActivityDescription(message);
				return apiResponseStrategy.handleResponseWithHeaderAndSendAuditLogForSuccessCase(DTOMapper.toUserDTO(user), message, auditReq, headers);
			} else {
				message = "User not found, session cleared.";
				logger.error(message);
				// To Do
				auditLogService.sendAuditLogToSqs(Integer.toString(HttpStatus.NOT_FOUND.value()), userID,
						auditLogUserName, activityType, activityDesc.concat(message), apiEndPoint,
						auditLogResponseFailure, httpMethod, message);
				return ResponseEntity.status(HttpStatus.NOT_FOUND).headers(headers).body(APIResponse.error(message));

			}
		} catch (Exception e) {
			message = e.getMessage();
			String responseMessage = e instanceof UserNotFoundException ? e.getMessage() : genericErrorMessage;
			logger.error(message);
			activityDesc = activityDesc.concat(message);
			auditLogService.sendAuditLogToSqs(Integer.toString(HttpStatus.INTERNAL_SERVER_ERROR.value()), userID,
					auditLogUserName, activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod,
					e.getMessage());
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).headers(headers)
					.body(APIResponse.error(responseMessage));
		}

	}

	@PostMapping("/refreshToken")
	public <T> ResponseEntity<APIResponse<T>> refreshToken(HttpServletRequest request, HttpServletResponse response) {
		// Extract refresh token from cookies
		String refreshToken = cookieUtils.getTokenFromCookies(request, REFRESH_TOKEN_COOKIE).orElse(null);
		String message = "";
		String activityType = "Authentication-RefreshToken";
		String apiEndPoint = "/api/users/refreshToken";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Requesting new access token is failed due to ";

		try {
			if (refreshToken == null) {
				message = "Refresh token is missing";
				logger.info("Requesting new access Token: {}", message);
				HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
				return apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(httpStatus, auditLogUserId,
						auditLogUserName, activityType, activityDesc, apiEndPoint, httpMethod, message);

			}
			
			RefreshToken savedRefreshToken = refreshTokenService.findRefreshToken(refreshToken);

			if (savedRefreshToken != null && refreshTokenService.verifyRefreshToken(savedRefreshToken)) {
				auditLogUserId = savedRefreshToken.getUser().getUserId();
				auditLogUserName = savedRefreshToken.getUser().getUsername();
				String userEmail = savedRefreshToken.getUser().getEmail();
				// Add cookie to headers
				HttpHeaders headers = cookieUtils.buildAuthHeadersWithCookies(auditLogUserName, userEmail, auditLogUserId, refreshToken);

				HttpStatus httpStatus = HttpStatus.OK;
				message = "Token refresh is successful.";

				refreshTokenService.updateRefreshToken(refreshToken, false);
				auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), auditLogUserId,
						auditLogUserName, activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
				return ResponseEntity.status(httpStatus).headers(headers).body(APIResponse.successWithNoData(message));

			} else {
				HttpStatus httpStatus = HttpStatus.UNAUTHORIZED;
				message = "Invalid or expired refresh token";
				logger.info("Requesting refresh Token: {} ", message);
				return apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(httpStatus, auditLogUserId,
						auditLogUserName, activityType, activityDesc, apiEndPoint, httpMethod, message);
			}

		} catch (Exception e) {
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					HttpStatus.INTERNAL_SERVER_ERROR, activityType, activityDesc, apiEndPoint, httpMethod,
					auditLogUserId, auditLogUserName);

		}

	}

	@PostMapping("/accessToken")
	public ResponseEntity<APIResponse<JWTDTO>> generateAccessToken(@RequestBody UserRequest userRequest) {

		String message = "";
		String activityType = "Authentication-AccessToken";
		String apiEndPoint = "/api/users/accessToken";
		String httpMethod = HttpMethod.POST.name();
		String activityDesc = "Requesting new access token is failed due to ";

		try {
			String userEmail = userRequest.getEmail();

			if (GeneralUtility.makeNotNull(userEmail).equals("")) {
				message = "Invalid user.";
				logger.info("Requesting access Token: {}", message);

				return apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(HttpStatus.BAD_REQUEST,
						auditLogUserId, auditLogUserName, activityType, activityDesc, apiEndPoint, httpMethod, message);


			}

			// find user
			UserDTO user = userService.checkSpecificActiveUserByEmail(userEmail);
			if (user == null) {
				message = "Invalid user.";
				return apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(HttpStatus.BAD_REQUEST,
						auditLogUserId, auditLogUserName, activityType, activityDesc, apiEndPoint, httpMethod, message);

			}
			auditLogUserId = user.getUserID();
			auditLogUserName = user.getUsername();

			String accessToken = jwtService.generateToken(user.getUsername(), userEmail, user.getUserID());

			if (accessToken != null) {

				HttpStatus httpStatus = HttpStatus.OK;
				message = "Access token generated successfully.";
				JWTDTO jwt = new JWTDTO();
				jwt.setToken(accessToken);

				auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), auditLogUserId,
						auditLogUserName, activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");
				return ResponseEntity.status(httpStatus).body(APIResponse.success(jwt, message));

			} else {
				HttpStatus httpStatus = HttpStatus.UNAUTHORIZED;
				message = "Failed to generate token.";
				logger.info("Requesting access Token: {}", message);
				return apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(httpStatus, auditLogUserId,
						auditLogUserName, activityType, activityDesc, apiEndPoint, httpMethod, message);
			}

		} catch (Exception e) {
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					HttpStatus.INTERNAL_SERVER_ERROR, activityType, activityDesc, apiEndPoint, httpMethod,
					auditLogUserId, auditLogUserName);

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
			auditLogService.sendAuditLogToSqs(Integer.toString(httpStatus.value()), auditLogUserId, auditLogUserName,
					activityType, message, apiEndPoint, auditLogResponseSuccess, httpMethod, "");

			return ResponseEntity.status(HttpStatus.OK).body(APIResponse.successWithNoData(message));
		} catch (Exception e) {
			// To Do
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e,
					HttpStatus.INTERNAL_SERVER_ERROR, activityType, activityDesc, apiEndPoint, httpMethod,
					auditLogUserId, auditLogUserName);
		}

	}

	@PutMapping(value = "/roles", produces = "application/json")
	public ResponseEntity<APIResponse<UserDTO>> updateUserRole(
			@RequestHeader("Authorization") String authorizationHeader, @RequestBody UserRequest roleReq) {
		logger.info("Call user updateUserRole API...");
		String message;
		String activityType = "Authentication-UpdateUserRole";
		String apiEndPoint = String.format("api/users/roles");
		String httpMethod = HttpMethod.PUT.name();
		String activityDesc = "Update User-Role failed due to ";
		AuditLogRequest auditReq = new AuditLogRequest("", auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, "");
			
		try {
			retrieveUserIDAndNameFromToken(authorizationHeader);

			// Validate User ID
			ValidationResult validationResult = userValidationStrategy.validateObjectByUseId(roleReq.getUserId());
			if (!validationResult.isValid()) {
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);

			}

			RoleType role = roleReq.getRole();
			if (role == null) {

				message = "User Role is invalid.";
				logger.info("updateUserRole: {}", message);

				HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
				validationResult.setStatus(httpStatus);
				return apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(validationResult,
						activityType, activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
			}

			UserDTO userDTO = userService.updateRoleByUser(validationResult.getUserId(), role);
			message = "Role is updated successfully.";
			auditReq.setActivityDescription(message);
            auditReq.setStatusCode("200");
            auditReq.setResponseStatus(auditLogResponseSuccess);
			return apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(userDTO, message, auditReq);
			
		

		} catch (Exception e) {
			// Exception handling
			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
		}
	}

	@GetMapping("/google/userinfo")
	public ResponseEntity<APIResponse<UserDTO>> getGoogleUserInfo(
			@RequestHeader("Authorization") String authorizationHeader) {

		logger.info("Call user Get Googel User Info API...");
		String message;
		String activityType = "Authentication-GetGoogelUserInfo";
		String apiEndPoint = "/google/userinfo";
		String httpMethod = HttpMethod.GET.name();
		String activityDesc = "Get google User-Info failed";
		AuditLogRequest auditReq = new AuditLogRequest("", auditLogUserId, auditLogUserName,
				activityType, activityDesc, apiEndPoint, auditLogResponseFailure, httpMethod, "");
		
		try {

			if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {

				return apiResponseStrategy.handleResponseAndsendAuditLogForFailedCase( activityType, activityDesc,
						"Authorization header is invalid", apiEndPoint, httpMethod, HttpStatus.UNAUTHORIZED,
						auditLogUserId, auditLogUserName);
			}

			String token = authorizationHeader.substring(7);

			UserDTO userDTO = googleAuthService.verifyAndGetUserInfo(token);
			if (userDTO != null && userDTO.getEmail() != null) {
				message = "Successfully get Google user info.";
			
				HttpHeaders headers = cookieUtils.buildAuthHeadersWithCookies(userDTO.getUsername(), userDTO.getEmail(),
						userDTO.getUserID(), null);
				auditReq.setActivityDescription(message);
				return apiResponseStrategy.handleResponseWithHeaderAndSendAuditLogForSuccessCase(userDTO, message, auditReq, headers);
				
				 
			} else {
				message = "Failed to get Google user info.";
				return apiResponseStrategy.handleResponseAndsendAuditLogForFailedCase( activityType,
						activityDesc, message, apiEndPoint, httpMethod, HttpStatus.BAD_REQUEST, auditLogUserId,
						auditLogUserName);

			}
		} catch (Exception e) {

			HttpStatusCode htpStatuscode = e instanceof UserNotFoundException ? HttpStatus.NOT_FOUND
					: HttpStatus.INTERNAL_SERVER_ERROR;
			return apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(e, htpStatuscode, activityType,
					activityDesc, apiEndPoint, httpMethod, auditLogUserId, auditLogUserName);
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

	private void retrieveUserIDAndNameFromToken(String authorizationHeader)
			throws JwtException, IllegalArgumentException, Exception {
		String jwtToken = authorizationHeader.substring(7);
		auditLogUserId = retrieveUserID(authorizationHeader);
		auditLogUserName = jwtService.extractUserNameAllowExpiredToken(jwtToken);
	}

	private String retrieveUserID(String authorizationHeader) throws JwtException, IllegalArgumentException, Exception {
		String jwtToken = authorizationHeader.substring(7);
		return jwtService.extractUserIdAllowExpiredToken(jwtToken);
	}

}
