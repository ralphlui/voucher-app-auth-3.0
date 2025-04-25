package voucher.management.app.auth.controller;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import voucher.management.app.auth.dto.*;
import voucher.management.app.auth.entity.RefreshToken;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.repository.UserRepository;
import voucher.management.app.auth.service.impl.*;
import voucher.management.app.auth.strategy.impl.APIResponseStrategy;
import voucher.management.app.auth.strategy.impl.UserValidationStrategy;
import voucher.management.app.auth.utility.*;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@ActiveProfiles("test")
public class UserControllerTest {

	@MockitoBean
	private UserService userService;

	@MockitoBean
	private UserRepository userRepository;

	@Autowired
	private MockMvc mockMvc;

	@InjectMocks
	private ObjectMapper objectMapper;

	@MockitoBean
	private EncryptionUtils encryptionUtils;

	@MockitoBean
	private JWTService jwtService;

	@MockitoBean
	private CookieUtils cookieUtils;

	@MockitoBean
	private RefreshTokenService refreshTokenService;

	@MockitoBean
	private GoogleAuthService googleAuthService;

	@Mock
	private APIResponseStrategy apiResponseStrategy;
	
	@Mock
	private UserValidationStrategy userValidationStrategy;

	 // Control flag per test
    static ThreadLocal<String> pentestValue = ThreadLocal.withInitial(() -> "true");

	@DynamicPropertySource
	static void dynamicProperties(DynamicPropertyRegistry registry) {
		registry.add("pentest.enable", () -> pentestValue.get());
	}
	
	private String validIdToken = "Bearer valid-id-token";
	private UserDTO mockUserDTO;
	private String accountVerificationCode = "mockVerificationCode";

	User testUser;
	User errorUser;
	UserRequest userRequest;

	private static List<UserDTO> mockUsers = new ArrayList<>();

	@BeforeEach
	void setUp() {
		userRequest = new UserRequest("useradmin@gmail.com", "Pwd@21212", "UserAdmin", RoleType.MERCHANT, true);
		userRequest.setUserId("8f6e8b84-1219-4c28-a95c-9891c11328b7");
		userRequest.setAccountVerificationCode(accountVerificationCode);
		testUser = new User(userRequest.getEmail(), userRequest.getUsername(), userRequest.getPassword(),
				userRequest.getRole(), true);
		errorUser = new User("error@gmail.com", "Error", "Pwd@21212", RoleType.MERCHANT, true);
		errorUser.setUserId("0");
		testUser.setUserId(userRequest.getUserId());

		mockUsers.add(DTOMapper.toUserDTO(testUser));

	}

	@AfterEach
	void tearDown() {
		testUser = new User();
		errorUser = new User();
		userRequest = new UserRequest();

	}
	

	@Test
	void testGetAllUser() throws Exception {

		Pageable pageable = PageRequest.of(0, 10, Sort.by("username").ascending());
		Map<Long, List<UserDTO>> mockUserMap = new HashMap<>();
		mockUserMap.put(0L, mockUsers);

		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);
		Mockito.when(userService.findActiveUsers(pageable)).thenReturn(mockUserMap);

		String authorizationHeader = "Bearer mock.jwt.token";

		when(jwtService.extractUserID("mock.jwt.token")).thenReturn(testUser.getUserId());

		mockMvc.perform(MockMvcRequestBuilders.get("/api/users").param("page", "0").param("size", "10")
				.header("Authorization", authorizationHeader).contentType(MediaType.APPLICATION_JSON))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Successfully get all active verified user.")).andDo(print());

		Map<Long, List<UserDTO>> emptyMockUserMap = new HashMap<>();
		List<UserDTO> emptyMockUsers = new ArrayList<>();
		emptyMockUserMap.put(0L, emptyMockUsers);

		Mockito.when(userService.findActiveUsers(pageable)).thenReturn(emptyMockUserMap);
		mockMvc.perform(MockMvcRequestBuilders.get("/api/users").param("page", "0").param("size", "10")
				.header("Authorization", authorizationHeader).contentType(MediaType.APPLICATION_JSON))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("No Active User List.")).andDo(print());

	}
	

	@Test
	void testUserLogin() throws Exception {
		testUser.setVerified(true);
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);
		Mockito.when(userService.findByEmail(userRequest.getEmail())).thenReturn(testUser);

		Mockito.when(userService.loginUser(userRequest.getEmail(), userRequest.getPassword()))
				.thenReturn(DTOMapper.toUserDTO(testUser));
		
		   HttpHeaders headers = new HttpHeaders();
	       headers.add("Set-Cookie", "access_token=abc123");
	       when(cookieUtils.buildAuthHeadersWithCookies(anyString(), anyString(), anyString(), anyString())).thenReturn(headers);

		
		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/login").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(userRequest))).andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.message").value(userRequest.getEmail() + " login successfully"))
				.andExpect(jsonPath("$.data.username").value(userRequest.getUsername()))
				.andExpect(jsonPath("$.data.email").value(userRequest.getEmail()))
				.andExpect(jsonPath("$.data.role").value(userRequest.getRole().toString())).andDo(print());

		UserRequest userNotFoundRequest = new UserRequest(errorUser.getEmail(), "Pwd@21212");

		pentestValue.set("false"); 
		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/login").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(userNotFoundRequest)))
				.andExpect(MockMvcResultMatchers.status().isNotFound())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.message").value("User account not found."))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());

	}
	
	@Test
	void testUserLoginPenTestDisable() throws Exception {
		pentestValue.set("false");
		testUser.setVerified(true);
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);
		Mockito.when(userService.findByEmail(userRequest.getEmail())).thenReturn(testUser);

		Mockito.when(userService.loginUser(userRequest.getEmail(), userRequest.getPassword()))
				.thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/login").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(userRequest))).andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.message").value(userRequest.getEmail() + " login successfully"))
				.andExpect(jsonPath("$.data.username").value(userRequest.getUsername()))
				.andExpect(jsonPath("$.data.email").value(userRequest.getEmail()))
				.andExpect(jsonPath("$.data.role").value(userRequest.getRole().toString())).andDo(print());

	}
	
	@Test
	void testLoginUserValidationFail() throws Exception {
		// Prepare input
		String jsonRequest = new ObjectMapper().writeValueAsString(userRequest);

		// Prepare validation
		ValidationResult validationResult = new ValidationResult();
		validationResult.setValid(false);
		validationResult.setStatus(HttpStatus.BAD_REQUEST);
		when(userValidationStrategy.validateObject(userRequest.getEmail())).thenReturn(validationResult);

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/login").contentType(MediaType.APPLICATION_JSON)
				.content(jsonRequest)).andExpect(jsonPath("$.success").value(false)).andDo(print());
	}


	@Test
	void testVerifyUser() throws Exception {

		testUser.setVerified(true);
		testUser.setActive(true);
		testUser.setVerificationCode(accountVerificationCode);

		Mockito.when(userService.verifyUser(accountVerificationCode)).thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.patch("/api/users/verify")
				.contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true)).andExpect(jsonPath("$.data.verified").value(true))
				.andDo(print());

		testUser.setVerificationCode("");

		mockMvc.perform(MockMvcRequestBuilders.patch("/api/users/verify", "")
				.contentType(MediaType.APPLICATION_JSON)
		        .content(objectMapper.writeValueAsString(testUser)))
				.andExpect(MockMvcResultMatchers.status().isBadRequest())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());

	}

	@Test
	void testCreateUser() throws Exception {
		Mockito.when(userService.createUser(Mockito.any(UserRequest.class))).thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.data.username").value(userRequest.getUsername()))
				.andExpect(jsonPath("$.data.email").value(userRequest.getEmail()))
				.andExpect(jsonPath("$.data.role").value(userRequest.getRole().toString())).andDo(print());

		User errorUser = new User("", "Error", "Pwd@21212", RoleType.MERCHANT, true);
		mockMvc.perform(MockMvcRequestBuilders.post("/api/users").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(errorUser)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.message").value("Email cannot be empty.")).andDo(print());
	}

	@Test
	void testResetPassword() throws Exception {
		testUser.setVerified(true);
		
		ValidationResult validResult = new ValidationResult();
		validResult.setValid(true);
		validResult.setUserId(testUser.getUserId());
		validResult.setUserName("John");
		validResult.setMessage("");

		Mockito.when(userValidationStrategy.validateObjectByUseId(Mockito.eq(userRequest), Mockito.eq(true)))
		       .thenReturn(validResult);
		
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);

		UserRequest userRequest = new UserRequest(testUser.getEmail(), "Pa@wo@rd@345");
		userRequest.setUserId(testUser.getUserId());
		Mockito.when(userService.resetPassword(userRequest.getUserId(), userRequest.getPassword()))
				.thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.patch("/api/users/resetPassword")
				.contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Reset Password is completed.")).andDo(print());
		
		testUser.setVerified(false);
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);

		userRequest.setUserId(testUser.getUserId());
		Mockito.when(userService.resetPassword(userRequest.getUserId(), userRequest.getPassword()))
				.thenReturn(DTOMapper.toUserDTO(testUser));
		
		mockMvc.perform(MockMvcRequestBuilders.patch("/api/users/resetPassword")
				.contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());
	}
	

	@Test
	void testUpdatedUser() throws Exception {
		testUser.setEmail("newemail@gmail.com");
		testUser.setVerified(true);
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);

		Mockito.when(userService.update(Mockito.any(UserRequest.class))).thenReturn(DTOMapper.toUserDTO(testUser));

		String authorizationHeader = "Bearer mock.jwt.token";
		when(jwtService.extractUserID("mock.jwt.token")).thenReturn(testUser.getUserId());

		mockMvc.perform(MockMvcRequestBuilders.put("/api/users").contentType(MediaType.APPLICATION_JSON)
				.header("Authorization", authorizationHeader).content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.message").value("User updated successfully."))
				.andExpect(jsonPath("$.data.username").value(testUser.getUsername()))
				.andExpect(jsonPath("$.data.email").value("newemail@gmail.com"))
				.andExpect(jsonPath("$.data.role").value(testUser.getRole().toString())).andDo(print());

		errorUser.setActive(false);
		UserRequest errorUserRequest = new UserRequest(errorUser.getEmail(), "Pwd@21212", "ErrorUser",
				RoleType.MERCHANT, false);
		errorUserRequest.setUserId(errorUser.getUserId());
		Mockito.when(userService.findByUserId(errorUser.getUserId())).thenReturn(errorUser);

		mockMvc.perform(MockMvcRequestBuilders.put("/api/users")
				.contentType(MediaType.APPLICATION_JSON)
				.header("Authorization", authorizationHeader)
				.content(objectMapper.writeValueAsString(userRequest))
				.content(objectMapper.writeValueAsString(errorUserRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());

	}

	@Test
	void testActiveUser() throws Exception {
		testUser.setVerified(true);
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);
		Mockito.when(userService.checkSpecificActiveUser(testUser.getUserId()))
				.thenReturn(DTOMapper.toUserDTO(testUser));

		String authorizationHeader = "Bearer mock.jwt.token";
		when(jwtService.extractUserID("mock.jwt.token")).thenReturn(testUser.getUserId());

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/active")
				.contentType(MediaType.APPLICATION_JSON).header("Authorization", authorizationHeader)
				.content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.data.username").value(testUser.getUsername()))
				.andExpect(jsonPath("$.data.email").value(testUser.getEmail()))
				.andExpect(jsonPath("$.data.active").value(true)).andExpect(jsonPath("$.data.verified").value(true))
				.andDo(print());

		errorUser.setVerified(false);
		Mockito.when(userService.findByUserId(errorUser.getUserId())).thenReturn(errorUser);
		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/active").header("Authorization", authorizationHeader)
				.contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(errorUser)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());
	}
	
	@Test
	void checkSpecificActiveUserUserNotFoundException() throws Exception {
		String userId = "123";
		String token = "Bearer test.jwt.token";

		ValidationResult validResult = new ValidationResult();
		validResult.setValid(true);
		validResult.setUserId(userId);
		validResult.setUserName("John");
		validResult.setMessage("");

		when(userValidationStrategy.validateObjectByUseId(eq(userRequest), eq(true))).thenReturn(validResult);

		when(userService.checkSpecificActiveUser(eq(userId))).thenThrow(new UserNotFoundException("User not found"));

		when(apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(any(Exception.class),
				eq(HttpStatus.NOT_FOUND), any(), any(), any(), any(), any(), any()))
				.thenReturn(new ResponseEntity<>(HttpStatus.NOT_FOUND));

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/active").header("Authorization", token)
				.contentType(MediaType.APPLICATION_JSON).content("{\"userId\": \"123\"}"))
				.andExpect(status().isNotFound());
	}
	

	@Test
	void testUserLogout() throws Exception {
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);
		String authorizationHeader = "Bearer mock.jwt.token";
		when(jwtService.extractUserID("mock.jwt.token")).thenReturn(testUser.getUserId());

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/logout").contentType(MediaType.APPLICATION_JSON)
				.header("Authorization", authorizationHeader).content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());

	}	
	
	@Test
    void testRefreshTokenSuccess() throws Exception {
        String refreshToken = "mockRefreshToken";
        String userId = "user123";
        String username = "testuser";
        String email = "test@example.com";

        // Mock user and refresh token
        User user = new User();
        user.setUserId(userId);
        user.setUsername(username);
        user.setEmail(email);

        RefreshToken token = new RefreshToken();
        token.setToken(refreshToken);
        token.setUser(user);
        token.setRevoked(false);
        token.setExpiryDate(LocalDateTime.now().plusHours(1));

        HttpHeaders headers = new HttpHeaders();
        headers.add("Set-Cookie", "access_token=mockAccessToken");

        when(cookieUtils.getTokenFromCookies((HttpServletRequest) any(HttpServletRequest.class), eq("refresh_token")))
                .thenReturn(Optional.of(refreshToken));

        when(refreshTokenService.findRefreshToken(refreshToken)).thenReturn(token);
        when(refreshTokenService.verifyRefreshToken(token)).thenReturn(true);
        when(cookieUtils.buildAuthHeadersWithCookies(username, email, userId, refreshToken)).thenReturn(headers);

        mockMvc.perform(MockMvcRequestBuilders.post("/api/users/refreshToken"))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"));
    }
	
	@Test
	void testRefreshTokenMissing() throws Exception {
		when(cookieUtils.getTokenFromCookies(any(HttpServletRequest.class), eq("refresh_token")))
				.thenReturn(Optional.empty());

		when(apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(any(), any(), any(), any(), any(),
				any(), any(), any())).thenReturn(new ResponseEntity<>(HttpStatus.BAD_REQUEST));

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/refreshToken")).andExpect(status().isBadRequest());
	}
	
	@Test
	void testRefreshTokenInvalid() throws Exception {
		String refreshToken = "invalidToken";

		when(cookieUtils.getTokenFromCookies(any(HttpServletRequest.class), eq("refresh_token")))
				.thenReturn(Optional.of(refreshToken));

		when(refreshTokenService.findRefreshToken(refreshToken)).thenReturn(null);

		when(apiResponseStrategy.handleResponseListAndsendAuditLogForJWTFailure(any(), any(), any(), any(), any(),
				any(), any(), any())).thenReturn(new ResponseEntity<>(HttpStatus.UNAUTHORIZED));

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/refreshToken")).andExpect(status().isUnauthorized());
	}
	  
		@Test
		void testRefreshTokenException() throws Exception {
			String refreshToken = "someToken";

			when(cookieUtils.getTokenFromCookies(any(HttpServletRequest.class), eq("refresh_token")))
					.thenReturn(Optional.of(refreshToken));

			when(refreshTokenService.findRefreshToken(refreshToken)).thenThrow(new RuntimeException("DB error"));

			when(apiResponseStrategy.handleResponseAndsendAuditLogForExceptionCase(any(), any(), any(), any(), any(),
					any(), any(), any())).thenReturn(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));

			mockMvc.perform(MockMvcRequestBuilders.post("/api/users/refreshToken"))
					.andExpect(status().isInternalServerError());
		}
	

	@Test
	void testVerifyToken() throws Exception {

		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);

		String authorizationHeader = "Bearer mock.jwt.token";
		when(jwtService.extractUserID("mock.jwt.token")).thenReturn(testUser.getUserId());

		mockMvc.perform(
				MockMvcRequestBuilders.get("/api/users/validateToken").header("Authorization", authorizationHeader))
				.andExpect(jsonPath("$.success").value(true)).andExpect(jsonPath("$.message").value("Token is valid."))
				.andDo(print());
	}


	@Test
	 void testUpdatedUserRole() throws Exception {

		testUser.setEmail("newemail@gmail.com");
		testUser.setVerified(true);
		testUser.setRole(RoleType.MERCHANT);
		testUser.setActive(true);

		// Mock behavior of the user service
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);
		Mockito.when(userService.updateRoleByUser(testUser.getUserId(), RoleType.MERCHANT))
				.thenReturn(DTOMapper.toUserDTO(testUser));

		UserRequest userRequest = new UserRequest();
		userRequest.setRole(RoleType.MERCHANT);
		userRequest.setUserId(testUser.getUserId());

		String authorizationHeader = "Bearer mock.jwt.token";
		when(jwtService.extractUserID("mock.jwt.token")).thenReturn(testUser.getUserId());

		mockMvc.perform(MockMvcRequestBuilders.put("/api/users/roles")
				.contentType(MediaType.APPLICATION_JSON).header("Authorization", authorizationHeader)
				.content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.message").value("Role is updated successfully."))
				.andExpect(jsonPath("$.data.username").value(testUser.getUsername()))
				.andExpect(jsonPath("$.data.email").value("newemail@gmail.com"))
				.andExpect(jsonPath("$.data.role").value(testUser.getRole().toString())).andDo(print());

		// Error Case: Update with invalid user ID (e.g., empty X-User-Id)
		errorUser.setVerified(false);
		UserRequest errorUserRequest = new UserRequest(errorUser.getEmail(), "Pwd@21212", "ErrorUser",
				RoleType.MERCHANT, true);
		errorUserRequest.setUserId(errorUser.getUserId());

		// Mock behavior for the error user
		Mockito.when(userService.findByUserId(errorUser.getUserId())).thenReturn(errorUser);

		mockMvc.perform(MockMvcRequestBuilders.put("/api/users/roles")
				.contentType(MediaType.APPLICATION_JSON).header("Authorization", authorizationHeader)
				.content(objectMapper.writeValueAsString(errorUserRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());

		verify(userService, times(1)).findByUserId(testUser.getUserId());
		verify(userService, times(1)).findByUserId(errorUser.getUserId());
		
		
		errorUser.setVerified(true);
		UserRequest noRoleTypeUserReq = new UserRequest(errorUser.getEmail(), "Pwd@21212", "ErrorUser",
				null, true);
		noRoleTypeUserReq.setUserId(errorUser.getUserId());

		// Mock behavior for the error user
		Mockito.when(userService.findByUserId(errorUser.getUserId())).thenReturn(errorUser);

		mockMvc.perform(MockMvcRequestBuilders.put("/api/users/roles")
				.contentType(MediaType.APPLICATION_JSON).header("Authorization", authorizationHeader)
				.content(objectMapper.writeValueAsString(noRoleTypeUserReq)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());
	}

	@Test
	void getGoogleUserInfo() throws Exception {

		mockUserDTO = new UserDTO();
		mockUserDTO.setEmail("test@example.com");
		mockUserDTO.setUsername("Test User");
		mockUserDTO.setUserID("user-123");

		when(googleAuthService.verifyAndGetUserInfo(anyString())).thenReturn(mockUserDTO);
		
		 
		when(apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(
	            any(UserDTO.class),  // Allow any UserDTO object
	            anyString(),         // Allow any string message
	            any(AuditLogRequest.class) // Allow any AuditLogRequest object
	        )).thenReturn(ResponseEntity.status(HttpStatus.OK).build()); // Return a mocked response (OK)

		mockMvc.perform(MockMvcRequestBuilders.get("/api/users/google/userinfo")
				.header("Authorization", validIdToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Successfully get Google user info."));
		
		mockMvc.perform(MockMvcRequestBuilders.get("/api/users/google/userinfo")
				.header("Authorization", ""))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.success").value(false));
	}
	
	@Test
	void getGoogleUserInfo_NotFound() throws Exception {
	    
	    when(googleAuthService.verifyAndGetUserInfo(anyString())).thenReturn(null);

	    when(apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(
	            any(UserDTO.class),  // Allow any UserDTO object
	            anyString(),         // Allow any string message
	            any(AuditLogRequest.class) // Allow any AuditLogRequest object
	        )).thenReturn(ResponseEntity.status(HttpStatus.OK).build()); // Return a mocked response (OK)

	   
	    
	    mockMvc.perform(MockMvcRequestBuilders.get("/api/users/google/userinfo")
	            .header("Authorization", validIdToken))
	            .andExpect(status().isBadRequest())
	            .andExpect(jsonPath("$.success").value(false))
	            .andExpect(jsonPath("$.message").value("Failed to get Google user info."));  
	    
	}
	
	
	@Test
	void testGenerateAccessToken() throws Exception {
	    when(userService.checkSpecificActiveUserByEmail(testUser.getEmail()))
	            .thenReturn(DTOMapper.toUserDTO(testUser));

	    when(jwtService.generateToken(anyString(), anyString(), anyString()))
	            .thenReturn("mockAccessToken");
	    when(apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(
	            any(UserDTO.class),  // Allow any UserDTO object
	            anyString(),         // Allow any string message
	            any(AuditLogRequest.class) // Allow any AuditLogRequest object
	        )).thenReturn(ResponseEntity.status(HttpStatus.OK).build()); // Return a mocked response (OK)

	    mockMvc.perform(MockMvcRequestBuilders.post("/api/users/accessToken")
	            .contentType(MediaType.APPLICATION_JSON)
	            .content(objectMapper.writeValueAsString(userRequest)))
	            .andExpect(status().isOk())
	            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
	            .andExpect(jsonPath("$.success").value(true))
	            .andExpect(jsonPath("$.message").value("Access token generated successfully."));  
	    
	    userRequest.setEmail("");
	    mockMvc.perform(MockMvcRequestBuilders.post("/api/users/accessToken")
	            .contentType(MediaType.APPLICATION_JSON)
	            .content(objectMapper.writeValueAsString(userRequest)))
	            .andExpect(status().isBadRequest())
	            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
	            .andExpect(jsonPath("$.success").value(false));
	}
	
	@Test
	void testGenerateAccessTokenError() throws Exception {
	    when(userService.checkSpecificActiveUserByEmail(testUser.getEmail()))
	            .thenReturn(DTOMapper.toUserDTO(testUser));

	    when(apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(
	            any(UserDTO.class),  // Allow any UserDTO object
	            anyString(),         // Allow any string message
	            any(AuditLogRequest.class) // Allow any AuditLogRequest object
	        )).thenReturn(ResponseEntity.status(HttpStatus.OK).build()); // Return a mocked response (OK)

	    
	    mockMvc.perform(MockMvcRequestBuilders.post("/api/users/accessToken")
	            .contentType(MediaType.APPLICATION_JSON)
	            .content(objectMapper.writeValueAsString(userRequest)))
	            .andExpect(status().isUnauthorized())
	            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
	            .andExpect(jsonPath("$.success").value(false));
	}

	@Test
	void GenerateAccessToken_UserNotFound() throws Exception {
	    when(userService.checkSpecificActiveUserByEmail(anyString())).thenReturn(null);
	    
	    when(apiResponseStrategy.handleResponseAndSendAuditLogForSuccessCase(
	            any(UserDTO.class),  // Allow any UserDTO object
	            anyString(),         // Allow any string message
	            any(AuditLogRequest.class) // Allow any AuditLogRequest object
	        )).thenReturn(ResponseEntity.status(HttpStatus.OK).build()); // Return a mocked response (OK)

    
	    mockMvc.perform(MockMvcRequestBuilders.post("/api/users/accessToken")
	            .contentType(MediaType.APPLICATION_JSON)
	            .content(objectMapper.writeValueAsString(userRequest)))
	            .andExpect(status().isBadRequest())
	            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
	            .andExpect(jsonPath("$.success").value(false))
	            .andExpect(jsonPath("$.message").value("Invalid user."));
	}


}
