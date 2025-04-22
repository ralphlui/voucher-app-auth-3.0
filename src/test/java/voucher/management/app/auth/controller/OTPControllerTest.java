package voucher.management.app.auth.controller;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test; 
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;

import voucher.management.app.auth.dto.*;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.service.impl.AuditLogService;
import voucher.management.app.auth.service.impl.JWTService;
import voucher.management.app.auth.service.impl.OTPService;
import voucher.management.app.auth.service.impl.RefreshTokenService;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.strategy.impl.APIResponseStrategy;
import voucher.management.app.auth.strategy.impl.UserValidationStrategy;
import voucher.management.app.auth.utility.CookieUtils;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@ActiveProfiles("test")
class OTPControllerTest {

    private MockMvc mockMvc;
    
    @Mock
    private OTPService otpService;
    
    @Mock
    private UserValidationStrategy userValidationStrategy;
    
    @Mock
    private  APIResponseStrategy apiResponseStrategy;
    
    @Mock
    private UserService userService;
    
    @Mock
    private AuditLogService auditLogService;
    
    @InjectMocks
    private OTPController otpController;
    
    private ObjectMapper objectMapper;
    
    @Mock
	private JWTService jwtService;

	@Mock
	private CookieUtils cookieUtils;

	
	@Mock
	private RefreshTokenService refreshTokenService;
	
	
    
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(otpController).build();
        objectMapper = new ObjectMapper();
    }
    
    @Test
    void testGenerateOtp() throws Exception {
        UserRequest userRequest = new UserRequest("test@example.com", null);
        ValidationResult validationResult = new ValidationResult();
        validationResult.setMessage("");
        validationResult.setStatus(HttpStatus.OK);
        validationResult.setValid(true);
        
        UserDTO userDTO = new UserDTO();
        userDTO.setActive(true);
        userDTO.setEmail("test@example.com");
        userDTO.setRole(RoleType.MERCHANT);
        userDTO.setVerified(true);
        userDTO.setUserID("123412");
        
        when(userValidationStrategy.validateObject(userRequest.getEmail())).thenReturn(validationResult);
        when(otpService.generateOTP(userRequest.getEmail())).thenReturn("123456");
        when(userService.checkSpecificActiveUser("123")).thenReturn(userDTO);
        
        mockMvc.perform(post("/api/users/otp/generate")
                .header("X-User-Id", "123")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isOk()).andDo(print());
    }

	@Test
	void testGenerateOtpInvalidInput() throws Exception {
		UserRequest userRequest = new UserRequest();
		userRequest.setEmail("test@example.com");
		userRequest.setOtp("123456");
		ValidationResult invalidResult = new ValidationResult();
		invalidResult.setValid(false);
		invalidResult.setUserId("userId123");
		invalidResult.setUserName("testuser");

		ResponseEntity<APIResponse<UserDTO>> badRequestResponse = ResponseEntity.badRequest().body(null);

		when(userValidationStrategy.validateObject("test@example.com")).thenReturn(invalidResult);
		when(apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(eq(invalidResult), anyString(),
				anyString(), anyString(), anyString(), anyString(), anyString())).thenReturn(badRequestResponse);

		mockMvc.perform(post("/api/users/otp/generate").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(userRequest))).andExpect(status().isBadRequest())
				.andDo(print());
	}
 
    
    @Test
    void testValidateOtp() throws Exception {
        UserRequest userRequest = new UserRequest("test@example.com", "123456");

        ValidationResult validationResult = new ValidationResult();
        validationResult.setMessage("");
        validationResult.setStatus(HttpStatus.OK);
        validationResult.setValid(true);

        UserDTO userDTO = new UserDTO();
        userDTO.setActive(true);
        userDTO.setEmail("test@example.com");
        userDTO.setRole(RoleType.MERCHANT);
        userDTO.setVerified(true);
        userDTO.setUserID("123");

        String userName = userDTO.getUsername();
        String email = userDTO.getEmail();
        String userId = userDTO.getUserID();
        String accessToken = "access-token";
        String refreshToken = "refresh-token";

        // Mock the cookies
        ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", accessToken).build();
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken).build();

        // Mock the creation of HttpHeaders and manually add cookies to it
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        headers.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        when(jwtService.generateToken(userName, email, userId, false)).thenReturn(accessToken);
        when(jwtService.generateToken(userName, email, userId, true)).thenReturn(refreshToken);
        when(cookieUtils.createCookie("access_token", accessToken, false, 1)).thenReturn(accessTokenCookie);
        when(cookieUtils.createCookie("refresh_token", refreshToken, true, 1)).thenReturn(refreshTokenCookie);

        doNothing().when(refreshTokenService).saveRefreshToken(userId, refreshToken);

        when(userValidationStrategy.validateObject(userRequest.getEmail())).thenReturn(validationResult);
        when(otpService.validateOTP(userRequest.getEmail(), userRequest.getOtp())).thenReturn(true);
        when(userService.checkSpecificActiveUser("123")).thenReturn(userDTO);

        // Perform the test with the mocked cookies in the headers
        mockMvc.perform(post("/api/users/otp/validate")
                .header("X-User-Id", "123")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andDo(print())
                .andExpect(status().isOk());
    }
    
    
    @Test
    public void testValidateOtpInvalidOtp() throws Exception {
        UserRequest request = new UserRequest();
        request.setEmail("test@example.com");
        request.setOtp("000000");

        ValidationResult validationResult = new ValidationResult();
        validationResult.setValid(true);
        validationResult.setUserId("userId123");
        validationResult.setUserName("testuser");

        UserDTO userDTO = new UserDTO();
        userDTO.setUsername("testUser");
        userDTO.setEmail("test@example.com");
        userDTO.setUserID("123");

        Mockito.when(userValidationStrategy.validateObject(anyString())).thenReturn(validationResult);
        Mockito.when(otpService.validateOTP(anyString(), anyString())).thenReturn(false);
        Mockito.when(userService.checkSpecificActiveUserByEmail(anyString())).thenReturn(userDTO);

        APIResponse<UserDTO> failedResponse = new APIResponse<UserDTO>(false, "OTP expired or incorrect", 0, null);
        Mockito.when(apiResponseStrategy.handleResponseAndsendAuditLogForFailedCase(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new org.springframework.http.ResponseEntity<>(failedResponse, HttpStatus.BAD_REQUEST));

        mockMvc.perform(post("/api/users/otp/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("OTP expired or incorrect"));
    }
    
	@Test
	void testValidateOtpInvalidInput() throws Exception {
		UserRequest userRequest = new UserRequest();
		userRequest.setEmail("test@example.com");
		userRequest.setOtp("123456");
		ValidationResult invalidResult = new ValidationResult();
		invalidResult.setValid(false);
		invalidResult.setUserId("userId123");
		invalidResult.setUserName("testuser");

		ResponseEntity<APIResponse<UserDTO>> badRequestResponse = ResponseEntity.badRequest().body(null);

		when(userValidationStrategy.validateObject("test@example.com")).thenReturn(invalidResult);
		when(apiResponseStrategy.handleResponseAndsendAuditLogForValidationFailure(eq(invalidResult), anyString(),
				anyString(), anyString(), anyString(), anyString(), anyString())).thenReturn(badRequestResponse);

		mockMvc.perform(post("/api/users/otp/validate").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(userRequest))).andExpect(status().isBadRequest())
				.andDo(print());
	}


	  @Test
	    public void testValidateOtpSuccess() throws Exception {
	        UserRequest request = new UserRequest();
	        request.setEmail("test@example.com");
	        request.setOtp("123456");

	        ValidationResult validationResult = new ValidationResult();
	        validationResult.setValid(true);
	        validationResult.setUserId("123");
	        validationResult.setUserName("testuser");
	        
	        UserDTO userDTO = new UserDTO();
	        userDTO.setUsername("testUser");
	        userDTO.setEmail("test@example.com");
	        userDTO.setUserID("123");
	        HttpHeaders headers = new HttpHeaders();

	        Mockito.when(userValidationStrategy.validateObject(anyString())).thenReturn(validationResult);
	        Mockito.when(otpService.validateOTP(anyString(), anyString())).thenReturn(true);
	        Mockito.when(userService.checkSpecificActiveUserByEmail(anyString())).thenReturn(userDTO);
	        Mockito.when(cookieUtils.createCookies(any(), any(), any(), any())).thenReturn(headers);

	        APIResponse<UserDTO> response = new APIResponse<UserDTO>(true, "OTP is valid.", 1, userDTO);
	        Mockito.when(apiResponseStrategy.handleResponseWithHeaderAndSendAuditLogForSuccessCase(any(), any(), any(), any()))
	                .thenReturn(new org.springframework.http.ResponseEntity<>(response, headers, HttpStatus.OK));

	        mockMvc.perform(post("/api/users/otp/validate")
	                        .contentType(MediaType.APPLICATION_JSON)
	                        .content(objectMapper.writeValueAsString(request)))
	                .andExpect(status().isOk())
	                .andExpect(jsonPath("$.message").value("OTP is valid."));
	    }
    
}

