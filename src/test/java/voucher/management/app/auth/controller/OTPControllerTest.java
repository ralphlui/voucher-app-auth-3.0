package voucher.management.app.auth.controller;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test; 
import org.mockito.InjectMocks;
import org.mockito.Mock; 
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;

import voucher.management.app.auth.dto.*;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.service.impl.AuditLogService;
import voucher.management.app.auth.service.impl.OTPStorageService;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.strategy.impl.UserValidationStrategy;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@ActiveProfiles("test")
class OTPControllerTest {

    private MockMvc mockMvc;
    
    @Mock
    private OTPStorageService otpService;
    
    @Mock
    private UserValidationStrategy userValidationStrategy;
    
    @Mock
    private UserService userService;
    
    @Mock
    private AuditLogService auditLogService;
    
    @InjectMocks
    private OTPController otpController;
    
    private ObjectMapper objectMapper;
    
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(otpController).build();
        objectMapper = new ObjectMapper();
    }
    
    @Test
    void testGenerateOtp_Success() throws Exception {
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
        when(otpService.generateAndStoreOTP(userRequest.getEmail())).thenReturn(123456);
        when(userService.checkSpecificActiveUser("123")).thenReturn(userDTO);
        
        mockMvc.perform(post("/api/otp/generate")
                .header("X-User-Id", "123")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("OTP sent to test@example.com. It is valid for 10 minutes."));
    }
    
    @Test
    void testGenerateOtp_UserNotFound() throws Exception {
        UserRequest userRequest = new UserRequest("test@example.com", null);

        ValidationResult validationResult = new ValidationResult();
        validationResult.setMessage("");
        validationResult.setStatus(HttpStatus.NOT_FOUND);
        validationResult.setValid(false);
        
        when(userValidationStrategy.validateObject(userRequest.getEmail())).thenReturn(validationResult);
        when(userService.checkSpecificActiveUser("123")).thenThrow(new UserNotFoundException("User not found"));
        
        mockMvc.perform(post("/api/otp/generate")
                .header("X-User-Id", "123")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isNotFound());
    }
    
    @Test
    void testValidateOtp_Success() throws Exception {
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
        userDTO.setUserID("123412");
        
        when(userValidationStrategy.validateObject(userRequest.getEmail())).thenReturn(validationResult);
        when(otpService.validateOTP(userRequest.getEmail(), userRequest.getOtp())).thenReturn(true);
        when(userService.checkSpecificActiveUser("123")).thenReturn(userDTO);
        
        mockMvc.perform(post("/api/otp/validate")
                .header("X-User-Id", "123")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("OTP is valid."));
    }
    
    @Test
    void testValidateOtp_InvalidOtp() throws Exception {
       UserRequest userRequest = new UserRequest("test@example.com", "123456");
        
        ValidationResult validationResult = new ValidationResult();
        validationResult.setMessage("");
        validationResult.setStatus(HttpStatus.BAD_REQUEST);
        validationResult.setValid(false);
         
        when(userValidationStrategy.validateObject(userRequest.getEmail())).thenReturn(validationResult);
        when(otpService.validateOTP(userRequest.getEmail(), userRequest.getOtp())).thenReturn(false);
        
        mockMvc.perform(post("/api/otp/validate")
                .header("X-User-Id", "123")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isBadRequest());
    }
}

