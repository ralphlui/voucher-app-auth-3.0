package voucher.management.app.auth.controller;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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

import com.fasterxml.jackson.databind.ObjectMapper;

import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.dto.ValidationResult;
import voucher.management.app.auth.service.impl.OTPStorageService;
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

    @InjectMocks
    private OTPController otpController;

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(otpController).build();
        objectMapper = new ObjectMapper();
    }

    @Test
    void testGenerateOtp() throws Exception {
        UserRequest userRequest = new UserRequest();
        userRequest.setEmail("test@example.com");
        ValidationResult valid = new ValidationResult();
        valid.setMessage("Valid");
        valid.setStatus(HttpStatus.OK);
        valid.setValid(true);
         
        when(userValidationStrategy.validateObject(userRequest.getEmail()))
            .thenReturn(valid);

        when(otpService.generateAndStoreOTP(userRequest.getEmail())).thenReturn(123456);

        mockMvc.perform(post("/api/otp/generate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }
    

    @Test
    void testOTPValidation() throws Exception {
        UserRequest userRequest = new UserRequest();
        userRequest.setEmail("test@example.com");
        userRequest.setOtp(123456);
        ValidationResult valid = new ValidationResult();
        valid.setMessage("Valid");
        valid.setStatus(HttpStatus.OK);
        valid.setValid(true);
         
        when(userValidationStrategy.validateObject(userRequest.getEmail()))
            .thenReturn(valid);

        when(otpService.validateOTP(userRequest.getEmail(),userRequest.getOtp())).thenReturn(true);

        mockMvc.perform(post("/api/otp/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }


}
