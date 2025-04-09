package voucher.management.app.auth.service;


import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;

import voucher.management.app.auth.configuration.AWSConfig;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.dto.ValidationResult;
import voucher.management.app.auth.service.impl.OTPService;
import voucher.management.app.auth.utility.GeneralUtility;
import voucher.management.app.auth.utility.AmazonSES;

public class OTPServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private AWSConfig awsConfig;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private OTPService otpService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    void testGenerateOTPStoresInRedis() {
        String email = "test@example.com";
        String hashedEmail = GeneralUtility.hashWithSHA256(email);

        when(redisTemplate.opsForValue().get(hashedEmail)).thenReturn(null);

        String otp = otpService.generateOTP(email);

        assertNotNull(otp);
        assertEquals(6, otp.length());
        verify(valueOperations).set(eq(hashedEmail), eq(otp), eq(Duration.ofMinutes(10)));
    }
    

    @Test
    void testValidateOTP_Success() {
        String email = "test@example.com";
        String otp = "123456";
        String hashedEmail = GeneralUtility.hashWithSHA256(email);

        when(valueOperations.get(hashedEmail)).thenReturn(otp);
        when(redisTemplate.opsForValue().get(hashedEmail)).thenReturn(otp);

        boolean result = otpService.validateOTP(email, otp);

        assertTrue(result);
        verify(valueOperations).getAndDelete(hashedEmail);
    }

    @Test
    void testValidateOTP_Failure() {
        String email = "test@example.com";
        String otp = "123456";
        String hashedEmail = GeneralUtility.hashWithSHA256(email);

        when(valueOperations.get(hashedEmail)).thenReturn("654321");
        when(redisTemplate.opsForValue().get(hashedEmail)).thenReturn("654321");

        boolean result = otpService.validateOTP(email, otp);

        assertFalse(result);
    }

    @Test
    void testSendOTPEmail_Success() {
        String email = "test@example.com";
        String otp = "654321";

        AmazonSimpleEmailService sesClient = mock(AmazonSimpleEmailService.class);
        when(awsConfig.sesClient()).thenReturn(sesClient);
        when(awsConfig.getEmailFrom()).thenReturn("noreply@example.com");

        try (MockedStatic<AmazonSES> mockedSES = mockStatic(AmazonSES.class)) {
            mockedSES.when(() -> AmazonSES.sendEmail(any(), any(), any(), any(), any())).thenReturn(true);

            boolean result = otpService.sendOTPEmail(otp, email);

            assertTrue(result);
        }
    }

    @Test
    void testSendOTPEmail_Failure() {
        String email = "test@example.com";
        String otp = "654321";

        when(awsConfig.sesClient()).thenThrow(new RuntimeException("AWS failure"));

        boolean result = otpService.sendOTPEmail(otp, email);

        assertFalse(result);
    }
}

