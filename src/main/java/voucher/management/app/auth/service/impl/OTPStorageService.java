package voucher.management.app.auth.service.impl;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import voucher.management.app.auth.configuration.AWSConfig;
import org.springframework.data.redis.core.StringRedisTemplate;

import voucher.management.app.auth.utility.AmazonSES;
import voucher.management.app.auth.utility.GeneralUtility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@Service
public class OTPStorageService {
	
	@Autowired
	private AWSConfig awsConfig;
	
	@Autowired
	private StringRedisTemplate redisTemplate;
	

	private static final Logger logger = LoggerFactory.getLogger(UserService.class);
	
	private static final String DIGITS = "0123456789";
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final int OTP_VALIDITY_DURATION = 10; // 10 minutes
	private static final int OTP_LENGTH = 6;
	
    private final Cache<String, Integer> otpCache = Caffeine.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .build();

    public String generateAndStoreOTP(String email) {
        String otp = generateRandomOTP(); // Generate 6-digit OTP
        String hashedEmail = GeneralUtility.hashWithSHA256(email);
        String storedOtp = getOtp(hashedEmail);
        if (storedOtp != null) {
			deleteOtp(hashedEmail);
		}
		redisTemplate.opsForValue().set(hashedEmail, otp, Duration.ofMinutes(OTP_VALIDITY_DURATION));
        return otp;
    }
    
    public boolean validateOTP(String email, int otp) {
        Integer storedOtp = otpCache.getIfPresent(email);
        if (storedOtp == null || storedOtp != otp) {
            return false;    
        }
        otpCache.invalidate(email);
        return true;
    }
    
	public void sendOtpEmail(String otp, String email) {
		try {
			AmazonSimpleEmailService client = awsConfig.sesClient();
			String from = awsConfig.getEmailFrom().trim();

			String subject = "OTP Notification";
			String body = "We have received your request for a One-Time Password.<br><h3>" + otp + "</h3><br>"
					+ "The above code will be expired in 10 mins.<br>"
					+ "This is an auto-generated email, please do not reply.";

			AmazonSES.sendEmail(client, from, Arrays.asList(email), subject, body);
		} catch (Exception e) {
			logger.error("Error occurred while sending otp, " + e.toString());
			e.printStackTrace();
		}
	}
	
	public String getOtp(String key) {
		return redisTemplate.opsForValue().get(key);
	}
	
	private void deleteOtp(String key) {
		redisTemplate.opsForValue().getAndDelete(key);
	}
	
	private String generateRandomOTP() {
		StringBuilder otp = new StringBuilder();
		for (int i = 0; i < OTP_LENGTH; i++) {
			otp.append(DIGITS.charAt(RANDOM.nextInt(DIGITS.length())));
		}
		return otp.toString();
	}
    
}
