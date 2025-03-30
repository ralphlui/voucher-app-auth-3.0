package voucher.management.app.auth.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;

import lombok.AllArgsConstructor;
import voucher.management.app.auth.configuration.AWSConfig;
import voucher.management.app.auth.utility.AmazonSES;
import voucher.management.app.auth.utility.GeneralUtility;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;

@AllArgsConstructor
@Service
public class OTPService {

	 
	private static final Logger logger = LoggerFactory.getLogger(OTPService.class);

	private static final int OTP_LENGTH = 6;
	private static final int OTP_VALIDITY_DURATION = 10;
	private static final String DIGITS = "0123456789";
	private static final SecureRandom RANDOM = new SecureRandom();

	
	private final StringRedisTemplate redisTemplate;
	
	private final AWSConfig awsConfig;
 

	public String generateOTP(String email) {
		String otp = generateRandomOTP(); // Generate 6-digit OTP
		String hashedEmail = GeneralUtility.hashWithSHA256(email);
		String storedOtp = getOtp(hashedEmail);
		if (storedOtp != null) {
			deleteOtp(hashedEmail);
		}
		redisTemplate.opsForValue().set(hashedEmail, otp, Duration.ofMinutes(OTP_VALIDITY_DURATION));
		return otp;
	}

	private String generateRandomOTP() {
		StringBuilder otp = new StringBuilder();
		for (int i = 0; i < OTP_LENGTH; i++) {
			otp.append(DIGITS.charAt(RANDOM.nextInt(DIGITS.length())));
		}
		return otp.toString();
	}

	public String getOtp(String key) {
		return redisTemplate.opsForValue().get(key);
	}

	private void deleteOtp(String key) {
		redisTemplate.opsForValue().getAndDelete(key);
	}

	public boolean validateOTP(String email, String otp) {
		String hashedEmail = GeneralUtility.hashWithSHA256(email);
		String storedOTP = getOtp(hashedEmail);

		if (storedOTP != null && storedOTP.equals(otp)) {
			deleteOtp(hashedEmail);
			return true;
		}
		return false;
	}

	public boolean sendOTPEmail(String otp, String email) {
		boolean isSent = false;
		try {
			AmazonSimpleEmailService client = awsConfig.sesClient();
			String from = awsConfig.getEmailFrom().trim();

			String subject = "OTP Notification";
			String body = "We have received your request for a One-Time Password.<br><h3>" + otp + "</h3><br>"
					+ "The above code will be expired in 10 mins.<br>"
					+ "This is an auto-generated email, please do not reply.";

			isSent = AmazonSES.sendEmail(client, from, Arrays.asList(email), subject, body);
		} catch (Exception e) {

		    logger.error("Error occurred while sending OTP: {}", e.toString(), e);

		}

		return isSent;
	}
}
