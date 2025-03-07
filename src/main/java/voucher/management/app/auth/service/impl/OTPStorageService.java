package voucher.management.app.auth.service.impl;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import voucher.management.app.auth.configuration.AWSConfig;
import voucher.management.app.auth.utility.AmazonSES;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@Service
public class OTPStorageService {
	
	@Autowired
	private AWSConfig awsConfig;
	
	private static final Logger logger = LoggerFactory.getLogger(UserService.class);
	
    private final Cache<String, Integer> otpCache = Caffeine.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .build();

    public int generateAndStoreOTP(String email) {
        int otp = (int) (100000 + Math.random() * 900000); // Generate 6-digit OTP
        otpCache.put(email, otp);
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
    
	public void sendOtpEmail(int otp, String email) {
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
    
}
