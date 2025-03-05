package voucher.management.app.auth.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine; 
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class OTPStorageService {
	
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

    
}
