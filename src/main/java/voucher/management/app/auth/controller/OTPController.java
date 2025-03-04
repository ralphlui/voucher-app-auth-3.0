package voucher.management.app.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import voucher.management.app.auth.dto.APIResponse;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.dto.ValidationResult;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.service.impl.OTPStorageService;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.strategy.impl.UserValidationStrategy;

@RestController
@RequestMapping("/api/otp")
public class OTPController {
	
	private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private OTPStorageService otpService;
    
    @Autowired
	private UserValidationStrategy userValidationStrategy;
	
    
    @PostMapping("/generate")
    public ResponseEntity<APIResponse<UserDTO>> generateOtp(@RequestBody UserRequest userRequest) {
    	try {
    	//check userEmail is valid 
    	logger.info("Reset Password : " + userRequest.getEmail());
    	ValidationResult validationResult = userValidationStrategy.validateObject(userRequest.getEmail());
    	if (!validationResult.isValid()) {
			
			logger.error("generateOtp Error: " + validationResult.getMessage());
			return ResponseEntity.status(validationResult.getStatus()).body(APIResponse.error(validationResult.getMessage()));			
		}
    	
    	
    	int otp = otpService.generateAndStoreOTP(userRequest.getEmail());
       // otpService.sendOTPEmail(email, otp);
        
        String message ="";
        if(otp>0) {
        	message ="OTP sent to " + userRequest.getEmail() + ". It is valid for 10 minutes.";
        }
        return ResponseEntity.status(HttpStatus.OK).body(APIResponse.success(message));
        
    
    	} catch (Exception e) {
    		String message = "OTP code generation failed.";
    		logger.error("generateOtp Error: " +message );
    		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(APIResponse.error(message));			
		}
	}

  
}


