package voucher.management.app.auth.service.impl;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import org.springframework.stereotype.Service;

@Service
public class PasswordValidatorService {

	 
	private static final Pattern NON_ALPHANUMERIC_PATTERN = Pattern.compile("[^a-zA-Z0-9]");
	private static final int MIN_LENGTH = 8;
	private static final int MAX_LENGTH = 30;
	
    private static final Pattern UPPER_CASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern LOWER_CASE_PATTERN = Pattern.compile("[a-z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("\\d");
   
	 
	public static boolean containsNonAlphanumericCharacters(String password) {
		return NON_ALPHANUMERIC_PATTERN.matcher(password).find();
	}

	public static String validatePassword(String password) {
        if (password == null || password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            return "Password must be within 8-30 characters long.";
        }

        if (!UPPER_CASE_PATTERN.matcher(password).find()) {
            return "Password must contain at least one uppercase letter.";
        }

        if (!LOWER_CASE_PATTERN.matcher(password).find()) {
            return "Password must contain at least one lowercase letter.";
        }

        if (!DIGIT_PATTERN.matcher(password).find()) {
            return "Password must contain at least one numeric digit.";
        }

        if (!containsNonAlphanumericCharacters(password)) {
            return "Password must contain at least one special character.";
        }
        
        return "valid";
    }

}
