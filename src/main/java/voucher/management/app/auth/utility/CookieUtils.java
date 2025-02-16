package voucher.management.app.auth.utility;

import java.time.Duration;

import org.springframework.http.ResponseCookie;

public class CookieUtils {

	public static ResponseCookie createCookie(String name, String value, boolean httpOnly) {
	    return ResponseCookie.from(name, value)
	            .httpOnly(httpOnly)  // Secure access based on token type
	            .secure(true)        // Ensure HTTPS only
	            .path("/")           // Accessible across the app
	            .maxAge(Duration.ofHours(1)) // More readable expiration
	            .sameSite("Strict")  // CSRF protection
	            .build();
	}
}
