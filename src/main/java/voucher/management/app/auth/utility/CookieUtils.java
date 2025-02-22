package voucher.management.app.auth.utility;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Cookie;

@Component
public class CookieUtils {

	public ResponseCookie createCookie(String name, String value, boolean httpOnly) {
	    return ResponseCookie.from(name, value)
	            .httpOnly(httpOnly)  // Secure access based on token type
	            .secure(true)        // Ensure HTTPS only
	            .path("/")           // Accessible across the app
	            .maxAge(Duration.ofHours(1)) // More readable expiration
	            .sameSite("Strict")  // CSRF protection
	            .build();
	}
	
	public Optional<String> getRefreshTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() == null) return Optional.empty();

        return Arrays.stream(request.getCookies())
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
}
