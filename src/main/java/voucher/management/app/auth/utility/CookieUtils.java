package voucher.management.app.auth.utility;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.security.InvalidKeyException;
import jakarta.servlet.http.HttpServletRequest;
import voucher.management.app.auth.service.impl.JWTService;
import voucher.management.app.auth.service.impl.RefreshTokenService;
import jakarta.servlet.http.Cookie;

@Component
public class CookieUtils {
	
	 
	private final JWTService jwtService;
	 
	private final RefreshTokenService refreshTokenService;
	
	public CookieUtils(JWTService jwtService, RefreshTokenService refreshTokenService) {
		this.jwtService = jwtService;
		this.refreshTokenService = refreshTokenService;
	}
	

	public ResponseCookie createCookie(String name, String value, boolean httpOnly, long duration) {
	    return ResponseCookie.from(name, value)
	            .httpOnly(httpOnly)  // Secure access based on token type
	            .secure(false)        // Ensure HTTPS only
	            .path("/")           // Accessible across the app
	            .maxAge(Duration.ofHours(duration)) // More readable expiration
	            .sameSite("Strict")  // CSRF protection
	            .build();
	}
	
	public Optional<String> getTokenFromCookies(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) return Optional.empty();

        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
	
	public HttpHeaders createCookies(String userName, String email, String userid, String refreshToken) throws InvalidKeyException, Exception {	
		String newAccessToken = jwtService.generateToken(userName, email, userid, false);
		String newRefreshToken = refreshToken == null ? jwtService.generateToken(userName, email, userid, true) : refreshToken;

		ResponseCookie accessTokenCookie = createCookie("access_token", newAccessToken, false, 1);
		ResponseCookie refreshTokenCookie = createCookie("refresh_token", newRefreshToken, true, 1);

		// Add cookie to headers
		HttpHeaders headers = createHttpHeader(accessTokenCookie, refreshTokenCookie);
		if (refreshToken == null) {
			refreshTokenService.saveRefreshToken(userid, newRefreshToken);
		}
			
		return headers;
	}
	
	
	public HttpHeaders createHttpHeader(ResponseCookie accessTokenCookie, ResponseCookie responseTokenCookie) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
		headers.add(HttpHeaders.SET_COOKIE, responseTokenCookie.toString());
		return headers;
	}
}
