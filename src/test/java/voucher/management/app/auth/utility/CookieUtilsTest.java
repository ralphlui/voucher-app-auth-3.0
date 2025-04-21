package voucher.management.app.auth.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import voucher.management.app.auth.service.impl.JWTService;
import voucher.management.app.auth.service.impl.RefreshTokenService;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@ActiveProfiles("test")
public class CookieUtilsTest {

	@Mock
	private JWTService jwtService;

	@Mock
	private RefreshTokenService refreshTokenService;

	@Test
	void testCreateCookie() {
		CookieUtils cookieUtils = new CookieUtils(jwtService, refreshTokenService);

		String name = "token";
		String value = "abc123";
		boolean httpOnly = true;
		long duration = 2L;

		ResponseCookie cookie = cookieUtils.createCookie(name, value, httpOnly, duration);

		assertEquals(cookie.getName(), name);
		assertEquals(cookie.getValue(), value);
		assertEquals(cookie.isHttpOnly(), httpOnly);
	}

	@Test
	void testGetTokenFromCookies_CookieExists() {
		CookieUtils cookieUtils = new CookieUtils(jwtService, refreshTokenService);

		HttpServletRequest request = mock(HttpServletRequest.class);
		Cookie[] cookies = { new Cookie("token", "abc123"), new Cookie("other", "value") };
		when(request.getCookies()).thenReturn(cookies);

		Optional<String> token = cookieUtils.getTokenFromCookies(request, "token");

		assertTrue(token.isPresent());
		assertEquals("abc123", token.get());
	}

	@Test
	void testCreateHttpHeader_AddsBothCookies() {

		CookieUtils cookieUtils = new CookieUtils(jwtService, refreshTokenService);

		ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", "abc123").path("/").httpOnly(true)
				.build();

		ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", "xyz789").path("/").httpOnly(true)
				.build();

		HttpHeaders headers = cookieUtils.createHttpHeader(accessTokenCookie, refreshTokenCookie);

		List<String> setCookieHeaders = headers.get(HttpHeaders.SET_COOKIE);

		assertNotNull(setCookieHeaders);
		assertEquals(2, setCookieHeaders.size());
		assertTrue(setCookieHeaders.contains(accessTokenCookie.toString()));
		assertTrue(setCookieHeaders.contains(refreshTokenCookie.toString()));
	}

}
