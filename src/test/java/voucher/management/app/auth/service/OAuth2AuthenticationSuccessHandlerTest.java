package voucher.management.app.auth.service;

import static org.mockito.Mockito.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import voucher.management.app.auth.service.impl.OAuth2AuthenticationSuccessHandler;
import voucher.management.app.auth.utility.CookieUtils;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.service.impl.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;


@SpringBootTest
@Transactional
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class OAuth2AuthenticationSuccessHandlerTest {

	@InjectMocks
	private OAuth2AuthenticationSuccessHandler authSuccessHandler;

	@Mock
	private UserService userService;

	@Mock
	private AuditLogService auditLogService;

	@Mock
	private CookieUtils cookieUtils;
 

	@Mock
	private OAuth2AuthenticationToken authentication;

	private final String frontEndUrl = "http://localhost:3000";
	private final String emailFrom = "noreply@example.com";
	private final String sqsUrl = "https://sqs.amazonaws.com/queue";

	@BeforeEach
	void setup() {

		authSuccessHandler = new OAuth2AuthenticationSuccessHandler(frontEndUrl, emailFrom, sqsUrl);

		ReflectionTestUtils.setField(authSuccessHandler, "auditLogService", auditLogService);
		ReflectionTestUtils.setField(authSuccessHandler, "userService", userService);
		ReflectionTestUtils.setField(authSuccessHandler, "cookieUtils", cookieUtils); 
	}

	@Test
	void testOnAuthenticationSuccess_NewUser() throws Exception {
	
		OAuth2AuthenticationToken authToken = mock(OAuth2AuthenticationToken.class);
		OAuth2User principal = mock(OAuth2User.class);
		when(authToken.getPrincipal()).thenReturn(principal);
		when(principal.getAttribute("email")).thenReturn("test@example.com");
		when(principal.getAttribute("name")).thenReturn("Test User");

		when(userService.findByEmail(anyString())).thenReturn(null);

		UserDTO userDTO = new UserDTO();
		userDTO.setEmail("test@example.com");
		when(userService.createUser(any(UserRequest.class))).thenReturn(userDTO);

		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest();

		authSuccessHandler.onAuthenticationSuccess(request, response, authToken);

		verify(auditLogService, times(1)).sendAuditLogToSqs(any(), any(), any(), any(), any(), any(), any(), any(),
				any());
	}

	@Test
	void testOnAuthenticationSuccess_ExistingUser() throws Exception {
	    
	    HttpServletRequest request = mock(HttpServletRequest.class);
	    HttpServletResponse response = mock(HttpServletResponse.class);

	    Map<String, Object> attributes = new HashMap<>();
	    attributes.put("email", "user@example.com");
	    attributes.put("name", "Test User");
	    String accessToken = "access-token";
        String refreshToken = "refresh-token";
        
      
	    ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", accessToken).build();
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken).build();

        HttpHeaders mockHeaders = new HttpHeaders();
        mockHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        mockHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        when(cookieUtils.createHttpHeader(any(), any())).thenReturn(mockHeaders);
        when(cookieUtils.createCookies(any(), any(), any(), any())).thenReturn(mockHeaders);


	    OAuth2User oAuth2User = new DefaultOAuth2User(Collections.emptyList(), attributes, "email");
	    OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
	    when(authentication.getPrincipal()).thenReturn(oAuth2User);

	    User existingUser = new User();
	    existingUser.setEmail("user@example.com");
	    existingUser.setUsername("Test User");
	    existingUser.setUserId("123");

	    when(userService.findByEmail("user@example.com")).thenReturn(existingUser);
	    when(cookieUtils.createCookie(any(), any(), anyBoolean(), anyInt())).thenReturn(null);
	    
 
	    authSuccessHandler.onAuthenticationSuccess(request, response, authentication);

	}

}
