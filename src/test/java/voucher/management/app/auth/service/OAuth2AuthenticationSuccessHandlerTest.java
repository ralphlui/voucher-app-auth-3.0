package voucher.management.app.auth.service;

import static org.mockito.Mockito.*;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import voucher.management.app.auth.service.impl.OAuth2AuthenticationSuccessHandler;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class OAuth2AuthenticationSuccessHandlerTest {

    private OAuth2AuthenticationSuccessHandler successHandler;

    @Mock
    private OAuth2AuthenticationToken authenticationToken;

    @Mock
    private OAuth2User principal;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        successHandler = new OAuth2AuthenticationSuccessHandler("http://frontend-url") {
            @Override
			public boolean userExists(String email) {
                 
                return true;
            }
        };
    }

    @Test
    public void testOnAuthenticationSuccess_WithEmail() throws ServletException, IOException {
       
        when(authenticationToken.getPrincipal()).thenReturn(principal);
        when(principal.getAttribute("email")).thenReturn("user@example.com"); // Simulating user with email

        successHandler.onAuthenticationSuccess(request, response, authenticationToken);

        verify(response).sendRedirect("http://frontend-url/dashboard");
    }

   
}

