package voucher.management.app.auth.service;


import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;

import jakarta.transaction.Transactional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuthProvider;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.service.impl.GoogleAuthService;
import voucher.management.app.auth.service.impl.UserService;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class GoogleAuthServiceTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private GoogleAuthService googleAuthService;

    @Spy
    private RestTemplate restTemplate = new RestTemplate();

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        googleAuthService.googleTokenInfoUrl = "https://oauth2.googleapis.com/tokeninfo?id_token=";
    }

    @Test
    public void testVerifyAndGetUserInfo_existingUser() throws Exception {
        // Mock token
        String token = "mock-token";

        // Spy the verifier (can't mock final classes easily without using PowerMock or Mockito-inline)
        GoogleIdToken mockIdToken = mock(GoogleIdToken.class);
        GoogleIdTokenVerifier verifier = mock(GoogleIdTokenVerifier.class);
        when(verifier.verify(token)).thenReturn(mockIdToken);

        // Set up restTemplate response
        Map<String, Object> googleInfo = new HashMap<>();
        googleInfo.put("email", "test@example.com");
        googleInfo.put("name", "Test User");

        RestTemplate spyTemplate = spy(new RestTemplate());
        doReturn(googleInfo).when(spyTemplate).getForObject(anyString(), eq(Map.class));
        googleAuthService.googleTokenInfoUrl = "https://mock-url/";

        // Mock user service
        User user = new User();
        user.setEmail("test@example.com");
        user.setUsername("Test User");
        user.setRole(RoleType.CUSTOMER);
        user.setAuthProvider(AuthProvider.GOOGLE);
        when(userService.findByEmail("test@example.com")).thenReturn(user);

        // Act
        UserDTO result = googleAuthService.verifyAndGetUserInfo(token);

        // Assert
        assertNotNull(result);
    }

    @Test
    public void testVerifyAndGetUserInfo_newUser() throws Exception {
        String token = "new-user-token";

        GoogleIdToken mockIdToken = mock(GoogleIdToken.class);
        GoogleIdTokenVerifier verifier = mock(GoogleIdTokenVerifier.class);
        when(verifier.verify(token)).thenReturn(mockIdToken);

        Map<String, Object> googleInfo = new HashMap<>();
        googleInfo.put("email", "newuser@example.com");
        googleInfo.put("name", "New User");

        doReturn(googleInfo).when(restTemplate).getForObject(anyString(), eq(Map.class));
        googleAuthService.googleTokenInfoUrl = "https://mock-url/";

        when(userService.findByEmail("newuser@example.com")).thenReturn(null);

        UserDTO mockDTO = new UserDTO();
        mockDTO.setEmail("newuser@example.com");
        mockDTO.setUsername("New User");
        when(userService.createUser(any(UserRequest.class))).thenReturn(mockDTO);

        UserDTO result = googleAuthService.verifyAndGetUserInfo(token);

        assertNotNull(result);
    }
}

