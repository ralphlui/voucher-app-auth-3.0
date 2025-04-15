package voucher.management.app.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;

import jakarta.transaction.Transactional;
import voucher.management.app.auth.configuration.AWSConfig;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuthProvider;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.repository.UserRepository;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.utility.AmazonSES;
import voucher.management.app.auth.utility.DTOMapper;
import voucher.management.app.auth.utility.EncryptionUtils;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class UserServiceTest {

	private static List<User> mockUsers = new ArrayList<>();

	@Spy
	@InjectMocks
	private UserService userService;

	@MockitoBean
	private UserRepository userRepository;

	@MockitoBean
	private PasswordEncoder passwordEncoder;

	@Mock
	private EncryptionUtils encryptionUtils;
	
	@Mock
    private AWSConfig awsConfig;

    @Mock
    private AmazonSimpleEmailService amazonSimpleEmailService;
    
    @Mock
    private AmazonSES amazonSES;

	

	@Value("${frontend.url}")
	private String frontEndUrl = "https://example.com";

	private static User user;

	private static UserRequest userRequest;
	

    private final String encryptedCode = "encryptedCode123";
    private final String decryptedCode = "decryptedCode456";

	@BeforeEach
	void setUp() {
		userService = new UserService(userRepository, passwordEncoder, encryptionUtils, null);
		userRequest = new UserRequest("useradmin@gmail.com", "Pwd@123", "UserAdmin", RoleType.CUSTOMER, true);
		user = new User(userRequest.getEmail(), userRequest.getUsername(), userRequest.getPassword(),
				userRequest.getRole(), true);
		userRequest.setUserId("8f6e8b84-1219-4c28-a95c-9891c11328b7");
		userRequest.setAuthProvider(AuthProvider.GOOGLE);
		user.setUserId(userRequest.getUserId());
		user.setAuthProvider(userRequest.getAuthProvider());
		mockUsers.add(user);

	}

	@AfterEach
	void tearDown() {
		user = new User();
		userRequest = new UserRequest();

	}

	@Test
	void getAllActiveUsers() {

		List<UserDTO> userDTOList = new ArrayList<UserDTO>();
		Pageable pageable = PageRequest.of(0, 10);
		Page<User> mockUserPages = new PageImpl<>(mockUsers, pageable, mockUsers.size());

		Mockito.when(userRepository.findActiveUserList(true, true, pageable)).thenReturn(mockUserPages);
		Map<Long, List<UserDTO>> userPages = userService.findActiveUsers(pageable);

		for (Map.Entry<Long, List<UserDTO>> entry : userPages.entrySet()) {
			userDTOList = entry.getValue();

		}
		assertEquals(mockUsers.size(), userDTOList.size());
		assertEquals(mockUsers.get(0).getEmail(), userDTOList.get(0).getEmail());

	}
	

    @Test
    void testFindActiveUsersexceptionThrown() {
        Pageable pageable = PageRequest.of(0, 10);
        Mockito.when(userRepository.findActiveUserList(true, true, pageable))
               .thenThrow(new RuntimeException("Database error"));

        assertThrows(RuntimeException.class, () -> {
            userService.findActiveUsers(pageable);
        });
    }

	@Test
	void createUser() throws Exception  {

		user.setEmail(userRequest.getEmail());
		Mockito.when(userRepository.save(Mockito.any(User.class))).thenReturn(user);
		Mockito.when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
		UserDTO createdUser = userService.createUser(userRequest);
		assertThat(createdUser).isNotNull();
		assertThat(createdUser.getEmail().equals("useradmin@gmail.com")).isTrue();

	}

	@Test
	void testValidateUserLogin_Successful() {

		Mockito.when(userRepository.findByEmailAndStatus(user.getEmail(), true, true)).thenReturn(user);
		Mockito.when(passwordEncoder.matches(user.getPassword(), user.getPassword())).thenReturn(true);

		UserDTO result = userService.loginUser(user.getEmail(), user.getPassword());

		assertEquals(user.getEmail(), result.getEmail());
	}
	
	
	@Test
    void testLoginUserInvalidPassword() {
        // Arrange
        String email = "user@example.com";
        String rawPassword = "wrongPassword";

        User user = new User();
        user.setEmail(email);
        user.setPassword("encodedPassword");

        when(userRepository.findByEmailAndStatus(email, true, true)).thenReturn(user);
        when(passwordEncoder.matches(rawPassword, "encodedPassword")).thenReturn(false);

        // Act & Assert
        assertThrows(UserNotFoundException.class, () -> userService.loginUser(email, rawPassword));
        verify(passwordEncoder).matches(rawPassword, "encodedPassword");
    }

    @Test
    void testLoginUser_UserNotFound() {
        // Arrange
        String email = "missing@example.com";
        when(userRepository.findByEmailAndStatus(email, true, true)).thenReturn(null);

        // Act & Assert
        assertThrows(UserNotFoundException.class, () -> userService.loginUser(email, "anyPassword"));
        verify(userRepository).findByEmailAndStatus(email, true, true);
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    void testLoginUserExceptionHandling() {
        // Arrange
        String email = "error@example.com";
        when(userRepository.findByEmailAndStatus(email, true, true))
            .thenThrow(new RuntimeException("DB error"));

        // Act & Assert
        RuntimeException ex = assertThrows(RuntimeException.class, () -> userService.loginUser(email, "password"));
        assertEquals("DB error", ex.getMessage());
    }

	@Test
	void verifyUser() throws Exception{
		String decodedVerificationCode = "7f03a9a9-d7a5-4742-bc85-68d52b2bee45";
		String verificationCode = encryptionUtils.encrypt(decodedVerificationCode);

		Mockito.when(encryptionUtils.decrypt(verificationCode)).thenReturn(decodedVerificationCode);
		Mockito.when(userRepository.findByVerificationCode(decodedVerificationCode, false, true)).thenReturn(user);
		Mockito.when(userRepository.save(Mockito.any(User.class))).thenReturn(user);

		UserDTO verifiedUser = userService.verifyUser(verificationCode);

		assertThat(user.isVerified()).isTrue();
		assertThat(verifiedUser).isNotNull();
	}

	@Test
	void updateUser(){

		userRequest.setUsername("Admin");
		Mockito.when(userService.findByUserId(user.getUserId())).thenReturn(user);

		Mockito.when(userRepository.save(user)).thenReturn(user);
		Mockito.when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));

		UserDTO updatedUser = userService.update(userRequest);
		assertThat(updatedUser.getUsername().equals("Admin")).isTrue();

	}
	
	@Test
	void testUpdateUserUserNotFound() {

		UserRequest request = new UserRequest();
		request.setUserId("nonexistent");

		when(userRepository.findByUserId("nonexistent")).thenReturn(null);

		assertThrows(UserNotFoundException.class, () -> userService.update(request));
		verify(userRepository).findByUserId("nonexistent");
	}
	

	@Test
	void testUpdateUserExceptionHandling() {

		UserRequest request = new UserRequest();
		request.setUserId("user123");

		when(userRepository.findByUserId("user123")).thenThrow(new RuntimeException("DB down"));

		Exception exception = assertThrows(RuntimeException.class, () -> userService.update(request));
		assertEquals("DB down", exception.getMessage());
	}
	

	@Test
	void testFindByEmailAndStatus() {

		Mockito.when(userRepository.findByEmailAndStatus(user.getEmail(), true, true)).thenReturn(user);

		User result = userService.findByEmailAndStatus(user.getEmail(), true, true);

		assertEquals(user, result);
	}

	@Test
	void resetPassword() {

		Mockito.when(userRepository.findByUserIdAndStatus(user.getUserId(), true, true)).thenReturn(user);
		Mockito.when(userRepository.save(user)).thenReturn(user);

		UserDTO updatedUser = userService.resetPassword(user.getUserId(), user.getPassword());
		assertThat(updatedUser.getEmail().equals("useradmin@gmail.com")).isTrue();

	}
	
	
	@Test
    void testResetPasswordUserNotFound() {
        // Arrange
        String userId = "missingUser";

        when(userService.findByUserIdAndStatus(userId, true, true)).thenReturn(null);

        // Act & Assert
        assertThrows(UserNotFoundException.class, () -> userService.resetPassword(userId, "somePass"));
        verify(userRepository, never()).save(any());
    }

    @Test
    void testResetPasswordExceptionHandling() {
        // Arrange
        String userId = "user123";

        when(userService.findByUserIdAndStatus(userId, true, true))
            .thenThrow(new RuntimeException("Unexpected error"));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> userService.resetPassword(userId, "pass"));
        assertEquals("Unexpected error", exception.getMessage());
    }

	@Test
	void checkSpecificActiveUser() {

		Mockito.when(userRepository.findByUserIdAndStatus(user.getUserId(), true, true)).thenReturn(user);

		UserDTO activeUser = userService.checkSpecificActiveUser(user.getUserId());
		assertThat(activeUser.getEmail().equals(user.getEmail())).isTrue();

	}
	
	@Test
    void testCheckSpecificActiveUserUserDoesNotExistThrowsException() {
       
        String userId = "unknownUser";
        when(userRepository.findByUserIdAndStatus(userId, true, true)).thenReturn(null);

       
        assertThrows(UserNotFoundException.class, () -> {
            userService.checkSpecificActiveUser(userId);
        });
    }

    @Test
    void testCheckSpecificActiveUserUnexpectedExceptionThrowsOriginalException() {
       
        String userId = "anyUser";
        when(userRepository.findByUserIdAndStatus(userId, true, true)).thenThrow(new RuntimeException("DB error"));

       
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            userService.checkSpecificActiveUser(userId);
        });

        assertEquals("DB error", exception.getMessage());
    }


	@Test
	void updateUserRole() {

		Mockito.when(userRepository.findByUserId(user.getUserId())).thenReturn(user);
		Mockito.when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
		Mockito.when(userRepository.save(Mockito.any(User.class))).thenReturn(user);

		UserDTO updatedUser = userService.updateRoleByUser(user.getUserId(), userRequest.getRole());

		assertNotNull(updatedUser);
		assertEquals("UserAdmin", updatedUser.getUsername());
		assertEquals(RoleType.CUSTOMER, updatedUser.getRole());
	}

	@Test
	void testUpdateRoleByUserUnexpectedException() {

		String userId = "123";
		RoleType newRole = RoleType.ADMIN;

		when(userRepository.findByUserId(userId)).thenThrow(new RuntimeException("DB failure"));

		Exception exception = assertThrows(RuntimeException.class, () -> {
			userService.updateRoleByUser(userId, newRole);
		});

		assertTrue(exception.getMessage().contains("Failed to update user role"));
		assertNotNull(exception.getCause());
	}
	
	@Test
	void checkSpecificActiveUserByEmail() throws Exception {

		Mockito.when(userRepository.findByEmailAndStatus(user.getEmail(), true, true)).thenReturn(user);

		
		UserDTO activeUser = userService.checkSpecificActiveUserByEmail(user.getEmail());
		assertThat(activeUser.getEmail()).isEqualTo(user.getEmail());


	}

	@Test
	void testCheckSpecificActiveUserByEmailUserNotFound() {
		
		String email = "notfound@example.com";

		when(userRepository.findByEmailAndStatus(email, true, true)).thenReturn(null);

		
		assertThrows(UserNotFoundException.class, () -> {
			userService.checkSpecificActiveUserByEmail(email);
		});
	}

	@Test
	void testCheckSpecificActiveUserByEmail_ExceptionHandling() {
		
		String email = "error@example.com";

		when(userRepository.findByEmailAndStatus(email, true, true)).thenThrow(new RuntimeException("Database error"));

		Exception exception = assertThrows(RuntimeException.class, () -> {
			userService.checkSpecificActiveUserByEmail(email);
		});

		assertEquals("Database error", exception.getMessage());
	}
	
	@Test
    void findActiveUserByID() {
    
        when(userRepository.findByUserIdAndStatus(user.getUserId(), true, true)).thenReturn(user);

        User result = userService.findActiveUserByID(user.getUserId());

        assertNotNull(result);
        assertEquals(user.getUserId(), result.getUserId());
        assertEquals("useradmin@gmail.com", result.getEmail());
        
    }
	

    @Test
    void testFindActiveUserByID_UserNotFound() {
        String userId = "456";

        when(userRepository.findByUserIdAndStatus(userId, true, true)).thenReturn(null);

        UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> {
            userService.findActiveUserByID(userId);
        });

        assertEquals("This user is not an active or verified user", exception.getMessage());
        verify(userRepository).findByUserIdAndStatus(userId, true, true);
    }
    
    @Test
    void testverifyUserUserNotFound() throws Exception {
        // Arrange
        Mockito.when(encryptionUtils.decrypt(encryptedCode)).thenReturn(decryptedCode);
        Mockito.when(userRepository.findByVerificationCode(decryptedCode, false, true)).thenReturn(null);

        // Act & Assert
        Exception exception = Assertions.assertThrows(UserNotFoundException.class, () -> {
            userService.verifyUser(encryptedCode);
        });

        Assertions.assertEquals("Vefriy user failed: Verfiy Id is invalid or already verified.", exception.getMessage());
    }

	@Test
	void testverifyUserUserDTONull() throws Exception {
		// Arrange
		User user = new User();
		user.setVerified(false);
		user.setVerificationCode(decryptedCode);

		User savedUser = new User();
		savedUser.setVerified(true);

		Mockito.when(encryptionUtils.decrypt(encryptedCode)).thenReturn(decryptedCode);
		Mockito.when(userRepository.findByVerificationCode(decryptedCode, false, true)).thenReturn(user);
		Mockito.when(userRepository.save(user)).thenReturn(savedUser);
		try (MockedStatic<DTOMapper> mockedStatic = Mockito.mockStatic(DTOMapper.class)) {
			mockedStatic.when(() -> DTOMapper.toUserDTO(savedUser)).thenReturn(null);

			Exception exception = Assertions.assertThrows(UserNotFoundException.class, () -> {
				userService.verifyUser(encryptedCode);
			});

			Assertions.assertEquals("Vefriy user failed: Verify Id is invalid or already verified.",
					exception.getMessage());
		}
	}
	
	 @Test
	    void testCreateUserwithGoogleProvider_success() throws Exception {
	        // Given
	        UserRequest request = new UserRequest();
	        request.setEmail("google@example.com");
	        request.setUsername("googleuser");
	        request.setPassword("anyPassword");
	        request.setAuthProvider(AuthProvider.GOOGLE);
	        request.setRole(RoleType.CUSTOMER);

	        when(passwordEncoder.encode(toString())).thenReturn("encoded");
	        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

	        // When
	        UserDTO result = userService.createUser(request);

	        // Then
	        assertNotNull(result);
	        assertEquals("google@example.com", result.getEmail());
	        verify(userRepository).save(any(User.class));
	        // ensure email verification is not sent
	    }

	    @Test
	    void testCreateUserSaveFails_throwsException() {
	        // Given
	        UserRequest request = new UserRequest();
	        request.setEmail("fail@example.com");
	        request.setUsername("failuser");
	        request.setPassword("password");
	        request.setAuthProvider(AuthProvider.NATIVE);
	        request.setRole(RoleType.CUSTOMER);

	        when(passwordEncoder.encode(toString())).thenReturn("encoded");
	        when(userRepository.save(any(User.class))).thenReturn(null);

	        // Then
	        Exception exception = assertThrows(Exception.class, () -> {
	            userService.createUser(request);
	        });

	        assertTrue(exception.getMessage().contains("User registration is not successful"));
	    }
	    

	    @Test
	    void testSendVerificationEmail_ExceptionHandling() {
	        // Arrange
	        User user = new User();
	        user.setUsername("Test");
	        user.setEmail("fail@example.com");
	        user.setVerificationCode("failcode");

	        when(awsConfig.sesClient()).thenThrow(new RuntimeException("SES client error"));

	        // Act & Assert: Should not throw, just log error
	        assertDoesNotThrow(() -> userService.sendVerificationEmail(user));
	    }

		@Test
		void testFindByEmail_userExists() {
			String email = "test@example.com";
			User mockUser = new User();
			mockUser.setUserId("123");
			mockUser.setEmail(email);

			Mockito.when(userRepository.findByEmail(email)).thenReturn(mockUser);

			User result = userService.findByEmail(email);

			assertNotNull(result);
			assertEquals(email, result.getEmail());
		}

		@Test
		void testFindByEmail_userNotFound() {
			String email = "nonexistent@example.com";

			Mockito.when(userRepository.findByEmail(email)).thenReturn(null);

			User result = userService.findByEmail(email);

			assertNull(result);
		}

}
