package voucher.management.app.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import jakarta.transaction.Transactional;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.repository.UserRepository;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.utility.EncryptionUtils;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class UserServiceTest {
	
	private static List<User> mockUsers = new ArrayList<>();
	
	@Autowired
	private UserService userService;
	
	@MockBean
	private UserRepository userRepository;
	
	@MockBean
	private PasswordEncoder passwordEncoder;
	
	@MockBean
	private EncryptionUtils encryptionUtils;

	
	private static User user;

	private static UserRequest userRequest;
	@BeforeEach
	void setUp() {
		userRequest = new UserRequest("useradmin@gmail.com", "Pwd@123", "UserAdmin", RoleType.CUSTOMER, true, new ArrayList<String>());
		user = new User(userRequest.getEmail(), userRequest.getUsername(), userRequest.getPassword(), userRequest.getRole(), true);
		userRequest.setUserId("8f6e8b84-1219-4c28-a95c-9891c11328b7");
		user.setPreferences("food");
		user.setUserId(userRequest.getUserId());
		mockUsers.add(user);

	}

	@AfterEach
	public void tearDown() {
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
	void createUser() throws Exception {

		user.setEmail(userRequest.getEmail());
		Mockito.when(userRepository.save(Mockito.any(User.class))).thenReturn(user);
		Mockito.when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
		UserDTO createdUser = userService.createUser(userRequest);
		assertThat(createdUser).isNotNull();
		assertThat(createdUser.getEmail().equals("useradmin@gmail.com")).isTrue();

	}
	
	@Test
    public void testValidateUserLogin_Successful() {
        
        Mockito.when(userRepository.findByEmailAndStatus(user.getEmail(), true, true)).thenReturn(user);
        Mockito.when(passwordEncoder.matches(user.getPassword(), user.getPassword())).thenReturn(true);

        UserDTO result = userService.loginUser(user.getEmail(), user.getPassword());

        assertEquals(user.getEmail(), result.getEmail());
    }
	

	@Test
	public void verifyUser() throws Exception {
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
	void updateUser() throws Exception {

		userRequest.setUsername("Admin");
		Mockito.when(userService.findByUserId(user.getUserId())).thenReturn(user);

		Mockito.when(userRepository.save(user)).thenReturn(user);
		Mockito.when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));

		UserDTO updatedUser = userService.update(userRequest);
		assertThat(updatedUser.getUsername().equals("Admin")).isTrue();

	}
	
	@Test
    public void testFindByEmailAndStatus() {
        
        Mockito.when(userRepository.findByEmailAndStatus(user.getEmail(), true, true)).thenReturn(user);

        User result = userService.findByEmailAndStatus(user.getEmail(), true, true);

        assertEquals(user, result);
    }
	
	@Test
	void getAllActiveUsersByPreferences() throws Exception {

		List<UserDTO> userDTOList = new ArrayList<UserDTO>();
		Pageable pageable = PageRequest.of(0, 10);
		Page<User> mockUserPages = new PageImpl<>(mockUsers, pageable, mockUsers.size());

		Mockito.when(userRepository.findByPreferences("clothing", true, true, RoleType.CUSTOMER, pageable)).thenReturn(mockUserPages);
		Map<Long, List<UserDTO>> userPages = userService.findUsersByPreferences("clothing", pageable);

		for (Map.Entry<Long, List<UserDTO>> entry : userPages.entrySet()) {
			userDTOList = entry.getValue();

		}
		assertEquals(mockUsers.size(), userDTOList.size());
		assertEquals(mockUsers.get(0).getEmail(), userDTOList.get(0).getEmail());
	}
	
	@Test
	void resetPassword() throws Exception {

		Mockito.when(userRepository.findByUserIdAndStatus(user.getUserId(), true, true)).thenReturn(user);
		Mockito.when(userRepository.save(user)).thenReturn(user);
     

		UserDTO updatedUser = userService.resetPassword(user.getUserId(), user.getPassword());
		assertThat(updatedUser.getEmail().equals("useradmin@gmail.com")).isTrue();

	}
	
	@Test
	void checkSpecificActiveUser() throws Exception {

		Mockito.when(userRepository.findByUserIdAndStatus(user.getUserId(), true, true)).thenReturn(user);
     
		UserDTO activeUser = userService.checkSpecificActiveUser(user.getUserId());
		assertThat(activeUser.getEmail().equals(user.getEmail())).isTrue();
		
	}
	
	@Test
	void deletePreferencesByUser() throws Exception {

		ArrayList<String> deletedPreferenceList = new ArrayList<String>();
		deletedPreferenceList.add("food");
		userRequest.setPreferences(deletedPreferenceList);
		Mockito.when(userService.findByUserId(user.getUserId())).thenReturn(user);
		Mockito.when(userRepository.save(user)).thenReturn(user);
     
	    UserDTO updateUser = userService.deletePreferencesByUser(userRequest.getUserId(), userRequest.getPreferences());
	    assertEquals(updateUser.getPreferences(), null);
		
	}
	
	@Test
	void updatePreferencesByUser() throws Exception {

		ArrayList<String> updatedPreferenceList = new ArrayList<String>();
		updatedPreferenceList.add("clothing");
		Mockito.when(userService.findByUserId(user.getUserId())).thenReturn(user);
		Mockito.when(userRepository.save(user)).thenReturn(user);
     
	    UserDTO updateUser = userService.updatePreferencesByUser(user.getUserId(),updatedPreferenceList);	
	    assertEquals(updateUser.getPreferences().isEmpty(), false);
	    assertEquals(updateUser.getPreferences().size(), 1);
	    assertNotNull(updateUser.getPreferences());
	}

}
