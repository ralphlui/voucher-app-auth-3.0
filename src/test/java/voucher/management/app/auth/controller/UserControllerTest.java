package voucher.management.app.auth.controller;

import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.repository.UserRepository;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.utility.DTOMapper;
import voucher.management.app.auth.utility.EncryptionUtils;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@ActiveProfiles("test")
public class UserControllerTest {
	

	@MockBean
	private UserService userService;
	
	
	@MockBean
	private UserRepository userRepository;

	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	private ObjectMapper objectMapper;
	
	@Autowired
	private EncryptionUtils encryptionUtils;

	
	User testUser;
	User errorUser;
	UserRequest userRequest = new UserRequest();

	private static List<UserDTO> mockUsers = new ArrayList<>();


	@BeforeEach
	void setUp() {
		userRequest = new UserRequest("useradmin@gmail.com", "Pwd@21212", "UserAdmin", RoleType.MERCHANT, true, new ArrayList<String>());
		userRequest.setUserId("8f6e8b84-1219-4c28-a95c-9891c11328b7");
		testUser = new User(userRequest.getEmail(), userRequest.getUsername(), userRequest.getPassword(), userRequest.getRole(), true);
		errorUser = new User("error@gmail.com", "Error", "Pwd@21212", RoleType.MERCHANT, true);
		errorUser.setUserId("0");
		testUser.setPreferences("food");
		testUser.setUserId(userRequest.getUserId());

		mockUsers.add(DTOMapper.toUserDTO(testUser));
	}

	@AfterEach
	public void tearDown() {
		testUser = new User();
		errorUser = new User();
		userRequest = new UserRequest();

	}
	
	@Test
	public void testGetAllUser() throws Exception {

		Pageable pageable = PageRequest.of(0, 10, Sort.by("username").ascending());
		Map<Long, List<UserDTO>> mockUserMap = new HashMap<>();
		mockUserMap.put(0L, mockUsers);

		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);
		Mockito.when(userService.findActiveUsers(pageable)).thenReturn(mockUserMap);

		mockMvc.perform(MockMvcRequestBuilders.get("/api/users")
				.param("page", "0").param("size", "10")
				.header("X-User-Id", testUser.getUserId())
				.contentType(MediaType.APPLICATION_JSON))
		        .andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Successfully get all active verified user.")).andDo(print());
		
		Map<Long, List<UserDTO>> emptyMockUserMap = new HashMap<>();
		List<UserDTO> emptyMockUsers = new ArrayList<>();
		emptyMockUserMap.put(0L, emptyMockUsers);

		Mockito.when(userService.findActiveUsers(pageable)).thenReturn(emptyMockUserMap);
		mockMvc.perform(MockMvcRequestBuilders.get("/api/users")
				.param("page", "0").param("size", "10")
				.header("X-User-Id", testUser.getUserId())
				.contentType(MediaType.APPLICATION_JSON)).andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("No Active User List.")).andDo(print());

	}
	
	@Test
	public void testUserLogin() throws Exception {
		testUser.setVerified(true);
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);
		Mockito.when(userService.findByEmail(userRequest.getEmail())).thenReturn(testUser);

		Mockito.when(userService.loginUser(userRequest.getEmail(), userRequest.getPassword()))
				.thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/login").contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", testUser.getUserId())
				.content(objectMapper.writeValueAsString(userRequest))).andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.message").value(userRequest.getEmail() + " login successfully"))
				.andExpect(jsonPath("$.data.username").value(userRequest.getUsername()))
				.andExpect(jsonPath("$.data.email").value(userRequest.getEmail()))
				.andExpect(jsonPath("$.data.role").value(userRequest.getRole().toString())).andDo(print());
		
		UserRequest userNotFoundRequest = new UserRequest(errorUser.getEmail(), "Pwd@21212");

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/login").contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", "")
				.content(objectMapper.writeValueAsString(userNotFoundRequest)))
				.andExpect(MockMvcResultMatchers.status().isNotFound())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.message").value("User account not found."))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());

	}
	


	@Test
	public void testVerifyUser() throws Exception {

		String decodedVerificationCode = "7f03a9a9-d7a5-4742-bc85-68d52b2bee45";
		String verificationCode = encryptionUtils.encrypt(decodedVerificationCode);
		testUser.setVerified(true);
		testUser.setActive(true);
		testUser.setVerificationCode(decodedVerificationCode);

		Mockito.when(userService.verifyUser(verificationCode)).thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.patch("/api/users/verify/{verifyid}", verificationCode)	
				.header("X-User-Id", testUser.getUserId()))
		        .andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data.verified").value(true))
				.andDo(print());
		
		
		testUser.setVerificationCode("");
		mockMvc.perform(MockMvcRequestBuilders.put("/api/users/verify/{verifyid}", "")
				).andExpect(MockMvcResultMatchers.status().isInternalServerError())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false))
				.andDo(print());
		
		
	}
	
	@Test
	public void testCreateUser() throws Exception {
		Mockito.when(userService.createUser(Mockito.any(UserRequest.class))).thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.data.username").value(userRequest.getUsername()))
				.andExpect(jsonPath("$.data.email").value(userRequest.getEmail()))
				.andExpect(jsonPath("$.data.role").value(userRequest.getRole().toString())).andDo(print());

		User errorUser = new User("", "Error", "Pwd@21212", RoleType.MERCHANT, true);
		mockMvc.perform(MockMvcRequestBuilders.post("/api/users").contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(errorUser)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.message").value("Email cannot be empty.")).andDo(print());
	}

	@Test
	public void testResetPassword() throws Exception {
		testUser.setVerified(true);
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);

		UserRequest userRequest = new UserRequest(testUser.getEmail(), "Password@345");
		userRequest.setUserId(testUser.getUserId());
		Mockito.when(userService.resetPassword(userRequest.getUserId(), userRequest.getPassword()))
				.thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.patch("/api/users/{id}/resetPassword", testUser.getUserId())
				.contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", testUser.getUserId())
				.content(objectMapper.writeValueAsString(userRequest)))
		         .andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Reset Password is completed."))
				.andDo(print());
	}

	@Test
	public void testUpdatedUser() throws Exception {
		testUser.setEmail("newemail@gmail.com");
		testUser.setVerified(true);
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);

		Mockito.when(userService.update(Mockito.any(UserRequest.class))).thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.put("/api/users/{id}", testUser.getUserId())
				.contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", testUser.getUserId())
				.content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.message").value("User updated successfully."))
				.andExpect(jsonPath("$.data.username").value(testUser.getUsername()))
				.andExpect(jsonPath("$.data.email").value("newemail@gmail.com"))
				.andExpect(jsonPath("$.data.role").value(testUser.getRole().toString())).andDo(print());

		errorUser.setActive(false);
		UserRequest errorUserRequest = new UserRequest(errorUser.getEmail(), "Pwd@21212", "ErrorUser", RoleType.MERCHANT, false, new ArrayList<String>());
		errorUserRequest.setUserId(errorUser.getUserId());
		Mockito.when(userService.findByUserId(errorUser.getUserId())).thenReturn(errorUser);

		mockMvc.perform(MockMvcRequestBuilders.put("/api/users/{id}", errorUser.getUserId())
				.contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", "")
				.content(objectMapper.writeValueAsString(errorUserRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());

	}
	
	@Test
	public void testActiveUser() throws Exception {
		testUser.setVerified(true);
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);
		Mockito.when(userService.checkSpecificActiveUser(testUser.getUserId())).thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.get("/api/users/{id}/active", testUser.getUserId())
				.contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", testUser.getUserId())
				.content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.data.username").value(testUser.getUsername()))
				.andExpect(jsonPath("$.data.email").value(testUser.getEmail()))
				.andExpect(jsonPath("$.data.active").value(true))
				.andExpect(jsonPath("$.data.verified").value(true))
				.andDo(print());

		errorUser.setVerified(false);
		Mockito.when(userService.findByUserId(errorUser.getUserId())).thenReturn(errorUser);
		mockMvc.perform(MockMvcRequestBuilders.get("/api/users/{id}/active", errorUser.getUserId())
				.header("X-User-Id", "")
				.contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(errorUser)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());
	}

	@Test
	public void testGetAllUsersByPreferences() throws Exception {

		Pageable pageable = PageRequest.of(0, 10, Sort.by("username").ascending());
		Map<Long, List<UserDTO>> mockUserMap = new HashMap<>();
		mockUserMap.put(0L, mockUsers);

		Mockito.when(userService.findUsersByPreferences("clothing", pageable)).thenReturn(mockUserMap);

		mockMvc.perform(MockMvcRequestBuilders.get("/api/users/preferences/{preference}", "clothing").param("page", "0")
				.param("size", "10")
				.header("X-User-Id", userRequest.getUserId())
				.contentType(MediaType.APPLICATION_JSON))
				.andExpect(MockMvcResultMatchers.status().isOk()).andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Successfully get all active users by this preference."))
				.andDo(print());

		mockMvc.perform(MockMvcRequestBuilders.get("/api/users/preferences/{preference}", "shoes").param("page", "0")
				.param("size", "10")
				.header("X-User-Id", userRequest.getUserId())
				.contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false)).andDo(print());

	}
	
	@Test
	void testDeletePreferencesByUser() throws Exception {
		
		testUser.setVerified(true);
		ArrayList<String> deletedPreferenceList = new ArrayList<String>();
		deletedPreferenceList.add("food");
		userRequest.setPreferences(deletedPreferenceList);
		
		Mockito.when(userService.findByUserId(userRequest.getUserId())).thenReturn(testUser);
		Mockito.when(userService.deletePreferencesByUser(userRequest.getUserId(),userRequest.getPreferences()))
		   .thenReturn(DTOMapper.toUserDTO(testUser));
		

		
		mockMvc.perform(MockMvcRequestBuilders.delete("/api/users/{id}/preferences", userRequest.getUserId())
				.contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", userRequest.getUserId())
				.content(objectMapper.writeValueAsString(userRequest)))
		        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Preferences are deleted successfully."))
				.andExpect(jsonPath("$.data.username").value(testUser.getUsername()))
			    .andDo(print());
		
		UserRequest errorUserRequest = new UserRequest();
		errorUserRequest.setUserId("0");
		mockMvc.perform(MockMvcRequestBuilders.delete("/api/users/{id}/preferences", errorUserRequest.getUserId())
				.contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", "")
				.content(objectMapper.writeValueAsString(errorUserRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false))
				.andDo(print());
	}
	
	@Test
	void testUpdatedPreferencesByUser() throws Exception {

		testUser.setVerified(true);
		ArrayList<String> updatedPreferenceList = new ArrayList<String>();
		updatedPreferenceList.add("clothing");
		userRequest.setPreferences(updatedPreferenceList);
		
		Mockito.when(userService.findByUserId(userRequest.getUserId())).thenReturn(testUser);
		Mockito.when(userService.updatePreferencesByUser(userRequest.getUserId(), userRequest.getPreferences()))
				.thenReturn(DTOMapper.toUserDTO(testUser));

		mockMvc.perform(MockMvcRequestBuilders.patch("/api/users/{id}/preferences", userRequest.getUserId())
				.contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", userRequest.getUserId())
				.content(objectMapper.writeValueAsString(userRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Preferences are updated successfully."))
				.andDo(print());
		
		UserRequest errorUserRequest = new UserRequest();
		errorUserRequest.setUserId("0");
		mockMvc.perform(MockMvcRequestBuilders.patch("/api/users/{id}/preferences", errorUserRequest.getUserId())
				.contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", "")
				.content(objectMapper.writeValueAsString(errorUserRequest)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.success").value(false))
				.andDo(print());
	}
	
	
	@Test
	public void testUserLogout() throws Exception {
		Mockito.when(userService.findByUserId(testUser.getUserId())).thenReturn(testUser);

		mockMvc.perform(MockMvcRequestBuilders.post("/api/users/logout").contentType(MediaType.APPLICATION_JSON)
				.header("X-User-Id", testUser.getUserId())
				.content(objectMapper.writeValueAsString(userRequest))).andExpect(MockMvcResultMatchers.status().isOk())
		        .andExpect(jsonPath("$.success").value(true))
			    .andDo(print());

	}
}
