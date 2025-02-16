package voucher.management.app.auth.exception;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import voucher.management.app.auth.dto.APIResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

@SpringBootTest
@ActiveProfiles("test")
public class GlobalExceptionHandlerTest {
	
	@Autowired
    private GlobalExceptionHandler globalExceptionHandler;


	@Test
    void testHandleUserNotFoundException() {
        UserNotFoundException ex = mock(UserNotFoundException.class);
        String errorMessage = "User not found";
        when(ex.getMessage()).thenReturn(errorMessage);

        ResponseEntity<String> responseEntity = globalExceptionHandler.handleUserNotFoundException(ex);

        assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
        assertEquals(errorMessage, responseEntity.getBody());
    }
	
	
	@SuppressWarnings("rawtypes")
	@Test
    void testHandleObjectNotFoundException() {
        Exception ex = new Exception("Test exception message");

        ResponseEntity<APIResponse> responseEntity = globalExceptionHandler.handleObjectNotFoundException(ex);

        // Verify the result
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertEquals("Failed to get data. Test exception message", responseEntity.getBody().getMessage());
    }
	
	@SuppressWarnings("rawtypes")
	@Test
    void testIllegalArgumentException() {
        IllegalArgumentException ex = new IllegalArgumentException("Test illegal argument message");

        ResponseEntity<APIResponse> responseEntity = globalExceptionHandler.illegalArgumentException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertEquals("Invalid data: Test illegal argument message", responseEntity.getBody().getMessage());
    }
}

