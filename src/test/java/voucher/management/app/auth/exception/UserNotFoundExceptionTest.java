package voucher.management.app.auth.exception;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@ActiveProfiles("test")
public class UserNotFoundExceptionTest {
	@Test
    void testConstructor() {
        // Create an instance of UserNotFoundException
        String errorMessage = "User not found";
        UserNotFoundException exception = new UserNotFoundException(errorMessage);

        // Verify that the message is correctly set
        assertEquals(errorMessage, exception.getMessage());
    }
}
