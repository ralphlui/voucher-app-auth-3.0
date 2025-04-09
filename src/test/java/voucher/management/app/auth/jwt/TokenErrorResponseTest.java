package voucher.management.app.auth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TokenErrorResponseTest {

    @Test
    void testSendErrorResponse() throws IOException {
        // Given
        MockHttpServletResponse response = new MockHttpServletResponse();
        String message = "Invalid token";
        int status = 401;
        String error = "Unauthorized"; // Not used in logic but part of the method signature

        // When
        TokenErrorResponse.sendErrorResponse(response, message, status, error);

        // Then
        assertEquals(status, response.getStatus());
        assertEquals("application/json", response.getContentType());

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> responseMap = mapper.readValue(response.getContentAsString(), Map.class);

        assertEquals(false, responseMap.get("success"));
        assertEquals(message, responseMap.get("message"));
        assertEquals(0, responseMap.get("totalRecord"));
        assertNull(responseMap.get("data"));
        assertEquals(status, responseMap.get("status"));
    }
}
