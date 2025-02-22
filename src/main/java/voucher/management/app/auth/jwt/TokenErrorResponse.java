package voucher.management.app.auth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class TokenErrorResponse {

	
    public static void sendErrorResponse(HttpServletResponse response, String message, int status, String error) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");

        Map<String, Object> errorDetails = new HashMap<>();
        ObjectMapper objectMapper = new ObjectMapper();

        errorDetails.put("success", false);
        errorDetails.put("message", message);
        errorDetails.put("totalRecord", 0);
        errorDetails.put("data", null);
        //errorDetails.put("status", status);
        //errorDetails.put("error", error);

        response.getWriter().write(objectMapper.writeValueAsString(errorDetails));
    }
}
