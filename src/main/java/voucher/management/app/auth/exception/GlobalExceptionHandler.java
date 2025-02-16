package voucher.management.app.auth.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import voucher.management.app.auth.dto.APIResponse;


@RestControllerAdvice
public class GlobalExceptionHandler {

	 private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(UserNotFoundException.class)
	public ResponseEntity<String> handleUserNotFoundException(UserNotFoundException ex) {

		ex.printStackTrace();

		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
	}

	@SuppressWarnings("rawtypes")
	@ExceptionHandler(Exception.class)
	@ResponseBody
	ResponseEntity<APIResponse> handleObjectNotFoundException(Exception ex){
		String message = "Failed to get data. " + ex.getMessage();
		 logger.error(message);
		  return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(APIResponse.error(message));
	}
	
	
	@SuppressWarnings("rawtypes")
	@ExceptionHandler(IllegalArgumentException.class)
    @ResponseBody
    public ResponseEntity<APIResponse> illegalArgumentException(IllegalArgumentException ex) {
        String message = "Invalid data: " + ex.getMessage();
        logger.error(message);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(APIResponse.error(message));
    }

}

