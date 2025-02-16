package voucher.management.app.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class APIResponse<T> {

	private Boolean success;
	private String message;
	private long totalRecord;
	private T data;


	public static <T> APIResponse<T> success(String message) {
		return APIResponse.<T>builder().success(true).message(message).data(null).totalRecord(1).build();
	}
	
	public static <T> APIResponse<T> noList(T data, String message) {
		return APIResponse.<T>builder().success(true).message(message).data(data).totalRecord(0).build();
	}

	public static <T> APIResponse<T> error(T data) {
		return APIResponse.<T>builder().success(false).message("error").totalRecord(0).build();
	}

	public static <T> APIResponse<T> error(String message) {
		return APIResponse.<T>builder().success(false).message(message).totalRecord(0).build();
	}

	public static <T> APIResponse<T> success(T data, String message) {
		return APIResponse.<T>builder().success(true).message(message).data(data).totalRecord(1).build();
	}


	public static <T> APIResponse<T> success(T data, String message, long totalRecord) {
		return APIResponse.<T>builder().success(true).message(message).totalRecord(totalRecord).data(data).build();
	}

}
