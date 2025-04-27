package voucher.management.app.auth.dto;

import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SearchRequest {
	    
	    @Min(0)
	    private int page = 0;

	    @Min(1)
	    private int size = 50;

}
