package voucher.management.app.auth.strategy;

import voucher.management.app.auth.dto.ValidationResult;

public interface IAPIHelperValidationStrategy<T> {

	ValidationResult validateCreation(T data) ;
	
	ValidationResult validateObject(String data);
	
	ValidationResult validateUpdating(T data) ;
	
	ValidationResult validateObjectByUserId(T userId,boolean requiresPasswordValidation);
}
