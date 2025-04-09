package voucher.management.app.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import voucher.management.app.auth.service.impl.PasswordValidatorService;

public class PasswordValidatorServiceTest {

    @Test
    void testPasswordTooShort() {
        String result = PasswordValidatorService.validatePassword("A1#d");
        assertEquals("Password must be within 8-30 characters long.", result);
    }

    @Test
    void testPasswordTooLong() {
        String longPassword = "A1#d".repeat(10);
        String result = PasswordValidatorService.validatePassword(longPassword);
        assertEquals("Password must be within 8-30 characters long.", result);
    }

    @Test
    void testPasswordMissingUppercase() {
        String result = PasswordValidatorService.validatePassword("abc#1234");
        assertEquals("Password must contain at least one uppercase letter.", result);
    }

    @Test
    void testPasswordMissingLowercase() {
        String result = PasswordValidatorService.validatePassword("ABC#1234");
        assertEquals("Password must contain at least one lowercase letter.", result);
    }

    @Test
    void testPasswordMissingDigit() {
        String result = PasswordValidatorService.validatePassword("Abc#defg");
        assertEquals("Password must contain at least one numeric digit.", result);
    }

    @Test
    void testPasswordMissingSpecialCharacter() {
        String result = PasswordValidatorService.validatePassword("Abc12345");
        assertEquals("Password must contain at least one special character.", result);
    }

    @Test
    void testPasswordContainingDictionaryWord() {
        // Assuming "admin" is in dictionary.txt
        String result = PasswordValidatorService.validatePassword("Adm1n#Pass");
        assertEquals("Password must not contain common dictionary words.", result);
    }

    @Test
    void testValidPassword() {
        String result = PasswordValidatorService.validatePassword("12345678kH@");
        assertEquals("valid", result);
    }

    @Test
    void testContainsNonAlphanumericCharacters() {
        assertTrue(PasswordValidatorService.containsNonAlphanumericCharacters("abc$123"));
    }
}

