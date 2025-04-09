package voucher.management.app.auth.utility;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@ActiveProfiles("test")
class EncryptionUtilsTest {

    private EncryptionUtils encryptionUtils;

    // Example 16-byte (128-bit) AES key in hex (must be 32 hex characters for 128-bit key)
    private static final String TEST_KEY = "00112233445566778899AABBCCDDEEFF";

    @BeforeEach
    void setUp() throws Exception {
        encryptionUtils = new EncryptionUtils();
        Field aesSecretKeyField = EncryptionUtils.class.getDeclaredField("aesSecretKey");
        aesSecretKeyField.setAccessible(true);
        aesSecretKeyField.set(encryptionUtils, TEST_KEY);
    }

    @Test
    void testEncryptionAndDecryption() throws Exception {
        String originalText = "HelloWorld123!";
        String encryptedText = encryptionUtils.encrypt(originalText);
        assertNotNull(encryptedText);
        assertNotEquals(originalText, encryptedText);

        String decryptedText = encryptionUtils.decrypt(encryptedText);
        assertEquals(originalText, decryptedText);
    }

    @Test
    void testDecryptWithInvalidData() {
        String invalidEncryptedText = "00AABB"; // not valid encrypted format
        assertThrows(Exception.class, () -> {
            encryptionUtils.decrypt(invalidEncryptedText);
        });
    }

    @Test
    void testEncryptNullValue() {
        assertThrows(NullPointerException.class, () -> {
            encryptionUtils.encrypt(null);
        });
    }
}

