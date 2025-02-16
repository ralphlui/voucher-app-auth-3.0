package voucher.management.app.auth.utility;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.model.*;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@ActiveProfiles("test")
public class AmazonSESTest {
	
    @Test
    void testSendEmail_Success() throws Exception {
        AmazonSimpleEmailService client = mock(AmazonSimpleEmailService.class);

        String from = "from@gmail.com";
        Collection<String> recipientsTo = List.of("to@gmail.com");
        String subject = "Test Subject";
        String body = "<html><body>Testing...</body></html>";

        boolean isSent = AmazonSES.sendEmail(client, from, recipientsTo, subject, body);

        assertTrue(isSent);

        ArgumentCaptor<SendEmailRequest> requestCaptor = ArgumentCaptor.forClass(SendEmailRequest.class);
        verify(client).sendEmail(requestCaptor.capture());

        SendEmailRequest sentRequest = requestCaptor.getValue();
        assertEquals(from, sentRequest.getSource());
        assertEquals(recipientsTo, sentRequest.getDestination().getToAddresses());
        assertEquals(subject, sentRequest.getMessage().getSubject().getData());
        assertEquals(body, sentRequest.getMessage().getBody().getHtml().getData());
    }

    @Test
    void testSendEmail_Failure() throws Exception {
        AmazonSimpleEmailService client = mock(AmazonSimpleEmailService.class);
        doThrow(new AmazonSimpleEmailServiceException("Test exception")).when(client).sendEmail(any());

        boolean isSent = AmazonSES.sendEmail(client, "from@example.com", new ArrayList<>(), "Test Subject", "Test Body");

        assertFalse(isSent);
    }
}