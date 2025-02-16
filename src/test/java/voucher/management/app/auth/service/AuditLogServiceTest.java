

package voucher.management.app.auth.service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.amazonaws.services.sqs.model.SendMessageResult;
import org.junit.jupiter.api.BeforeEach;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;

import jakarta.transaction.Transactional;
import voucher.management.app.auth.configuration.AWSConfig;
import voucher.management.app.auth.service.impl.AuditLogService;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class AuditLogServiceTest {
	
	   @Mock
	    private AmazonSQS sqs;

	    @Mock
	    private AWSConfig awsConfig;

	    @InjectMocks
	    private AuditLogService auditLogService;
	    

	    @BeforeEach
	    void setUp() {
	        MockitoAnnotations.openMocks(this);
	    }

	    @Test
	    void testSendAuditLogToSqs_success() {
	       
	        String queueUrl = "https://sqs.aws-region.amazonaws.com/123456789012/MyQueue";
	        String auditLogRequest = "Sample Audit Log";
	        
	        SendMessageResult sendMessageResult = new SendMessageResult();
	        sendMessageResult.setMessageId("12345");

	        when(awsConfig.getSQSUrl()).thenReturn(queueUrl);
	        when(sqs.sendMessage(any(SendMessageRequest.class))).thenReturn(sendMessageResult);

		    SendMessageRequest sendMessageRequest = new SendMessageRequest()
		            .withQueueUrl(queueUrl)
		            .withMessageBody(auditLogRequest);
		    
		    SendMessageResult sendMessageReponse = sqs.sendMessage(sendMessageRequest);

	        auditLogService.sendAuditLogToSqs("200", "user1", "john.doe", "LOGIN", "User logged in",
	                "/login", "200 OK", "POST", "No remarks");
	        
	        assertThat(sendMessageReponse.getMessageId()).isNotNull();
	    }

	}
