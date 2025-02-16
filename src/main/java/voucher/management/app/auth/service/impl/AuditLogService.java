package voucher.management.app.auth.service.impl;

import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.amazonaws.services.sqs.model.SendMessageResult;
import com.fasterxml.jackson.databind.ObjectMapper;

import voucher.management.app.auth.configuration.AWSConfig;
import voucher.management.app.auth.dto.AuditLogRequest;
import voucher.management.app.auth.service.IAuditService;

@Service
public class AuditLogService implements IAuditService {
	
	private static final Logger logger = LoggerFactory.getLogger(AuditLogService.class);
	
	
	@Autowired
	private AWSConfig awsConfig;
	
	@Autowired
	private AmazonSQS amazonSQS;


	@Async
    @Override
	public void sendAuditLogToSqs(String statusCode, String userId, String username, String activityType, String activityDescription,
			String requestActionEndpoint, String responseStatus, String requestType, String remarks) {
		try {
		    String auditLogRequest = createLogEntryRequest(statusCode, userId, username, activityType, activityDescription,
		        requestActionEndpoint, responseStatus, requestType, remarks);
		    
		    String queueUrl = awsConfig.getSQSUrl();

		    SendMessageRequest sendMessageRequest = new SendMessageRequest()
		            .withQueueUrl(queueUrl)
		            .withMessageBody(auditLogRequest);

		    SendMessageResult sendMessageResult = amazonSQS.sendMessage(sendMessageRequest);
		    logger.info("Message response in SQS: " + sendMessageResult.getMessageId());
		    
		} catch (Exception e) {
		    // Generic exception handling for any other unforeseen errors
		    logger.error("Exception: Unexpected error occurred while sending audit logs to SQS " + e.toString());
		}
	}
	
	
	private String createLogEntryRequest(String statusCode, String userId, String username, String activityType,
			String activityDescription, String requestActionEndpoint, String responseStatus, String requestType,
			String remarks) {

		ObjectMapper objectMapper = new ObjectMapper();
		AuditLogRequest logRequest = new AuditLogRequest();
		logRequest.setStatusCode(statusCode);
		logRequest.setUserId(userId);
		logRequest.setUsername(username);
		logRequest.setActivityType(activityType);
		logRequest.setActivityDescription(activityDescription);
		logRequest.setRequestActionEndpoint(requestActionEndpoint);
		logRequest.setResponseStatus(responseStatus);
		logRequest.setRequestType(requestType);
		logRequest.setRemarks(remarks);
		try {

			String auditLogString = objectMapper.writeValueAsString(logRequest);
			logger.info("Serialized JSON: " + auditLogString);

			byte[] messageBytes = auditLogString.getBytes(StandardCharsets.UTF_8);
			int messageSize = messageBytes.length;
			int maxMessageSize = 256 * 1024;  // Max Size 256 KB in bytes

			if (messageSize > maxMessageSize) {
				logger.warn("Message size exceeds the 256 KB limit: {} bytes, truncating remarks.", messageSize);

				String truncatedRemarks = truncateMessage(logRequest.getRemarks(), maxMessageSize, auditLogString);
				logRequest.setRemarks(truncatedRemarks.concat("..."));

				auditLogString = objectMapper.writeValueAsString(logRequest);
				messageBytes = auditLogString.getBytes(StandardCharsets.UTF_8);

				logger.info("Truncated message size: {} bytes", messageBytes.length);
			}

			return auditLogString;

		} catch (Exception e) {
			logger.error("Exception: Unexpected error occurred while creatin audit log object", e.toString());
			e.printStackTrace();
		}
		return "";

	}
	
	public String truncateMessage(String remarks, int maxMessageSize, String currentMessage) {
	    try {
	        // Start truncating the remarks field only if it exceeds the limit
	        byte[] currentMessageBytes = currentMessage.getBytes(StandardCharsets.UTF_8);
	        int currentSize = currentMessageBytes.length;
	        
	        byte[] remarkBytes = remarks.getBytes(StandardCharsets.UTF_8);
	        
	        int remarkSize =remarkBytes.length;

	        int diffMsgSize = currentSize - maxMessageSize;

	        if (diffMsgSize >= remarkSize) {
	            return ""; // If no space left for remarks, return an empty string
	        }	      
	        
	        int  allowedBytesForRemarks = remarkSize - (diffMsgSize+5);
	        if (remarkBytes.length <= allowedBytesForRemarks) {
	            return remarks; 
	        }

	        String truncatedRemarks = new String(remarkBytes, 0, allowedBytesForRemarks, StandardCharsets.UTF_8);
	        return truncatedRemarks;
	    } catch (Exception e) {
	        logger.error("Error while truncating message remarks: {}", e.getMessage());
	        return remarks; 
	    }
	}
	
}
