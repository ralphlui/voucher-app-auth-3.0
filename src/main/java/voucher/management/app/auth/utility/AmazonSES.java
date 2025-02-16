package voucher.management.app.auth.utility;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.model.Body;
import com.amazonaws.services.simpleemail.model.Content;
import com.amazonaws.services.simpleemail.model.Destination;
import com.amazonaws.services.simpleemail.model.Message;
import com.amazonaws.services.simpleemail.model.SendEmailRequest;

@Component
public class AmazonSES {

	private static final Logger logger = LoggerFactory.getLogger(AmazonSES.class);

	public static boolean sendEmail(AmazonSimpleEmailService client, String from, Collection<String> recipientsTo,
			String subject, String body) throws Exception {
		boolean isSent = false;

		logger.info("From: " + from);
		logger.info("To: " + recipientsTo.size() + " :: " + recipientsTo.toString());
		logger.info("body: " + body);
		logger.info("subject: " + subject);
		try {

			SendEmailRequest request = new SendEmailRequest()
					.withDestination(new Destination().withToAddresses(recipientsTo))
					.withMessage(new Message()
							.withBody(new Body().withHtml(new Content().withCharset("UTF-8").withData(body)))
							.withSubject(new Content().withCharset("UTF-8").withData(subject)))
					.withSource(from);

			client.sendEmail(request);
			isSent = true;
			logger.info("Email sent successfully.");
		} catch (Exception ex) {
			logger.error("sendEmail exception... {}", ex.toString());

			isSent = false;
		}
		return isSent;

	}
}