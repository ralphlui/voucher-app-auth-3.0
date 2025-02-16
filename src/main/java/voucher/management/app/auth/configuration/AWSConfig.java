package voucher.management.app.auth.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailServiceClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;

@Configuration
public class AWSConfig {

	@Value("${aws.region}")
	private String awsRegion;

	@Value("${aws.accesskey}")
	private String awsAccessKey;

	@Value("${aws.secretkey}")
	private String awsSecretKey;

	@Value("${aws.ses.from}")
	private String emailFrom;

	@Value("${aws.sqs.url}")
	private String sqsURL;

	@Bean
	public String getEmailFrom() {
		return emailFrom;
	}

	@Bean
	public String getSQSUrl() {
		return sqsURL;
	}
	
	@Bean
	public AWSCredentials awsCredentials() {
		return new BasicAWSCredentials(awsAccessKey, awsSecretKey);
	}
	

	@Bean
	public AmazonSimpleEmailService sesClient() {
		AWSCredentials awsCredentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
		AmazonSimpleEmailService sesClient = AmazonSimpleEmailServiceClientBuilder.standard()
				.withCredentials(new AWSStaticCredentialsProvider(awsCredentials)).withRegion(awsRegion).build();
		return sesClient;
	}
	
	@Bean
    public AmazonSQS amazonSQSClient(AWSCredentials awsCredentials) {
        return AmazonSQSClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
                .withRegion(awsRegion)
                .build();
    }

}
