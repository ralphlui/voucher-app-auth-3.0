package voucher.management.app.auth.service.impl;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import org.springframework.stereotype.Service;

@Service
public class PasswordValidatorService {

	private static final Pattern NON_ALPHANUMERIC_PATTERN = Pattern.compile("[^a-zA-Z0-9]");
	private static final int MIN_LENGTH = 8;
	private static final int MAX_LENGTH = 30;

	private static final Pattern UPPER_CASE_PATTERN = Pattern.compile("[A-Z]");
	private static final Pattern LOWER_CASE_PATTERN = Pattern.compile("[a-z]");
	private static final Pattern DIGIT_PATTERN = Pattern.compile("\\d");

	public static boolean containsNonAlphanumericCharacters(String password) {
		return NON_ALPHANUMERIC_PATTERN.matcher(password).find();
	}

	public static String validatePassword(String password) {
		if (password == null || password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
			return "Password must be within 8-30 characters long.";
		}

		if (!UPPER_CASE_PATTERN.matcher(password).find()) {
			return "Password must contain at least one uppercase letter.";
		}

		if (!LOWER_CASE_PATTERN.matcher(password).find()) {
			return "Password must contain at least one lowercase letter.";
		}

		if (!DIGIT_PATTERN.matcher(password).find()) {
			return "Password must contain at least one numeric digit.";
		}

		if (!containsNonAlphanumericCharacters(password)) {
			return "Password must contain at least one special character.";
		}

		if (containsDictionaryWord(password)) {
			return "Password must not contain common dictionary words.";
		}

		return "valid";
	}

	
	private static Set<String> loadDictionary() {
		
	    Set<String> dictionaryWords = new HashSet<>();
	    try (InputStream inputStream = PasswordValidatorService.class.getClassLoader().getResourceAsStream("dictionary.txt")) {
	        if (inputStream == null) {
	            throw new FileNotFoundException("dictionary.txt not found in classpath.");
	        }
	        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
	            String line;
	            while ((line = br.readLine()) != null) {
	                dictionaryWords.add(line.trim().toLowerCase());
	            }
	        }
	    } catch (IOException e) {
	        e.printStackTrace();
	    }
	    return dictionaryWords;
	}


	public static boolean containsDictionaryWord(String password) {
		Set<String> dictionaryWords = loadDictionary();
		List<String> words = extractWordsFromPassword(password);

		if (dictionaryWords != null) {
			return containsAnyDictionaryWord(words, dictionaryWords);
		}

		return false;
	}

	private static List<String> extractWordsFromPassword(String password) {
		List<String> words = new ArrayList<>();
		String[] parts = password.split("[^A-Za-z]");

		for (String str : parts) {
			if (str.length() > 3) {
				addSuffixesToWords(str, words);
			}
		}
		return words;
	}

	private static void addSuffixesToWords(String str, List<String> words) {
		IntStream.range(0, str.length()).forEach(i -> {
			String suffix = str.substring(i);
			IntStream.rangeClosed(0, suffix.length()).forEach(j -> {
				String suffixCut = suffix.substring(0, j);
				if (suffixCut.length() > 3) {
					words.add(suffixCut);
				}
			});
		});
	}

	private static boolean containsAnyDictionaryWord(List<String> words, Set<String> dictionaryWords) {
		for (String word : words) {
			for (String dictionaryWord : dictionaryWords) {
				if (word.equalsIgnoreCase(dictionaryWord)) {
					return true;
				}
			}
		}
		return false;
	}

}
