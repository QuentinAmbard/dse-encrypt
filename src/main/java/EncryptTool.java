import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class EncryptTool {
    private SecretKeySpec secretKey;
    private Cipher cipher;
    private int ivLength = 0;
    private Random r = new Random();
    private final String valueBase;

    public EncryptTool(byte[] key, String cipher, String valueBase) {
        this.valueBase = valueBase;
        String algorithm = cipher.substring(0, cipher.indexOf("/"));
        String block = cipher.substring(algorithm.length() + 1, cipher.length());
        block = block.substring(0, block.indexOf("/"));
        if (block.equals("CBC")) {
            ivLength = 16;
        }
        System.out.println("KEY LENGHT=" + key.length);
        secretKey = new SecretKeySpec(key, algorithm);
        try {
            this.cipher = Cipher.getInstance(cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println("couldn't create encryption tool using algorithm " + cipher);
        }
    }

    public String encryptValue(String value) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        if (ivLength != 0) {
            byte[] iv = new byte[ivLength];
            r.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedValue = cipher.doFinal(value.getBytes());
            byte[] merged = Arrays.copyOf(iv, iv.length + encryptedValue.length);
            System.arraycopy(encryptedValue, 0, merged, iv.length, encryptedValue.length);
            return encodeToBase(merged, valueBase);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return encodeToBase(cipher.doFinal(value.getBytes()), valueBase);
        }
    }

    public String decryptValue(String value) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        if (ivLength != 0) {
            byte[] merged = decodeBase(value, valueBase);
            byte[] iv = Arrays.copyOfRange(merged, 0, ivLength);
            byte[] cryptedValue = Arrays.copyOfRange(merged, ivLength, merged.length);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            return new String(cipher.doFinal(cryptedValue), StandardCharsets.UTF_8);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(decodeBase(value, valueBase)), StandardCharsets.UTF_8);
        }
    }

    public static byte[] decodeKey(String keyStr, String keyBase) {
        byte[] key = decodeBase(keyStr, keyBase);
        if (key.length < 16) {
            throw new IllegalStateException("Invalid key. Requires lengh >= 16b, current key has " + key.length);
        }
        return key;
    }

    private static String encodeToBase(byte[] bytes, String base) {
        if (base.equals(EncryptTool.BASE_16)) {
            return Hex.encodeHexString(bytes);
        } else {
            return Base64.encodeBase64String(bytes);
        }
    }

    private static byte[] decodeBase(String value, String base) {
        if (base.equals(EncryptTool.BASE_16)) {
            try {
                return Hex.decodeHex(value);
            } catch (DecoderException e) {
                throw new IllegalArgumentException("can't decode hexa value. Make sure your keyBase is 16", e);
            }
        } else {
            return Base64.decodeBase64(value);
        }
    }

    private static byte[] readKeyContent(String filePath, String keybase) {
        try (Stream<String> stream = Files.lines(Paths.get(filePath), StandardCharsets.UTF_8)) {
            List<String> lines = stream.collect(Collectors.toList());
            if (lines.size() != 1) {
                throw new IllegalStateException("key file has " + lines.size() + " lines. Should be only 1");
            }
            return decodeKey(lines.get(0), keybase);
        } catch (IOException e) {
            System.out.println("can't read " + filePath);
            throw new IllegalStateException("can't read " + filePath, e);
        }
    }


    public static String generateKey(int length, String keyBase) {
        byte[] key = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return encodeToBase(key, keyBase);
    }

    public final static String DEFAULT_CIPHER = "AES/ECB/PKCS5Padding";
    public final static String CIPHER_ECB = "AES/CBC/PKCS5Padding";
    private final static String CIPHER_OPTION = "--cipher";
    private final static String DEFAULT_KEY_SIZE = "128";
    private final static String KEY_SIZE_OPTION = "--key_size";
    private final static String VALUE_BASE_OPTION = "--value_base";
    private final static String KEY_BASE_OPTION = "--key_base";
    private final static String BASE_64 = "64";
    private final static String BASE_16 = "16";
    private final static String DEFAULT_VALUE_BASE = BASE_64;
    private final static String DEFAULT_KEY_BASE = BASE_16;

    private final static String COMMAND_CREATE_KEY = "createkey";
    private final static String COMMAND_ENCRYPT = "encrypt";
    private final static String COMMAND_DECRYPT = "decrypt";

    public static void main(String[] args) {
        String choice = args.length > 0 ? args[0] : "help";
        switch (choice) {
            case COMMAND_CREATE_KEY:
                int keySize = Integer.valueOf(getOptionalParameter(args, KEY_SIZE_OPTION, DEFAULT_KEY_SIZE)) / 8;
                String keyBase = getOptionalParameter(args, KEY_BASE_OPTION, DEFAULT_KEY_BASE);
                System.out.println(generateKey(keySize, keyBase));
                break;
            case COMMAND_ENCRYPT:
                EncryptTool ske = initEncryption(args[1], args);
                String value = args[2];
                try {
                    System.out.println(ske.encryptValue(value));
                } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
                    System.err.println("Couldn't encrypt value: " + e.getMessage());
                    e.printStackTrace();
                }
                break;
            case COMMAND_DECRYPT:
                EncryptTool ske2 = initEncryption(args[1], args);
                String value2 = args[2];
                try {
                    System.out.println(ske2.decryptValue(value2));
                } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
                    System.err.println("Couldn't decrypt value: " + e.getMessage());
                    e.printStackTrace();
                }
                break;
            default:
                System.out.println("Encrypt or decrypt configuration using the given key. Default cipher is " + DEFAULT_CIPHER + " with default key lenght = " + DEFAULT_KEY_SIZE + ". Usage:");
                System.out.println("    " + COMMAND_ENCRYPT + " [key_path] [value_to_encrypt] " + CIPHER_OPTION + " [cipher] ");
                System.out.println("    " + COMMAND_DECRYPT + " [key_path] [value_to_decrypt] " + CIPHER_OPTION + " [cipher] ");
                System.out.println("    " + COMMAND_CREATE_KEY + " " + KEY_SIZE_OPTION + " [size] " + CIPHER_OPTION + " [cipher]");
                System.out.println("Using openssl command:");
                System.out.println("DECRYPT SECRET:");
                System.out.println("     openssl enc -d -a -aes-128-ecb -in ./encrypted_value.txt -K $(cat ./key128.txt)");
                System.out.println("     echo \"vRbHuqHvRPVnwXXCaH2zGQ==\" | openssl enc -d -a -aes-128-ecb -K $(cat /home/quentin/Downloads/key128.txt)");
                System.out.println("ENCRYPT SECRET:");
                System.out.println("     openssl enc -a -aes-128-ecb -in ./raw_value.txt -K $(cat ./key128.txt)");
                System.out.println("     echo \"toto\" | openssl enc -a -aes-128-ecb -K $(cat ./key128.txt)");
                break;
        }
    }

    private static EncryptTool initEncryption(String keyPath) {
        return initEncryption(keyPath, DEFAULT_CIPHER, DEFAULT_KEY_BASE, DEFAULT_VALUE_BASE);
    }

    private static EncryptTool initEncryption(String path, String[] args) {
        String cipher = getOptionalParameter(args, CIPHER_OPTION, DEFAULT_CIPHER);
        String keyBase = getOptionalParameter(args, KEY_BASE_OPTION, DEFAULT_KEY_BASE);
        String valueBase = getOptionalParameter(args, VALUE_BASE_OPTION, DEFAULT_VALUE_BASE);
        return initEncryption(path, cipher, keyBase, valueBase);
    }


    private static EncryptTool initEncryption(String keyPath, String cipher, String keyBase, String valueBase) {
        byte[] key = readKeyContent(keyPath, keyBase);
        return initEncryption(key, cipher, valueBase);
    }

    private static EncryptTool initEncryption(byte[] key, String cipher, String valueBase) {
        return new EncryptTool(key, cipher, valueBase);
    }

    private static String getOptionalParameter(String[] args, String key, String defaultValue) {
        String value = defaultValue;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals(key)) {
                value = args[i + 1];
                i++;
            }
        }
        return value;
    }

}
