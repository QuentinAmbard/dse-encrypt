import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;


public class EncryptToolTest {

    public static void main(String[] args) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        testEncryptionDecryption();
        testEncryptionDecryptionIV();
    }

    public static void testEncryptionDecryption() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        String keyStr = EncryptTool.generateKey(16, "16");
        assert(Base64.decodeBase64(keyStr).length == 16);
        byte[] key = EncryptTool.decodeKey(keyStr, "16");
        assert(key.length == 16);
        EncryptTool et = new EncryptTool(key, EncryptTool.CIPHER_ECB, "16");
        String cryptedValue = et.encryptValue("aaa");
        assert (!cryptedValue.equals("aaa"));
        assert (et.decryptValue(cryptedValue).equals("aaa"));

        String value = "http://azesdf/?10.0.0.1";
        cryptedValue = et.encryptValue(value);
        assert (!cryptedValue.equals(value));
        assert (et.decryptValue(cryptedValue).equals(value));
    }

    public static void testEncryptionDecryptionIV() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        String keyStr = EncryptTool.generateKey(16, "16");
        assert(Base64.decodeBase64(keyStr).length == 16);
        byte[] key = EncryptTool.decodeKey(keyStr, "16");
        assert(key.length == 16);
        EncryptTool et = new EncryptTool(key, EncryptTool.DEFAULT_CIPHER, "16");
        String cryptedValue = et.encryptValue("aaa");
        assert (!cryptedValue.equals("aaa"));
        assert (et.decryptValue(cryptedValue).equals("aaa"));

        String value = "http://azesdf/?10.0.0.1";
        cryptedValue = et.encryptValue(value);
        assert (!cryptedValue.equals(value));
        assert (et.decryptValue(cryptedValue).equals(value));
    }

}
