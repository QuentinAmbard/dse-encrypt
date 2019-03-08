import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

public abstract class SystemKey2 {
    private static final SecureRandom random = new SecureRandom();

    private static final ConcurrentHashMap<String, SystemKey2> keys = new ConcurrentHashMap<>();
    private static final byte[] NONE = new byte[]{};

    public static File createKey(String path, String cipherName, int keyStrength) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException {
        return createKey(null, path, cipherName, keyStrength);
    }

    public static File createKey(File directory, String path, String cipherName, int keyStrength) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        File keyFile = new File(directory, path);

        KeyGenerator keyGen = KeyGenerator.getInstance(getKeyType(cipherName));
        keyGen.init(keyStrength, random);
        SecretKey key = keyGen.generateKey();

        // validate the ciphername
        Cipher.getInstance(cipherName);

        if (keyFile.exists())
            throw new IOException("File already exists: " + keyFile);
        if (!keyFile.getParentFile().exists() && !keyFile.getParentFile().mkdirs())
            throw new IOException("Failed to create directory: " + keyFile.getParentFile());
        if (!keyFile.createNewFile())
            throw new IOException("Failed to create file: " + keyFile);
        if (!keyFile.setWritable(true, true))
            throw new IOException("File not writeable: " + keyFile);
        if (!keyFile.setReadable(true, true))
            throw new IOException("File not readable: " + keyFile);


        PrintStream ps = null;
        try
        {
            ps = new PrintStream(new FileOutputStream(keyFile));
            ps.println(cipherName + ":" + keyStrength + ":" + Base64.encodeBase64String(key.getEncoded()));
        }
        finally
        {
            IOUtils.closeQuietly(ps);
        }
        return keyFile;
    }

    protected abstract SecretKey getKey() throws KeyAccessException;

    protected abstract String getCipherName();

    protected abstract int getKeyStrength();

    protected abstract int getIvLength();

    public abstract String getName();

    private static byte[] createIv(int size) {
        assert size >= 0;

        if (size == 0) {
            return NONE;
        } else {
            byte[] b = new byte[size];
            random.nextBytes(b);
            return b;
        }
    }

    protected static int getIvLength(String cipherName) throws IOException {
        if (cipherName.matches(".*/(CBC|CFB|OFB|PCBC)/.*")) {
            try {
                return Cipher.getInstance(cipherName).getBlockSize();
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new IOException(e);
            }
        } else {
            return 0;
        }
    }

    public byte[] encrypt(byte[] input, boolean opscenter) throws IOException {
        try {
            byte[] iv = createIv(getIvLength());
            Cipher cipher = Cipher.getInstance(getCipherName());
            if (iv.length > 0) {
                cipher.init(Cipher.ENCRYPT_MODE, getKey(), new IvParameterSpec(iv));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, getKey());
            }
            byte[] output = cipher.doFinal(input);
            if (opscenter) {
                return ArrayUtils.addAll(output, iv);
            } else {
                return ArrayUtils.addAll(iv, output);
            }
        } catch (NoSuchPaddingException | InvalidKeyException | NoSuchAlgorithmException | KeyAccessException |
                IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new IOException("Couldn't encrypt input", e);
        }
    }


    public byte[] decrypt(byte[] input) throws IOException {
        if (input == null)
            throw new IOException("input is null");
        try {
            byte[] iv = getIvLength() > 0 ? Arrays.copyOfRange(input, 0, getIvLength()) : NONE;
            Cipher cipher = Cipher.getInstance(getCipherName());
            if (iv.length > 0) {
                cipher.init(Cipher.DECRYPT_MODE, getKey(), new IvParameterSpec(iv));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, getKey());
            }

            return cipher.doFinal(input, getIvLength(), input.length - getIvLength());
        } catch (NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException |
                NoSuchAlgorithmException | KeyAccessException | InvalidAlgorithmParameterException e) {
            throw new IOException("Couldn't decrypt input", e);
        }
    }

    public String decrypt(String input) throws IOException {
        if (input == null)
            throw new IOException("input is null");
        return new String(decrypt(Base64.decodeBase64(input.getBytes())));
    }


    public String encrypt(String input, boolean opscenter) throws IOException {
        return Base64.encodeBase64String(encrypt(input.getBytes(), opscenter));
    }

    protected static String getKeyType(String cipherName) {
        return cipherName.replaceAll("/.*", "");
    }
}
