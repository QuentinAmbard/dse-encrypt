import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

public abstract class SystemKey
{
    private static final Random random = new SecureRandom();

    private static final ConcurrentHashMap<String, SystemKey> keys = new ConcurrentHashMap<>();
    private static final byte[] NONE = new byte[]{};

    protected abstract SecretKey getKey() throws KeyAccessException;
    protected abstract String getCipherName();
    protected abstract int getKeyStrength();
    protected abstract int getIvLength();
    public abstract String getName();

    private static byte[] createIv(int size)
    {
        assert size >= 0;

        if (size == 0)
        {
            return NONE;
        }
        else
        {
            byte[] b = new byte[size];
            random.nextBytes(b);
            return b;
        }
    }

    protected static int getIvLength(String cipherName) throws IOException
    {
        if (cipherName.matches(".*/(CBC|CFB|OFB|PCBC)/.*"))
        {
            try
            {
                return Cipher.getInstance(cipherName).getBlockSize();
            }
            catch (NoSuchAlgorithmException | NoSuchPaddingException e)
            {
                throw new IOException(e);
            }
        }
        else
        {
            return 0;
        }
    }

    public byte[] encrypt(byte[] input, boolean opscenter) throws IOException
    {
        try
        {
            byte[] iv = createIv(getIvLength());
            Cipher cipher = Cipher.getInstance(getCipherName());
            if (iv.length > 0)
            {
                cipher.init(Cipher.ENCRYPT_MODE, getKey(), new IvParameterSpec(iv));
            }
            else
            {
                cipher.init(Cipher.ENCRYPT_MODE, getKey());
            }
            byte[] output = cipher.doFinal(input);
            if(opscenter){
                return ArrayUtils.addAll(output, iv);
            } else {
                return ArrayUtils.addAll(iv, output);
            }
        }
        catch (NoSuchPaddingException | InvalidKeyException | NoSuchAlgorithmException | KeyAccessException |
                IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e)
        {
            throw new IOException("Couldn't encrypt input", e);
        }
    }

    public String encrypt(String input, boolean opscenter) throws IOException
    {
        return Base64.encodeBase64String(encrypt(input.getBytes(), opscenter));
    }

    protected static String getKeyType(String cipherName)
    {
        return cipherName.replaceAll("/.*", "");
    }
}
