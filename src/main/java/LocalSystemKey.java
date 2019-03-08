import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;

public class LocalSystemKey extends SystemKey
{
    private static final SecureRandom random = new SecureRandom();

    private final File keyFile;

    private final String cipherName;
    private final int keyStrength;
    private final int ivLength;
    private final SecretKey key;
    private final boolean opscenter;

    public LocalSystemKey(File keyFile) throws IOException
    {
        assert keyFile != null;
        this.keyFile = keyFile;

        // load system key
        BufferedReader is = null;
        try
        {
            is = new BufferedReader(new InputStreamReader(new FileInputStream(keyFile)));
            String line;
            line = is.readLine();
            if (line == null)
                throw new IOException("Key file: " + keyFile + " is empty");
            {
                final String keyStr;
                String[] fields = line.split(":");
                //Opscenter key
                if (fields.length == 2) {
                    opscenter = true;
                    //256
                    if(fields[1].length() == 44){
                        keyStrength = 256 ;
                    } else {
                        keyStrength = 128 ;
                    }
                    cipherName = "AES/"+fields[0]+"/PKCS5Padding";
                    keyStr = fields[1];
                } else if (fields.length == 3) {
                    opscenter = false;
                    keyStrength = Integer.parseInt(fields[1]);
                    cipherName = fields[0];
                    keyStr = fields[2];
                } else {
                    throw new IOException("Malformed key file");
                }
                byte[] keyBytes = Base64.decodeBase64(keyStr.getBytes());
                key = new SecretKeySpec(keyBytes, getKeyType(cipherName));
                ivLength = getIvLength(cipherName);

            }
        }
        finally
        {
            IOUtils.closeQuietly(is);
        }
    }

    @Override
    protected SecretKey getKey()
    {
        return key;
    }

    @Override
    protected String getCipherName()
    {
        return cipherName;
    }

    @Override
    protected int getKeyStrength()
    {
        return keyStrength;
    }

    @Override
    protected int getIvLength()
    {
        return ivLength;
    }


    public static LocalSystemKey getKey(String path) throws IOException
    {
        File systemKeyFile = new File(path);
        if (!systemKeyFile.exists())
            throw new IOException(String.format("Master key file '%s' does not exist", systemKeyFile.getAbsolutePath()));

        return new LocalSystemKey(systemKeyFile);
    }

    public String getName()
    {
        return keyFile.getName();
    }

    public String getAbsolutePath()
    {
        return keyFile.getAbsolutePath();
    }

    public boolean isOpscenter(){
        return opscenter;
    }
}