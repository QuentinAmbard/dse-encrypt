import java.io.IOException;

public class Encrypt {
    public static void main(String[] args) throws IOException {
        String keyPath = args[0];
        String value = args[1];

        LocalSystemKey systemKey =  LocalSystemKey.getKey(keyPath);
        String encrypted = systemKey.encrypt(value, systemKey.isOpscenter());
        System.out.println(encrypted);
    }
}
