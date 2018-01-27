package ro.ne8.symmetricencryption;

import ro.ne8.symmetricencryption.enc.cbc.CBCFileDecription;
import ro.ne8.symmetricencryption.enc.cbc.CBCFileEncryption;
import ro.ne8.symmetricencryption.enc.ecb.ECBFileDecription;
import ro.ne8.symmetricencryption.enc.ecb.ECBFileEncryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class App {

    public static final String CLEAR_TEXT = "clear-text.txt";
    public static final String ECB_CIPHER_TEXT = "ecb-cipher.enc";
    public static final String ECB_DECRYPTION_RESULT = "ecb-decryption-result.txt";
    public static final String PASSWORD = "passwordpassword";
    public static final String ALGORITHM_AES = "AES";
    public static final String CBC_CIPHER_TEXT = "cbc-cipher.enc";
    public static final String CBC_DECRYPTION_RESULT = "cbc-clear.txt";

    public static void main(final String[] args) throws IllegalBlockSizeException, ShortBufferException, BadPaddingException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        final ECBFileEncryption ecbFileEncryption = new ECBFileEncryption();
        ecbFileEncryption.encrypt(CLEAR_TEXT, ECB_CIPHER_TEXT, PASSWORD, ALGORITHM_AES);

        final ECBFileDecription ecbFileDecription = new ECBFileDecription();
        ecbFileDecription.decrypt(ECB_CIPHER_TEXT, ECB_DECRYPTION_RESULT, PASSWORD, ALGORITHM_AES);

        final CBCFileEncryption cbcFileEncryption = new CBCFileEncryption();
        cbcFileEncryption.encrypt(CLEAR_TEXT, CBC_CIPHER_TEXT, PASSWORD, ALGORITHM_AES);

        final CBCFileDecription cbcFileDecription = new CBCFileDecription();
        cbcFileDecription.decrypt(CBC_CIPHER_TEXT, CBC_DECRYPTION_RESULT, PASSWORD, ALGORITHM_AES);
    }
}
