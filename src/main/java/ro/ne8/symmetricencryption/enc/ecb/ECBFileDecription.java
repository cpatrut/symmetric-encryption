package ro.ne8.symmetricencryption.enc.ecb;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class ECBFileDecription {
    private static final String ENCRYPTION_MODE = "ECB";
    private static final String ENCRYPTION_PADDING = "PKCS5Padding";

    public void decrypt(final String fileInput, final String fileOutput, final String key, final String algorithm) throws IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        //setupFiles
        final FileInputStream fileInputStream = tryGetFileInputStream(fileInput);
        final FileOutputStream fileOutputStream = tryGetOuputFileSteam(fileOutput);

        //Setup descryption
        final String cipherSetup = algorithm + "/" + ENCRYPTION_MODE + "/" + ENCRYPTION_PADDING;
        final Cipher cipher = Cipher.getInstance(cipherSetup);
        final Key secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        cipher.init(Cipher.DECRYPT_MODE,secretKeySpec);

        //setup file ops
        final byte[] cipherTextBuffer = new byte[cipher.getBlockSize()];
        int noBytes;
        byte[] clearTextBuffer;

        //operate file
        while ((noBytes = fileInputStream.read(cipherTextBuffer)) != -1) {
            final int outputSize = cipher.getOutputSize(noBytes);
            clearTextBuffer = new byte[outputSize];
            final int noOutputByes = cipher.update(cipherTextBuffer, 0, noBytes, clearTextBuffer, 0);
            fileOutputStream.write(clearTextBuffer, 0, noOutputByes);
        }

        clearTextBuffer = cipher.doFinal();

        fileOutputStream.write(clearTextBuffer);
        fileInputStream.close();
        fileOutputStream.close();

    }

    private void tryToInitCipher(final Cipher cipher, final Key key) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } catch (final InvalidKeyException e) {
            e.printStackTrace();
        }

    }

    private Cipher tryToGetCipherInstance(final String cipherSetup) {
        try {
            return Cipher.getInstance(cipherSetup);
        } catch (final NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (final NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;

    }

    private FileInputStream tryGetFileInputStream(final String inputFile) {
        try {
            return new FileInputStream(inputFile);
        } catch (final FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    private FileOutputStream tryGetOuputFileSteam(final String outputFile) {
        try {
            return new FileOutputStream(outputFile);
        } catch (final FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }
}
