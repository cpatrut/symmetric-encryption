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

public class ECBFileEncryption {

    private static final String ENCRYPTION_MODE = "ECB";
    private static final String ENCRYPTION_PADDING = "PKCS5Padding";

    public void encrypt(final String inputFile, final String outputFile, final String key, final String algorithm) throws IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        //setup files
        final FileInputStream fileInputStream = tryGetFileInputStream(inputFile);
        final FileOutputStream fileOutputStream = tryGetOuputFileSteam(outputFile);


        System.out.println("what a message");
        //setup cipher
        final String cipherSetup = algorithm + "/" + ENCRYPTION_MODE + "/" + ENCRYPTION_PADDING;
        final Cipher cipher = Cipher.getInstance(cipherSetup);
        final Key keySpec = new SecretKeySpec(key.getBytes(), algorithm);
        cipher.init(Cipher.ENCRYPT_MODE,keySpec);

        // setup reading
        final byte[] clearTextBuffer = new byte[cipher.getBlockSize()];
        int noBytes;
        byte[] cipherBuffer;

        //start processing file
        while ((noBytes = fileInputStream.read(clearTextBuffer)) != -1) {
            //initializing cipher buffer with empty values
            cipherBuffer = new byte[cipher.getOutputSize(noBytes)];

            //putting inside of the cipher values the result of the current block encryption and extracting the number of bytes resulted from the op
            final int noOutputBytes = cipher.update(clearTextBuffer, 0, noBytes, cipherBuffer, 0);
            //writing inside of the file the  cipher buffer
            fileOutputStream.write(cipherBuffer, 0, noOutputBytes);
        }

        //final Block
        cipherBuffer = cipher.doFinal();
        fileOutputStream.write(cipherBuffer);

        fileInputStream.close();
        fileOutputStream.close();
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
