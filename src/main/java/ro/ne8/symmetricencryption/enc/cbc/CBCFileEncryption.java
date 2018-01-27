package ro.ne8.symmetricencryption.enc.cbc;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class CBCFileEncryption {
    private static final String ENCRYPTION_MODE = "CBC";
    private static final String ENCRYPTION_PADDING = "PKCS5Padding";


    public void encrypt(final String inputFileName, final String outputFileName, final String secretKey, final String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        //setupFiles
        final FileInputStream fileInputStream = tryGetFileInputStream(inputFileName);
        final FileOutputStream fileOutputStream = tryGetOuputFileSteam(outputFileName);

        final String cipherSetup = algorithm + "/" + ENCRYPTION_MODE + "/" + ENCRYPTION_PADDING;

        final Cipher cipher = Cipher.getInstance(cipherSetup);
        final Key secretKeySpec = new SecretKeySpec(secretKey.getBytes(), algorithm);

        final byte[] IV = new byte[secretKey.getBytes().length];

        for (int i = 0; i < IV.length; i++) {
            IV[i] = (byte) 0xFF;
        }
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);


        fileOutputStream.write(IV);

        final byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes;
        while ((noBytes = fileInputStream.read(buffer)) != -1) {
            final byte[] cipherBlockBuffer = new byte[cipher.getOutputSize(noBytes)];
            final int noOutputBytes = cipher.update(buffer, 0, noBytes, cipherBlockBuffer, 0);
            fileOutputStream.write(cipherBlockBuffer, 0, noOutputBytes);

        }

        final byte[] lastCipherBlock = new byte[cipher.getBlockSize()];
        final int lastBlockSize = cipher.doFinal(lastCipherBlock, 0);
        fileOutputStream.write(lastCipherBlock, 0, lastBlockSize);

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
