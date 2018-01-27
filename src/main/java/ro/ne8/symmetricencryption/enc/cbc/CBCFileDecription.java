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

public class CBCFileDecription {
    private static final String ENCRYPTION_MODE = "CBC";
    private static final String ENCRYPTION_PADDING = "PKCS5Padding";


    public void decrypt(final String inputFileName, final String outputFileName, final String secretKey, final String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        //setupFiles
        final FileInputStream fileInputStream = tryGetFileInputStream(inputFileName);
        final FileOutputStream fileOutputStream = tryGetOuputFileSteam(outputFileName);

        final String cipherSetup = algorithm + "/" + ENCRYPTION_MODE + "/" + ENCRYPTION_PADDING;

        final Cipher cipher = Cipher.getInstance(cipherSetup);
        final Key secretKeySpec = new SecretKeySpec(secretKey.getBytes(), algorithm);

        final byte[] IV = new byte[secretKey.getBytes().length];
        fileInputStream.read(IV);
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        final byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes;
        while ((noBytes = fileInputStream.read(buffer)) != -1) {
            final byte[] cipherBlock = new byte[cipher.getOutputSize(noBytes)];
            final int exitBytes = cipher.update(buffer, 0, noBytes, cipherBlock, 0);
            fileOutputStream.write(cipherBlock, 0, exitBytes);
        }
        final byte[] lastCipherBlock = new byte[cipher.getBlockSize()];
        final int lastBlockSize = cipher.doFinal(lastCipherBlock, 0);
        fileOutputStream.write(lastCipherBlock, 0, lastBlockSize);

        fileOutputStream.close();
        fileInputStream.close();
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
