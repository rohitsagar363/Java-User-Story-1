//Perform encryption and decryption using algorithms for provided password

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Scanner;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class All {
    //BASE64
    static class Base64ed {

        public static String getEncodedString(String password) {
            //return encrypted string
            return Base64.getEncoder().encodeToString(password.getBytes());
        }

        public static String getDecodeString(String encryptedString) {
            //return decrypted string
            return new String(Base64.getMimeDecoder().decode(encryptedString));
        }

    }
    // AES
    static class AES {

        private static final String SECRET_KEY = "abcdefghijklmno";
        private static final String SALT = "qwertyuiopkasd";
        public static String encrypt(String strToEncrypt)
        {
            try {
                // Create default byte array
                byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                IvParameterSpec ivspec = new IvParameterSpec(iv);

                // Create SecretKeyFactory object
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

                // Create KeySpec object and assign with
                // constructor
                KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
                // Return encrypted string
                return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
            }
            catch (Exception e) {
                System.out.println("Error while encrypting: "
                        + e.toString());
            }
            return null;
        }

        // This method use to decrypt to string
        public static String decrypt(String strToDecrypt)
        {
            try {
                // Default byte array
                byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                // Create IvParameterSpec object and assign with
                // constructor
                IvParameterSpec ivspec = new IvParameterSpec(iv);

                // Create SecretKeyFactory Object
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

                // Create KeySpec object and assign with
                // constructor
                KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
                // Return decrypted string
                return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
            }
            catch (Exception e) {
                System.out.println("Error while decrypting: " + e.toString());
            }
            return null;
        }
    }

    //SHA256
    static class SHA256 {
        public static byte[] getSHA(String input) throws NoSuchAlgorithmException {
            // Static getInstance method is called with hashing SHA
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // digest() method called
            // to calculate message digest of an input
            // and return array of byte
            return md.digest(input.getBytes(StandardCharsets.UTF_8));
        }

        public static String toHexString(byte[] hash) {
            // Convert byte array into signum representation
            BigInteger number = new BigInteger(1, hash);

            // Convert message digest into hex value
            StringBuilder hexString = new StringBuilder(number.toString(16));

            // Pad with leading zeros
            while (hexString.length() < 32) {
                hexString.insert(0, '0');
            }

            return hexString.toString();
        }
    }

}

//Main Class
public class Demo {

    private final static Logger LOGGER =
            Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);
        LOGGER.log(Level.INFO, "logMessage: Taking Input");
        System.out.println("Enter password OR Encrypted password: ");
        String password = sc.nextLine();

        LOGGER.log(Level.INFO, "logMessage: Choosing Algorithm");
        System.out.println("Choose Algorithm: 1 for Base64, 2 for AES, 3 for DES, 4 for SHA256");
        int Algo = sc.nextInt();

        LOGGER.log(Level.INFO, "logMessage: Choosing Encryption or Decryption");
        System.out.println("E or D");
        char option = sc.next().charAt(0);

        if (Algo == 1) {

            if(option == 'E') {

                String encryptedString = All.Base64ed.getEncodedString(password);

                System.out.println("encrypted password using Base64: " + encryptedString);
                LOGGER.log(Level.INFO, "logMessage: Encrypted");
            }

            if(option == 'D') {

                String decryptedString = All.Base64ed.getDecodeString(password);

                System.out.println("decrypted password using Base64: " + decryptedString);
                LOGGER.log(Level.INFO, "logMessage: Decrypted");
            }
        }

        if(Algo ==3){
            try{
                KeyGenerator kg = KeyGenerator.getInstance("DES");
                SecretKey myDESKey = kg.generateKey();
                Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, myDESKey);
                byte[] text = password.getBytes();
                if (option == 'E') {
                    byte[] textEnc = cipher.doFinal(text);
                    //System.out.println("Encrypted password using DES: " + new String(textEnc));
                    System.out.println("Encrypted password in bytes: "+ textEnc);
                    LOGGER.log(Level.INFO, "logMessage: Encrypted");

                }
                if(option == 'D') {
                    cipher.init(Cipher.DECRYPT_MODE, myDESKey);
                    byte[] textDec = cipher.doFinal(password.getBytes());
                    System.out.println("Decrypted password using DES: " + new String(textDec));
                    LOGGER.log(Level.INFO, "logMessage: Decrypted");
                }
            }
            catch(Exception e){

            }
        }

        if(Algo ==2){

            if(option == 'E') {
                // encryption method
                String encryptedString
                        = All.AES.encrypt(password);
                System.out.println("encrypted password using AES: " + encryptedString);
                LOGGER.log(Level.INFO, "logMessage: Encrypted");

            }
            // decryption method
            if(option == 'D') {
                String decryptedString
                        = All.AES.decrypt(password);
                System.out.println("DECRYPTED password using AES: " + decryptedString);
                LOGGER.log(Level.INFO, "logMessage: Decrypted");


            }

        }

        if (Algo == 4){
            try
            {
                // decryption method
                System.out.println("Encrypted password using SHA-256: " + All.SHA256.toHexString(All.SHA256.getSHA(password)));
                LOGGER.log(Level.INFO, "logMessage: Encrypted");
            }

            catch (NoSuchAlgorithmException e) {
                System.out.println("Exception thrown for incorrect algorithm: " + e);
            }
        }


    }

}

