import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class PasswordManager {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SALT = "12345678"; // In a real scenario, use a secure random salt
    private static final String CHARSET = "UTF-8";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Welcome to CC Password Manager");

        while (true) {
            System.out.println("What would you like to do?");
            System.out.println("1. Create a new password vault");
            System.out.println("2. Sign in to a password vault");
            System.out.println("3. Add a password to a vault");
            System.out.println("4. Fetch a password from a vault");
            System.out.println("Quit (enter q or quit)");
            String choice = scanner.nextLine();

            if (choice.equals("1")) {
                createVault(scanner);
            } else if (choice.equals("2")) {
                signInVault(scanner);
            } else if (choice.equals("3")) {
                addPasswordRecord(scanner);
            } else if (choice.equals("4")) {
                fetchPasswordRecord(scanner);
            } else if (choice.equals("q") || choice.equals("quit")) {
                break;
            } else {
                System.out.println("Invalid choice.");
            }
        }
        scanner.close();
    }

    private static void createVault(Scanner scanner) {
        try {
            System.out.print("Please provide a name for the vault: ");
            String vaultName = scanner.nextLine();
            System.out.print("Please enter a master password: ");
            String masterPassword = new String(System.console().readPassword());
            System.out.print("Please confirm the master password: ");
            String confirmPassword = new String(System.console().readPassword());

            if (!masterPassword.equals(confirmPassword)) {
                System.out.println("Passwords do not match. Please try again.");
                return;
            }

            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            SecretKeySpec key = getKeyFromPassword(masterPassword, salt);

            Map<String, String> emptyVault = new HashMap<>();
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] encryptedData = encryptData(emptyVault.toString().getBytes(CHARSET), key, ivSpec);

            try (FileOutputStream fos = new FileOutputStream(vaultName + ".vault");
                 ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(salt);
                oos.writeObject(iv);
                oos.writeObject(encryptedData);
            }

            System.out.println("New vault created and saved as: " + vaultName + ".vault");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKeySpec getKeyFromPassword(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private static byte[] encryptData(byte[] data, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    private static byte[] decryptData(byte[] data, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    private static void signInVault(Scanner scanner) {
        try {
            System.out.print("Enter vault name: ");
            String vaultName = scanner.nextLine();
            System.out.print("Enter password for the vault: ");
            String masterPassword = new String(System.console().readPassword());

            try (FileInputStream fis = new FileInputStream(vaultName + ".vault");
                 ObjectInputStream ois = new ObjectInputStream(fis)) {
                byte[] salt = (byte[]) ois.readObject();
                byte[] iv = (byte[]) ois.readObject();
                byte[] encryptedData = (byte[]) ois.readObject();

                SecretKeySpec key = getKeyFromPassword(masterPassword, salt);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                byte[] decryptedData = decryptData(encryptedData, key, ivSpec);

                System.out.println("Thank you, you are now signed in.");
                // You may want to save the decrypted data in a global variable or a session for further use
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void addPasswordRecord(Scanner scanner) {
        try {
            System.out.print("Please provide the name of the vault: ");
            String vaultName = scanner.nextLine();
            System.out.print("Enter password for the vault: ");
            String masterPassword = new String(System.console().readPassword());

            try (FileInputStream fis = new FileInputStream(vaultName + ".vault");
                 ObjectInputStream ois = new ObjectInputStream(fis)) {
                byte[] salt = (byte[]) ois.readObject();
                byte[] iv = (byte[]) ois.readObject();
                byte[] encryptedData = (byte[]) ois.readObject();

                SecretKeySpec key = getKeyFromPassword(masterPassword, salt);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                byte[] decryptedData = decryptData(encryptedData, key, ivSpec);

                // Convert decrypted data to Map
                String decryptedString = new String(decryptedData, CHARSET);
                Map<String, String> vaultData = new HashMap<>();
                if (!decryptedString.equals("{}")) {
                    String[] entries = decryptedString.substring(1, decryptedString.length() - 1).split(", ");
                    for (String entry : entries) {
                        String[] kv = entry.split("=");
                        vaultData.put(kv[0], kv[1]);
                    }
                }

                System.out.print("Please provide a name for the record: ");
                String recordName = scanner.nextLine();
                System.out.print("Please enter the username: ");
                String username = scanner.nextLine();
                System.out.print("Please enter the password: ");
                String password = new String(System.console().readPassword());

                vaultData.put(recordName, username + ":" + password);

                byte[] newEncryptedData = encryptData(vaultData.toString().getBytes(CHARSET), key, ivSpec);

                try (FileOutputStream fos = new FileOutputStream(vaultName + ".vault");
                     ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                    oos.writeObject(salt);
                    oos.writeObject(iv);
                    oos.writeObject(newEncryptedData);
                }

                System.out.println("Password record added successfully.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void fetchPasswordRecord(Scanner scanner) {
        try {
            System.out.print("Please provide the name of the vault: ");
            String vaultName = scanner.nextLine();
            System.out.print("Enter password for the vault: ");
            String masterPassword = new String(System.console().readPassword());

            try (FileInputStream fis = new FileInputStream(vaultName + ".vault");
                 ObjectInputStream ois = new ObjectInputStream(fis)) {
                byte[] salt = (byte[]) ois.readObject();
                byte[] iv = (byte[]) ois.readObject();
                byte[] encryptedData = (byte[]) ois.readObject();

                SecretKeySpec key = getKeyFromPassword(masterPassword, salt);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                byte[] decryptedData = decryptData(encryptedData, key, ivSpec);

                // Convert decrypted data to Map
                String decryptedString = new String(decryptedData, CHARSET);
                Map<String, String> vaultData = new HashMap<>();
                if (!decryptedString.equals("{}")) {
                    String[] entries = decryptedString.substring(1, decryptedString.length() - 1).split(", ");
                    for (String entry : entries) {
                        String[] kv = entry.split("=");
                        vaultData.put(kv[0], kv[1]);
                    }
                }

                System.out.print("Please enter the record name: ");
                String recordName = scanner.nextLine();

                if (vaultData.containsKey(recordName)) {
                    String[] credentials = vaultData.get(recordName).split(":");
                    System.out.println("For " + recordName + ":");
                    System.out.println("The username: is " + credentials[0]);
                    System.out.println("The password is: " + credentials[1]);
                } else {
                    System.out.println("Record not found.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
