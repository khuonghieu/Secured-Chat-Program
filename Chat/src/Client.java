import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Client {
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Socket socket = new Socket("localhost", 6666);

        SecretKey macKey = receiveMacKey(socket);
        SecretKey desKey = receiveDesKey(socket);
        while(true){
            receiveMessage(socket, macKey, desKey);
            sendMessage(socket, macKey, desKey);
        }
    }

    
    
    private static SecretKey receiveMacKey(Socket socket) throws IOException, ClassNotFoundException {
        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

        String encodedKey = dataInputStream.readUTF();
        System.out.println("Received Mac Key = " + encodedKey);
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);

        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA1");
    }
    private static SecretKey receiveDesKey(Socket socket) throws IOException, ClassNotFoundException {
        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

        String encodedKey = dataInputStream.readUTF();
        System.out.println("Received DES Key = " + encodedKey);
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);

        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
    }

    
    
    
    private static void receiveMessage(Socket socket, SecretKey key, SecretKey desKey) throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        try {
            //Receive the message first
            //getting received object from server
            InputStream i_p_stream = socket.getInputStream();
            BufferedReader received = new BufferedReader(new InputStreamReader(i_p_stream));
            
            Cipher dcipher = Cipher.getInstance("DES");
            dcipher.init(Cipher.DECRYPT_MODE,desKey);
            byte[] message = new sun.misc.BASE64Decoder().decodeBuffer(received.readLine());
            System.out.println("Received message encrypted: " + new String(message));
            byte[] decryptedText = dcipher.doFinal(message);
            System.out.println("Received message after deciphered: "+ new String(decryptedText, "UTF8"));
            //Receive the HMAC second
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            byte[] hmac = (byte[]) objectInputStream.readObject();
            if (checkHMAC(key, hmac, message)){
                System.out.println("HMAC Confirmed.");
                System.out.println("Here is the message: " + message);
            }
            else{
                System.out.println("HMAC Confirmed");
            }
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }
    
    
    
    private static void sendMessage(Socket socket, SecretKey key, SecretKey desKey) throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        try {
            OutputStream o_p_stream = socket.getOutputStream();
            PrintWriter p_write = new PrintWriter(o_p_stream, true);
            //Message being sent
            System.out.println("Type your message: ");
            String message = new Scanner(System.in).nextLine();

            // Hash-based Message Authentication Code is created by hashing the message using
            // the SHA-1 hashing algorithm and key
            Mac mac = Mac.getInstance("HmacSHA1"); //SHA-1 Algorithm
            mac.init(key); //key
            
            Cipher ecipher = Cipher.getInstance("DES");
            ecipher.init(Cipher.ENCRYPT_MODE,desKey);
            
            //This HMAC must be verified by the receiver to ensure authentication and integrity
            byte[] hmac = mac.doFinal(message.getBytes());

            //Send the message first
            byte[] encryptedText = ecipher.doFinal(message.getBytes());
            p_write.println(new sun.misc.BASE64Encoder().encode(encryptedText));

            System.out.println("Sent message: " + message);

            //Send the HMAC second
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(hmac);

        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            e.printStackTrace();
        }
    }

    
    
    
    private static boolean checkHMAC(SecretKey key, byte[] receivedHMAC, byte[] receivedMessage) throws NoSuchAlgorithmException, InvalidKeyException {
        //Generate HMAC from receiving end
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key);
        byte[] generatedHMAC = mac.doFinal(receivedMessage);
        return Arrays.equals(generatedHMAC, receivedHMAC);
    }
}
