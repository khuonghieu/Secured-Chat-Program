import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
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

public class Server {
    public static void main(String args[]) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, 
            BadPaddingException {
        ServerSocket serverSocket = new ServerSocket(6666); //create server
        Socket socket = serverSocket.accept(); //establish connection

        //Send key
        SecretKey macKey = sendMacKey(socket);
        SecretKey desKey = sendDesKey(socket);
        //Send message and HMAC to receiving end
        while(true){
            sendMessage(socket, macKey, desKey);
            receiveMessage(socket, macKey, desKey);
        }

        
    }

    private static SecretKey sendMacKey(Socket socket) throws NoSuchAlgorithmException, IOException {
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        SecretKey key = KeyGenerator.getInstance("HmacSHA1").generateKey();

        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Sent HMAC Key = " + encodedKey);

        dataOutputStream.writeUTF(encodedKey);

        return key;
    }
    private static SecretKey sendDesKey(Socket socket) throws NoSuchAlgorithmException, IOException {
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        SecretKey key = KeyGenerator.getInstance("DES").generateKey();

        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Sent DES Key = " + encodedKey);

        dataOutputStream.writeUTF(encodedKey);

        return key;
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
