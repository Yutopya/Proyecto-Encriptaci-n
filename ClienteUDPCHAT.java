package CommRed.EjerciciosChat;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.*;
import java.security.*;
import java.util.Random;
import java.util.Scanner;

public class ClienteUDPCHAT {
    private static final DatagramSocket clienteUDP;
    private static final KeyPair parejaClaves;
    static {
        try {
            clienteUDP = new DatagramSocket(new Random().nextInt(1000, 9999));
            parejaClaves= MetodosEcriptacionASimetrica.generarClaves();
        } catch (SocketException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    private static final PublicKey clavePublica = parejaClaves.getPublic();
    private static final PrivateKey clavePrivada = parejaClaves.getPrivate();
    private static String nombre;

    public static void main(String[] args) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Scanner lector = new Scanner(System.in);
        String mensaje;
        System.out.println("Escribe tu nombre");
        System.out.println(clavePublica.getFormat());
        nombre = lector.nextLine();
        envioNombre();
        envioClave();
        hiloReceptor.start();
        do {
            System.out.println("Escribe tu mensaje. Exit para salir");
            mensaje = lector.nextLine();
            if (!mensaje.equalsIgnoreCase("exit")) {
                envioMensaje(mensaje);
            } else {
                System.out.println("Gracias por usar nuestro programa");
                envioMensaje(mensaje);
                System.exit(1);

            }
        } while (!mensaje.equalsIgnoreCase("exit"));
    }

    private static void envioNombre() {
        envioMensaje("nombre");
    }

    private static void envioClave(){
        byte[] mensajeBytes = clavePublica.getEncoded();
        cartero(mensajeBytes);
    }

    private static void envioMensaje(String mensaje) {
        //Enviar paquete
        String mensajeEnviado = nombre + "," + mensaje;
        byte[] mensajeBytes = mensajeEnviado.getBytes();
        cartero(mensajeBytes);

    }
    private static void cartero(byte[] mensajeBytes){
        DatagramPacket paquete;
        try {
            paquete = new DatagramPacket(
                    mensajeBytes, mensajeBytes.length, InetAddress.getByName("localhost"), 1234);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
        try {
            clienteUDP.send(paquete);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static Thread hiloReceptor = new Thread(() -> {
        while (true) {
            byte[] bytes = new byte[1024];
            DatagramPacket paquete2 = new DatagramPacket(bytes, bytes.length);
            try {
                clienteUDP.receive(paquete2);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            String paqueteRecibido = new String(
                    paquete2.getData(), 0, paquete2.getLength());
            try {
                System.out.println(MetodosEcriptacionASimetrica.desencriptar(paqueteRecibido,clavePrivada));
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException |
                     BadPaddingException | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }
    });
}
