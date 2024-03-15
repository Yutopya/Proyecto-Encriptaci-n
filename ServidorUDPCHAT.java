package CommRed.EjerciciosChat;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;


public class ServidorUDPCHAT {
    private static final ArrayList<String> usuarios = new ArrayList<>();
    private static final ArrayList<Integer> puertos = new ArrayList<>();
    private static final ArrayList<PublicKey> claves = new ArrayList<>();
    private static final InetAddress direccion;
    private static final DatagramSocket servidorUDP;

    static {
        try {
            direccion = InetAddress.getByName("127.0.0.1");
            servidorUDP = new DatagramSocket(1234);
        } catch (UnknownHostException | SocketException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        String usuario;
        String mensaje;
        boolean registrado;
        int comp;
        byte[] bytes = new byte[1024];
        DatagramPacket paqueteInicial = new DatagramPacket(bytes, bytes.length);
        DatagramPacket paqueteClave = new DatagramPacket(bytes, bytes.length);
        DatagramPacket paqueteMensaje;
        //Recibir Paquete
        while (true) {
            registrado=true;
            comp=0;
            servidorUDP.receive(paqueteInicial);
            //Comprueba si puertos esta vacio, si esta vacio, directamente va a registrar el siguiente usuario
            if (!puertos.isEmpty()) {
                //Recorre la lista de puertos para ver si ya esta registrado
                for (Integer puerto : puertos) {
                    if (puerto.equals(paqueteInicial.getPort())) {
                        comp++;
                    }
                }
                if(comp==0){
                    registrado=false;
                }
            }else{
                registrado=false;
            }

            if (registrado) {
                //Si ya esta registrado, lo indentifica como mensaje
                paqueteMensaje = paqueteInicial;
                System.out.print("Mensaje recibido: ");
                String paqueteRecibido = new String(
                        paqueteMensaje.getData(), 0, paqueteMensaje.getLength());
                System.out.println(paqueteRecibido);
                String[] mensajes = paqueteRecibido.split(",");
                usuario = mensajes[0];
                mensaje = mensajes[1];
                //Comprueba si el mensaje es exit para borrar al usuario o simplemente enviar el mensaje de broadcast
                if (!mensaje.equalsIgnoreCase("exit")) {
                    broadcastMensaje(usuario, mensaje);
                } else {
                    broadcastMensaje(usuario, "Se ha desconectado");
                    eliminarUsuario(usuario);
                }
            } else {
                //Registra al usuario 
                String paqueteRecibido = new String(
                        paqueteInicial.getData(), 0, paqueteInicial.getLength());
                String[] mensajes = paqueteRecibido.split(",");
                usuario = mensajes[0];
                usuarios.add(usuario);
                puertos.add(paqueteInicial.getPort());
                servidorUDP.receive(paqueteClave);
                claves.add(generarPK(paqueteClave.getData()));
                System.out.println("Usuario Registrado");
            }
        }
    }

    private static PublicKey generarPK(byte[] clave) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(clave));
    }

    private static void eliminarUsuario(String usuario) {
        boolean encontrado = true;
        int i = 0;
        do {
            if (usuarios.get(i).equals(usuario)) {
                usuarios.remove(i);
                puertos.remove(i);
                claves.remove(i);
                encontrado = false;
            }
            i++;
        } while (i < usuarios.size() && encontrado);
    }

    private static void broadcastMensaje(String usuario, String mensaje) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        for (int i = 0; i < usuarios.size(); i++) {
            String encriptado = MetodosEcriptacionASimetrica.stringEncriptado(usuario + ": " + mensaje.toUpperCase(),claves.get(i));
            byte[] mensajeBytes = encriptado.getBytes();
            DatagramPacket paquete2 = new DatagramPacket(
                    mensajeBytes, mensajeBytes.length, direccion, puertos.get(i));
            servidorUDP.send(paquete2);
            System.out.println("Mensaje enviado");
        }
    }
}
