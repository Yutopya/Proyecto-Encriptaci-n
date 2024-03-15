package CommRed.EjerciciosChat;

import javax.crypto.*;
import java.security.*;
import java.util.Base64;

public class MetodosEcriptacionASimetrica {
    public static KeyPair generarClaves() throws NoSuchAlgorithmException {
        KeyPairGenerator generadorClaves = KeyPairGenerator.getInstance("RSA");
        generadorClaves.initialize(2048);

        return generadorClaves.generateKeyPair();
    }
    public static String stringEncriptado(String dato, PublicKey clavePublica) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cifrado = Cipher.getInstance("RSA");
        cifrado.init(Cipher.ENCRYPT_MODE,clavePublica);

        byte[] encriptado = cifrado.doFinal(dato.getBytes());

        return Base64.getEncoder().encodeToString(encriptado);
    }
    public static String desencriptar(String datoEncriptado, PrivateKey clavePrivada) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cifrado = Cipher.getInstance("RSA");
        cifrado.init(Cipher.DECRYPT_MODE,clavePrivada);

        byte[] desencriptado = cifrado.doFinal(Base64.getDecoder().decode(datoEncriptado));
        return new String(desencriptado);
    }
}
