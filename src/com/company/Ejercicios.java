package com.company;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Scanner;

public class Ejercicios {

    Scanner sc = new Scanner(System.in);

    public void E1(){
        System.out.println();
        KeyPair keyPair = Xifrar.randomGenerate(1024);
        System.out.println("Introduce un texto");
        String texto = sc.nextLine();
        byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);
        byte[] encriptado = Xifrar.encryptData(keyPair.getPublic(), bytes);
        byte[] desencriptado = Xifrar.decryptData(keyPair.getPrivate(), encriptado);

        String msg = new String(desencriptado, 0, desencriptado.length);
        System.out.println("Texto original: "+ texto);
        System.out.println("Texto en bytes: " + bytes);
        System.out.println("Byte encriptado: " + encriptado);
        System.out.println("Byte desencriptado: " + desencriptado);
        System.out.println("KeyPair Public: " + keyPair.getPublic());
        System.out.println("KeyPair Public Algoritmo: " + keyPair.getPublic().getAlgorithm());
        System.out.println("KeyPair Public Encoded: " + keyPair.getPublic().getEncoded());
        System.out.println("KeyPair Public Format: " + keyPair.getPublic().getFormat());
        System.out.println("KeyPair Private: " + keyPair.getPrivate());
        System.out.println("KeyPair Private Algoritmo: " + keyPair.getPrivate().getAlgorithm());
        System.out.println("KeyPair Private Encoded: " + keyPair.getPrivate().getEncoded());
        System.out.println("KeyPair Private Format: " + keyPair.getPrivate().getFormat());
        System.out.println("Texto final: " + msg);

    }
}
