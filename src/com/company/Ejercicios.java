package com.company;

import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Scanner;

public class Ejercicios {

    Scanner sc = new Scanner(System.in);

    public void E1_1(){
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
    public static void E1_2_1(){
        KeyStore keystore = null;
        try{
            keystore = Xifrar.loadKeyStore("src/com/company/keystore_chema.ks", "123456");
            System.out.println("Tipo KeyStore: "+ keystore.getType());
            System.out.println("Tamaño KeyStore: "+ keystore.size());
            Enumeration<String> alies = keystore.aliases();
            while (alies.hasMoreElements()){
                System.out.println("Alias: " + alies.nextElement() + "");
            }
            Certificate certificado = keystore.getCertificate(keystore.aliases().nextElement());
            System.out.println("Certificado de lamevaclaum9: " + certificado);
            System.out.println("Algoritmo de lamevaclaum9: " + certificado.getPublicKey().getAlgorithm());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static  void E1_2_2(){
        SecretKey secretKey = Xifrar.SecretKey(192);
        try {
            KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection("123456".toCharArray());
            KeyStore keyStore = Xifrar.loadKeyStore("src/com/company/keystore_chema.ks","123456");
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
            keyStore.setEntry("mykey2",secretKeyEntry,protectionParameter);
            FileOutputStream fos = new FileOutputStream("src/com/company/keystore_chema.ks");
            keyStore.store(fos,"123456".toCharArray());
            fos.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static void E1_3(){
        try{
            PublicKey publicKey = Xifrar.getPublicKey("src/com/company/archivo");
            System.out.println(publicKey);
        } catch (Exception e){
            throw new RuntimeException();
        }
    }

    public static void E1_4(){
        try {
            KeyStore keyStore = Xifrar.loadKeyStore("src/com/company/keystore_chema.ks","123456");
            PublicKey publicKey = Xifrar.getPublicKey(keyStore, "lamevaclaum9", "123456");
            System.out.println(publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void E1_5Y6(){
        KeyPair keyPair = Xifrar.randomGenerate(1024);
        String texto = "Xiao ratita";
        byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);
        byte[] firma = Xifrar.signData(bytes, keyPair.getPrivate());
        System.out.println(firma);

        System.out.println("1.6");
        System.out.println(Xifrar.validateSignature(bytes,firma,keyPair.getPublic()));
    }

    public static void E2_1(){

    }

    public void E2_2(){
        System.out.println("2.2");
        System.out.println("Introduce un texto:");
        String texto = sc.nextLine();
        byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);
        KeyPair kp = Xifrar.randomGenerate(1024);

        byte[][] encriptedData = Xifrar.encryptWrappedData(bytes, kp.getPublic());

        byte[] decriptedData;
        try {
            decriptedData = Xifrar.decryptWrappedData(encriptedData, kp.getPrivate());
            String textoFinal = new String(decriptedData, 0, decriptedData.length);

            System.out.println("Texto original: " + texto);
            System.out.println("Datos encriptados: " + encriptedData);
            System.out.println("Datos desencriptados: " + decriptedData);
            System.out.println("Texto al final: " + textoFinal);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
