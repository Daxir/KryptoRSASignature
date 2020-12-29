package org.example;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class RSA {
    BigInteger p,q,N,e,d,euler,pm1,qm1,k,km1,S;
    MessageDigest digest;
    static final int keyLen=256; //ta wartość daje długość d=512

    public RSA()
    {
        try {
            digest=MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {ex.printStackTrace();}
    }

    public static byte[] hexToBytes(String tekst)
    {
        if (tekst == null) { return null;}
        else if (tekst.length() < 2) { return null;}
        else { if (tekst.length()%2!=0)tekst+='0';
            int dl = tekst.length() / 2;
            byte[] wynik = new byte[dl];
            for (int i = 0; i < dl; i++)
            { try{
                wynik[i] = (byte) Integer.parseInt(tekst.substring(i * 2, i * 2 + 2), 16);
            }catch(NumberFormatException e){
                System.out.println("debil"); }
            }
            return wynik;
        }
    }

    public void generateKey()
    {
        p = BigInteger.probablePrime(keyLen,new Random());
        q = BigInteger.probablePrime(keyLen,new Random());
        N = p.multiply(q);
        pm1=p.subtract(BigInteger.ONE);
        qm1=q.subtract(BigInteger.ONE);
        euler=pm1.multiply(qm1);
        e = BigInteger.probablePrime(keyLen,new Random());
        while(true)
            if (e.gcd(euler).equals(BigInteger.ONE))break;
            else e=e.nextProbablePrime();
        d = e.modInverse(euler);
        //k do ślepego podpisu
        k = BigInteger.probablePrime(keyLen,new Random());
        while(true)
            if (k.gcd(euler).equals(BigInteger.ONE))break;
            else k=k.nextProbablePrime();
        km1=k.modInverse(N);
    }

    public BigInteger blindSignature(byte[] plainText)
    {
        digest.update(plainText);
        BigInteger sig=new BigInteger(1, digest.digest());
        sig = sig.multiply(k.modPow(e,N)).mod(N);
        sig=sig.modPow(d, N);
        S=sig;
        sig=sig.multiply(km1).mod(N);
        return sig;
    }

    public boolean blindVerify(byte[] plainText, BigInteger signature)
    {
        digest.update(plainText);
        BigInteger tmp=new BigInteger(1, digest.digest());
        tmp = tmp.multiply(k.modPow(e,N)).mod(N);
        tmp=tmp.modPow(d, N);
        tmp=tmp.multiply(km1).mod(N);
        return signature.compareTo(tmp) == 0;
    }
}
