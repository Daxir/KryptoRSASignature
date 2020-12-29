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


    public BigInteger podpisujSlepo(byte[] tekst)
    {
        digest.update(tekst);
        BigInteger podpis=new BigInteger(1, digest.digest());
        podpis = podpis.multiply(k.modPow(e,N)).mod(N);
        podpis=podpis.modPow(d, N);S=podpis;
        podpis=podpis.multiply(km1).mod(N);
        return podpis;
    }

    public BigInteger podpisujSlepo(String tekst)
    {
        digest.update(tekst.getBytes());
        BigInteger podpis=new BigInteger(1, digest.digest());
        podpis = podpis.multiply(k.modPow(e,N)).mod(N);
        podpis=podpis.modPow(d, N);S=podpis;
        podpis=podpis.multiply(km1).mod(N);
        return podpis;
    }


    public boolean weryfikujBigIntSlepo(byte[] tekstJawny, BigInteger podpis)
    {
        digest.update(tekstJawny);
        BigInteger pom=new BigInteger(1, digest.digest());
        pom = pom.multiply(k.modPow(e,N)).mod(N);
        pom=pom.modPow(d, N);//S=podpis;
        pom=pom.multiply(km1).mod(N);
        return podpis.compareTo(pom) == 0;
    }


    //zakładamy, że podpis jest w postaci hexadecymalnych znaków
    public boolean weryfikujStringSlepo(String tekstJawny, String podpis)
    {
        digest.update(tekstJawny.getBytes());
        BigInteger pom=new BigInteger(1, digest.digest());
        pom = pom.multiply(k.modPow(e,N)).mod(N);
        pom=pom.modPow(d, N);//S=podpis;
        pom=pom.multiply(km1).mod(N);
        BigInteger bi=new BigInteger(1, hexToBytes(podpis));
        return bi.compareTo(pom) == 0;
    }
}
