package org.example;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class RSA {

    class RSAKeyException extends Exception
    {
        public RSAKeyException(String msg){super(msg);};
    }


    BigInteger p,q,N,e,d,euler,pm1,qm1,k,km1,S;
    MessageDigest digest;
    int keyLen=256; //ta wartość daje długość d=512
    int ilZnHex=keyLen/4;//ilość znaków hex wyświetlanych w polu klucza
    Random random=new Random();

    public RSA()
    {
        generateKey();
        try{
            digest=MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {ex.printStackTrace();}
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

    public BigInteger[] encrypt(byte[] message)
    {
        int ileZnakow = (N.bitLength()-1)/8;
        while (message.length % ileZnakow != 0)
        {
            message = Arrays.copyOf(message, message.length+1); // powiększa o 1 i uzupełnia zerem
            message[message.length-1] = '\000';
        }
        int chunks = message.length/ ileZnakow;
        BigInteger[] cipher = new BigInteger[chunks];
        for (int i = 0; i < chunks; i++)
        {
            byte[] pom = Auxx.podtablica(message, ileZnakow*i, ileZnakow*(i+1));
            cipher[i] = new BigInteger(1, pom);
            cipher[i] = cipher[i].modPow(e,N);
        }
        return cipher;
    }


    public BigInteger[] encrypt(String message)
    {
        int ileZnakow = (N.bitLength()-1)/8;
        while (message.length() % ileZnakow != 0)
            message += ' ';
        int chunks = message.length()/ ileZnakow;
        BigInteger[] cipher = new BigInteger[chunks];
        for (int i = 0; i < chunks; i++)
        {
            String s = message.substring(ileZnakow*i,ileZnakow*(i+1));
            cipher[i] = Auxx.stringToBigInt(s);
            cipher[i] = cipher[i].modPow(e,N);
        }
        return cipher;
    }


    public String encryptFromStringToString(String message)
    {
        String str = new String();
        BigInteger[] bi_table = encrypt(message);
        for(int i = 0; i < bi_table.length; i++)
            str += bi_table[i] + "\n";
        return str;
    }

    public String decrypt(BigInteger[] cipher)
    {
        String s = new String();
        for (int i = 0; i < cipher.length; i++)
        {
            s += Auxx.bigIntToString(cipher[i].modPow(d,N));
        }
        return s;
    }

    public BigInteger[] decryptToBigInt(BigInteger[] cipher)
    {
        BigInteger[] wynik = new BigInteger[cipher.length];
        for (int i = 0; i < cipher.length; i++)
            wynik[i] = cipher[i].modPow(d,N);
        return wynik;
    }

    public String decryptFromStringToString(String cipher)
    {
        String[] wiersze = cipher.split("\n");
        BigInteger[] bi_table = new BigInteger[wiersze.length];
        for(int i = 0; i < wiersze.length; i++)
            bi_table[i] = new BigInteger(wiersze[i]);
        return decrypt(bi_table);
    }

    public BigInteger podpisuj(byte[] tekst)
    {
        digest.update(tekst);
        BigInteger podpis=new BigInteger(1, digest.digest());
        podpis = podpis.modPow(d,N);
        return podpis;
    }

    public BigInteger podpisuj(String tekst)
    {
        digest.update(tekst.getBytes());
        BigInteger podpis=new BigInteger(1, digest.digest());
        podpis = podpis.modPow(d,N);
        return podpis;
    }


    public boolean weryfikujBigInt(byte[] tekstJawny, BigInteger podpis)
    {
        digest.update(tekstJawny);
        BigInteger hash = new BigInteger(1, digest.digest());
        podpis=podpis.modPow(e,N);
        return hash.compareTo(podpis) == 0;
    }


    //zakładamy, że podpis jest w postaci hexadecymalnych znaków
    public boolean weryfikujString(String tekstJawny, String podpis)
    {
        digest.update(tekstJawny.getBytes());
        BigInteger hash = new BigInteger(1, digest.digest());
        BigInteger bi=new BigInteger(1,Auxx.hexToBytes(podpis));
        bi=bi.modPow(e,N);
        return hash.compareTo(bi) == 0;
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
        BigInteger bi=new BigInteger(1,Auxx.hexToBytes(podpis));
        return bi.compareTo(pom) == 0;
    }
}
