/* Created by: SELS Team
*
* Description: Testing crypto strength to make sure we have unlimited strength Java policy files
*
* License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
*                   We use Bouncy Castle libraries. They are distributed under http://www.bouncycastle.org/licence.html
*/

import java.security.Security;
import java.security.Key;
import javax.crypto.Cipher;
import javax.security.auth.kerberos.KerberosKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;

public class testCryptoStrength{



    public static void main(String[] args) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
	try{
	    /*KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("RSA", "BC");
	    dsaKpg.initialize(3096);
	    KeyPair dsaKp = dsaKpg.generateKeyPair();*/
	    /*KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
	    elgKpg.initialize(elParams);
	    elgKp = elgKpg.generateKeyPair();*/

	    /*KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
	    kg.init(256);
	    KerberosKey sk = (KerberosKey) kg.generateKey();*/


	    byte [] randomNumber = new byte[32];
	    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
	    random.nextBytes(randomNumber);
	    SecretKeySpec sk = new SecretKeySpec(randomNumber, "AES");
	    Cipher c = Cipher.getInstance("AES", "BC");
	    c.init(c.ENCRYPT_MODE, (Key)sk);
	    byte[] enc = c.doFinal(new String("test").getBytes());

	    System.out.println("Unlimited Strength Policy Test Successful\n");
	}
	catch (SecurityException e){
	    System.out.println("Caught Exception: " + e.toString());
	}
    }
}
