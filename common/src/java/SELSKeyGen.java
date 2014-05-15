/* Created by: SELS Team
*
* Description: El Gamal key generation
*
* License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
*                   We use Bouncy Castle libraries. They are distributed under http://www.bouncycastle.org/licence.html
*/

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileReader;
import java.io.BufferedReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;

/**
 * A simple utility class that generates a public/secret keyring containing a DSA signing
 * key and an El Gamal key for encryption.

 * <p>
 * usage: DSAElGamalKeyRingGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are placed 
 * in the files pub.[asc|bpg] and secret.[asc|bpg].
 * <p>
 * <b>Note</b>: this example encrypts the secret key using AES_256, many PGP products still
 * do not support this, if you are having problems importing keys try changing the algorithm
 * id to PGPEncryptedData.CAST5. CAST5 is more widelysupported.
 */
public class SELSKeyGen
{
	public static int orderQ;
	public static BigInteger g;
	public static BigInteger p;
	public static BigInteger q;
	public static int paramFlag=0;//set to 1=> new param pubkey format 0=> old param PGQ format
    
    static ElGamalPrivateKey secKeyLM;
    static ElGamalPrivateKey secKeyLS;
    static ElGamalPrivateKey secKeyUA;
    static ElGamalPrivateKey secKeyUB;

	static String SELS_LIST_PATH = "";
    
    private static PGPPublicKey readPublicKey(
            InputStream    in)
            throws IOException, PGPException
        {
            in = PGPUtil.getDecoderStream(in);
            
            PGPPublicKeyRingCollection        pgpPub = new PGPPublicKeyRingCollection(in);

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //
            PGPPublicKey    key = null;
            
            //
            // iterate through the key rings.
            //
            Iterator rIt = pgpPub.getKeyRings();
            
            while (key == null && rIt.hasNext())
            {
                PGPPublicKeyRing    kRing = (PGPPublicKeyRing)rIt.next();    
                Iterator                        kIt = kRing.getPublicKeys();
                //boolean                        encryptionKeyFound = false;
                
                while (key == null && kIt.hasNext())
                {
                    PGPPublicKey    k = (PGPPublicKey)kIt.next();
                    
                    if (k.isEncryptionKey())
                    {
                        key = k;
                    }
                }
            }
            
            if (key == null)
            {
                throw new IllegalArgumentException("Can't find encryption key in key ring.");
            }
            
            return key;
        }
        
        /**
         * Load a secret key ring collection from keyIn and find the secret key corresponding to
         * keyID if it exists.
         * 
         * @param keyIn input stream representing a key ring collection.
         * @param keyID keyID we want.
         * @param pass passphrase to decrypt secret key with.
         * @return
         * @throws IOException
         * @throws PGPException
         * @throws NoSuchProviderException
         */
        private static PGPPrivateKey findSecretKey(
            InputStream keyIn,
            long        keyID,
            char[]      pass)
            throws IOException, PGPException, NoSuchProviderException
        {    
            PGPSecretKeyRingCollection    pgpSec = new PGPSecretKeyRingCollection(
                                                                PGPUtil.getDecoderStream(keyIn));
                                                                                            
            PGPSecretKey    pgpSecKey = pgpSec.getSecretKey(keyID);
            
            if (pgpSecKey == null)
            {
                return null;
            }
            
            return pgpSecKey.extractPrivateKey(pass, "BC");
        }

    // This method returns a positive natural random number in BigInt format


    public static BigInteger getRandomBigInt(int length)throws Exception{
	byte [] randomNumber = new byte[length];
	SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
	random.nextBytes(randomNumber);
	BigInteger check = new BigInteger(randomNumber);
	while (check.compareTo(BigInteger.ONE) != 1) {
	    random.nextBytes(randomNumber);
	    check = new BigInteger(randomNumber);
	}
	return(check);
    }

        
    public static BigInteger genRandom() throws Exception
    {
    	FileOutputStream out = new FileOutputStream( SELS_LIST_PATH + "/random" );
    	BigInteger r = getRandomBigInt(orderQ);
    	out.write(r.toString().getBytes());
    	out.close();

		return r;
    }
    private static void GenParams(int keysiz) throws Exception{
	ElGamalGroupParams elParams = OakleyGroups.getElGamalGroup(keysiz); 
	// Choose 1024 or 2048	
										
	g = elParams.getG();
	p = elParams.getP();
	q= elParams.getQ();
	
	String str = "g: " + g.toString() + 
		"\np: " + p.toString() +
		"\nq: " + q.toString() + "\n";

	//wite these values to files

	//it is inefficient to write them to files and read them from file when we 
	//have them available through a static final class in this case. but will have to do
	//it to keep code changes to a minimum - rbobba
	
	FileOutputStream out = new FileOutputStream(SELS_LIST_PATH+"/params");
	out.write(str.getBytes());
	out.close();
    }


    public static void initPGQ() throws Exception
    {
	String paramFile = SELS_LIST_PATH + "/params.gpg";
	File file = new File(paramFile);
	if(file.exists())
	    {
		PGPPublicKey pgpPubKey = readPublicKey(new FileInputStream(paramFile));
		JCEElGamalPublicKey pubKey = (JCEElGamalPublicKey)pgpPubKey.getKey("BC");
		ElGamalParameterSpec spec = pubKey.getParameters();
		p = spec.getP();
		g = spec.getG();
		orderQ = p.bitLength()/8;
		paramFlag = 1;

		System.out.println("P: = " + p.toString());
		System.out.println("G: = " + g.toString());
		
	    } // end if
	else
	    {
		paramFile = SELS_LIST_PATH + "/params";
		BufferedReader in = new BufferedReader(new FileReader(paramFile));
	
		while (true)
		    {
			String line = in.readLine();
			if (line == null)
			    break;
			String wlist[] = line.split("\\s");

			if( wlist[0].equals("g:") )
			    g = new BigInteger(wlist[1]);
			else if( wlist[0].equals("p:"))
			    p = new BigInteger(wlist[1]);
			else if( wlist[0].equals("q:"))
			    q = new BigInteger(wlist[1]);
		    }// end while
		orderQ = q.bitLength()/8;
		paramFlag=0;
		
	    }// end else
	   

    }

    private static void exportKeyPair(
            OutputStream    secretOut,
            OutputStream    publicOut,
            KeyPair         dsaKp,
            KeyPair         elgKp,
            String          identity,
            char[]          passPhrase,
            boolean         armor,
	    int             exptimesec)
            throws IOException, InvalidKeyException, NoSuchProviderException, 
				SignatureException, PGPException
        {
            if ((armor) && (secretOut != null))
            {
					secretOut = new ArmoredOutputStream(secretOut);
            }

            
    	    //Create subpacket vector for expiration time

    	    PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
            int secondsToExpire = exptimesec;
    	    subpacketGenerator.setKeyExpirationTime(false, secondsToExpire);
            subpacketGenerator.setExportable(true, true);
    	    PGPSignatureSubpacketVector subpacketVector = subpacketGenerator.generate();
	    
	    PGPKeyPair dsaKeyPair = new PGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date(), "BC");
            PGPKeyPair elgKeyPair = 
				new PGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date(), "BC");
            
            PGPKeyRingGenerator keyRingGen = 
				new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                identity, PGPEncryptedData.AES_256, passPhrase, 
				subpacketVector, null, new SecureRandom(), "BC");
            
            keyRingGen.addSubKey(elgKeyPair);            

			if (secretOut != null)
			{
				keyRingGen.generateSecretKeyRing().encode(secretOut);
				secretOut.close();
			}
            
            if (armor)
            {
                publicOut = new ArmoredOutputStream(publicOut);
            }
            
            keyRingGen.generatePublicKeyRing().encode(publicOut);            
            publicOut.close();
        }
    
    private static void LSKeyGen(String LSUserId, String LSPass, int expsec)
		throws Exception
	{
        KeyPairGenerator    dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");    
        KeyPair             dsaKp;      
        KeyPairGenerator    elgKpg;           
        ElGamalParameterSpec     elParams = new ElGamalParameterSpec(p, g);
        KeyPair elgKp;
 
		//	LS
		FileOutputStream out1 = new FileOutputStream(
			SELS_LIST_PATH + "/LS_secret.asc");
		FileOutputStream out2 = new FileOutputStream(
			SELS_LIST_PATH + "/LS_pub.asc");
		 
		dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
		dsaKpg.initialize(1024);
		dsaKp = dsaKpg.generateKeyPair();

		elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
		elgKpg.initialize(elParams);
		elgKp = elgKpg.generateKeyPair();
		secKeyLS = (ElGamalPrivateKey)elgKp.getPrivate();
		exportKeyPair(out1, out2, dsaKp, elgKp, LSUserId, 
			LSPass.toCharArray(), true, expsec);
	}

	private static void LMKeyGen(String LMUserId, String LMPass, int expsec)
		throws Exception
	{
        KeyPairGenerator    dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");    
        KeyPair             dsaKp;      
        KeyPairGenerator    elgKpg;           
        ElGamalParameterSpec     elParams = new ElGamalParameterSpec(p, g);
        KeyPair elgKp;
        
		//	LM
		FileOutputStream    out1 = new FileOutputStream(
			SELS_LIST_PATH + "/LM_secret.asc");
		FileOutputStream    out2 = new FileOutputStream(
			SELS_LIST_PATH + "/LM_pub.asc");
		
		dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
		dsaKpg.initialize(1024);
		dsaKp = dsaKpg.generateKeyPair();
		
		elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
		elgKpg.initialize(elParams);
		elgKp = elgKpg.generateKeyPair();
		secKeyLM = (ElGamalPrivateKey)elgKp.getPrivate();
		exportKeyPair(out1, out2, dsaKp, elgKp, LMUserId, LMPass.
			toCharArray(), true, expsec);
	}

	private static void LKKeyGen(String userId, String LKPass, int expsec)
		throws Exception
	{
        KeyPairGenerator    dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");    
        KeyPair             dsaKp;      
        KeyPairGenerator    elgKpg;           
        ElGamalParameterSpec     elParams = new ElGamalParameterSpec(p, g);
        KeyPair elgKp;
        
		dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
		dsaKpg.initialize(1024);
		dsaKp = dsaKpg.generateKeyPair();
		
		elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
		elgKpg.initialize(elParams);

		// generate a random BigInteger
		// BigInteger r = genRandom();

		ElGamalPublicKey pubKeyLM;
		ElGamalPublicKey pubKeyLS;
		//	LM
		PGPPublicKey pgpPubKey = readPublicKey(
			new FileInputStream(SELS_LIST_PATH+"/LM_pub.asc"));
		
		pubKeyLM = (ElGamalPublicKey)pgpPubKey.getKey("BC");        
		BigInteger PK_LM = pubKeyLM.getY();
  
		//	LS
		pgpPubKey = readPublicKey(
			new FileInputStream(SELS_LIST_PATH+"/LS_pub.asc"));
		
		pubKeyLS = (ElGamalPublicKey)pgpPubKey.getKey("BC");        
		BigInteger PK_LS = pubKeyLS.getY();

		// List Key
		FileOutputStream out1 = new FileOutputStream(
			SELS_LIST_PATH+"/rev_secret.asc");
		FileOutputStream out2 = new FileOutputStream(
			SELS_LIST_PATH+"/LK_pub.asc");
		
		dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
		dsaKpg.initialize(1024);
		dsaKp = dsaKpg.generateKeyPair();
		
		BigInteger y=PK_LS.multiply(PK_LM).mod(p);

		System.out.println( y );

		ElGamalPrivateKeySpec privSpec = new ElGamalPrivateKeySpec( new BigInteger("0"), elParams); 
		ElGamalPublicKeySpec pubSpec =  new ElGamalPublicKeySpec(y, elParams);
		ElGamalPublicPGKey pubKey= new ElGamalPublicPGKey(pubSpec);
		ElGamalPrivatePGKey secKey= new ElGamalPrivatePGKey(privSpec);
		
		elgKp = new KeyPair(pubKey, secKey);
		exportKeyPair(out1, out2, dsaKp, elgKp, userId, LKPass.toCharArray(), true, expsec);

	}

	private static void CKeyGen(String userid, String randomStr, String LSPass, int expsec)
		throws Exception
	{
	    KeyPairGenerator    dsaKpg = KeyPairGenerator.getInstance("DSA", "BC"); 
	    KeyPair             dsaKp;      
	    //KeyPairGenerator    elgKpg;           
	    ElGamalParameterSpec     elParams = new ElGamalParameterSpec(p, g);
	    KeyPair elgKp;
	    
	    System.out.println( userid);
	    System.out.println( randomStr);
	    System.out.println( LSPass);
	    // read a random BigInteger
	    BigInteger r = new BigInteger(randomStr);
		
	    //	LS
	    PGPPublicKey pgpPubKey = readPublicKey(
						   new FileInputStream( SELS_LIST_PATH + "/LS_pub.asc"));
	    PGPPrivateKey pgpSecKey = findSecretKey(
						    new FileInputStream(SELS_LIST_PATH + "/LS_secret.asc"),
						    pgpPubKey.getKeyID(), LSPass.toCharArray());
		
	    secKeyLS = (ElGamalPrivateKey)pgpSecKey.getKey();        
	    BigInteger K_LS = secKeyLS.getX();
  
		
	    //	User A's correspoding
	    FileOutputStream out1 = new FileOutputStream(
							 SELS_LIST_PATH + "/" + userid + "_secret.asc");
	    FileOutputStream out2 = new FileOutputStream(
							 SELS_LIST_PATH + "/" + userid + "_pub.asc");
		
	    dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
	    dsaKpg.initialize(1024);
	    dsaKp = dsaKpg.generateKeyPair();
	    BigInteger x;

	    if(paramFlag==1)
		     x = K_LS.subtract(r).mod(p);
	    else
		     x = K_LS.subtract(r).mod(q);
		BigInteger y=g.modPow(x,p);
		
		ElGamalPrivateKeySpec privSpec =  new ElGamalPrivateKeySpec(x, elParams); 
		ElGamalPublicKeySpec pubSpec =  new ElGamalPublicKeySpec(y, elParams);
		
		ElGamalPublicPGKey pubKey= new ElGamalPublicPGKey(pubSpec);
		ElGamalPrivatePGKey secKey= new ElGamalPrivatePGKey(privSpec);
		
		elgKp = new KeyPair(pubKey, secKey);
		exportKeyPair(out1, out2, dsaKp, elgKp, userid, 
			LSPass.toCharArray(), true, expsec);
   
	}

	private static void userKeyGen(String subuserid, String servuserid,  String subuserIdHash,
		String servuserIdHash, String LMPass, String userPass, int expsec)
		throws Exception
	{
        
        // this takes a while as the key generator has to generate 
		// some DSA params
        // before it generates the key.
        KeyPairGenerator  dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
        KeyPair             dsaKp;      
        //KeyPairGenerator    elgKpg;           
        ElGamalParameterSpec     elParams = new ElGamalParameterSpec(p, g);
         
        // this is quicker because we are using pregenerated parameters.
        KeyPair                    elgKp;// = elgKpg.generateKeyPair();
        

		System.out.println( subuserid );
		System.out.println( servuserid);
		// generate a random BigInteger
		BigInteger r = genRandom();

		//	LM
		PGPPublicKey pgpPubKey = readPublicKey(
			new FileInputStream(SELS_LIST_PATH+"/LM_pub.asc"));
		PGPPrivateKey pgpSecKey = findSecretKey(
			new FileInputStream(SELS_LIST_PATH+"/LM_secret.asc"), 
				pgpPubKey.getKeyID(), LMPass.toCharArray());		

		secKeyLM = (ElGamalPrivateKey)pgpSecKey.getKey();        
		BigInteger K_LM = secKeyLM.getX();
  
		//	User A's sub key
		FileOutputStream out1 = new FileOutputStream(
			 SELS_LIST_PATH+"/" + subuserIdHash + "_subsecret.asc");
		FileOutputStream out2 = new FileOutputStream(
			 SELS_LIST_PATH+"/" + subuserIdHash + "_subpub.asc");

		//    User A's serv key
		FileOutputStream out3 = new FileOutputStream(
                         SELS_LIST_PATH+"/" + servuserIdHash + "_servsecret.asc");
                FileOutputStream out4 = new FileOutputStream(
                         SELS_LIST_PATH+"/" + servuserIdHash + "_servpub.asc");
	
		dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
		dsaKpg.initialize(1024);
		dsaKp = dsaKpg.generateKeyPair();
		BigInteger x;
		if(paramFlag==1)
			 x = K_LM.add(r).mod(p);
		else
			x = K_LM.add(r).mod(q);
		
		BigInteger y=g.modPow(x,p);
		
		ElGamalPrivateKeySpec privSpec =  
			new ElGamalPrivateKeySpec(x, elParams); 
		ElGamalPublicKeySpec pubSpec =  
			new ElGamalPublicKeySpec(y, elParams);
		
		ElGamalPublicPGKey pubKey= new ElGamalPublicPGKey(pubSpec);
		ElGamalPrivatePGKey secKey= new ElGamalPrivatePGKey(privSpec);
		
		elgKp = new KeyPair(pubKey, secKey);
		exportKeyPair(out1, out2, dsaKp, elgKp, subuserid, 
			userPass.toCharArray(), true, expsec);
		exportKeyPair(out3, out4, dsaKp, elgKp, servuserid,
                        userPass.toCharArray(), true, expsec);
	
	}

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());


		if ( args.length > 1 )
		{
			String type = args[0];
			SELS_LIST_PATH = args[1];
    
			if(!(type.equals("GENPARAMS"))) initPGQ();

			if (type.equals("LM"))
				LMKeyGen(args[2], args[3], Integer.parseInt(args[4]));
			else if (type.equals("LS"))
			    	LSKeyGen(args[2],args[3], Integer.parseInt(args[4]));
			else if (type.equals("USER"))
				userKeyGen(args[2], args[3], "", "", args[4], args[5], Integer.parseInt(args[6]));
			else if (type.equals("CUSER"))
				CKeyGen(args[2], args[3], args[4], Integer.parseInt(args[5]));
			//else if (type.equals("GENPARAMS"))
			//  GenParamsBC();
			 else if (type.equals("GENPARAMS"))
 			    GenParams(Integer.parseInt(args[2]));
			//else if(type.equals("testinit"))
			//	initPGQ();
		}
		else
		{
			java.util.Properties prop = new java.util.Properties();
			prop.load( System.in );


			String type = prop.getProperty( "type" );
			SELS_LIST_PATH = prop.getProperty( "listPath" );
			String userId = prop.getProperty("userId");
			String subuserId = prop.getProperty( "subuserId" );
			String servuserId = prop.getProperty( "servuserId");
			String subuserIdHash = prop.getProperty( "subuserIdHash" );
			String servuserIdHash = prop.getProperty( "servuserIdHash" );
			String LSPass = prop.getProperty( "LSPass" );
			String LMPass = prop.getProperty( "LMPass" );
			String userPass = prop.getProperty( "userPass" );
			String LKPass = prop.getProperty( "LKPass" );
			String randomStr = prop.getProperty( "randStr" );
			String expsecstr = prop.getProperty("expsec");
			String keysize = prop.getProperty("keysize");

			if(!type.equals("GENPARAMS")) initPGQ();

			if (type.equals("LM"))
				LMKeyGen(userId, LMPass, Integer.parseInt(expsecstr));
			else if (type.equals("LS"))
			    LSKeyGen(userId, LSPass, Integer.parseInt(expsecstr)) ;
			else if (type.equals("USER"))
				userKeyGen(subuserId, servuserId, subuserIdHash, servuserIdHash, LMPass, userPass, Integer.parseInt(expsecstr));
			else if (type.equals("CUSER"))
				CKeyGen(userId, randomStr, LSPass, Integer.parseInt(expsecstr));
			else if (type.equals("LK"))
				LKKeyGen(userId, LKPass, Integer.parseInt(expsecstr));
			//else if (type.equals("GENPARAMS"))
			//  GenParamsBC();
			 else if (type.equals("GENPARAMS"))
 			    GenParams(Integer.parseInt(keysize));

		}

	}
}
