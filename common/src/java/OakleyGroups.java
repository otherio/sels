/* Created by: SELS Team
*
* Description: Oakley parameters
*
* License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt) 
*/

import java.math.BigInteger;
public final class OakleyGroups

{

       /** 
        * Precomputed Diffie Hellman groups from rfc 5114 (2048-bit MODP Group with 224-bit Prime Order Subgroup)
        */

    private static final ElGamalGroupParams

        DIFFIE_2048 = new ElGamalGroupParams(
	    /* p */
            new BigInteger("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1" +
        		   "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" +
                           "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212" +
                           "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
                           "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708" +
                           "B3BF8A317091883681286130BC8985DB1602E714415D9330" +
                           "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D" +
                           "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
                           "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763" +
                           "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" +
                           "CF9DE5384E71B81C0AC4DFFE0C10E64F", 16),
				
	    /* q */
            new BigInteger("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99" +
                           "B36371EB", 16),
            /* g */
            new BigInteger("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF" +
                           "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA" +
                           "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7" +
                           "C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
                           "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE" +
                           "F180EB34118E98D119529A45D6F834566E3025E316A330EF" +
                           "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB" +
                           "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
                           "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269" +
                           "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" +
                           "81BC087F2A7065B384B890D3191F2BFA", 16) );

    /**
     * Precomputed oakley groups from rfc2412 
     * --this class modeled after cryptix code (cryptix.org)
     */

    private static final ElGamalGroupParams

        OAKLEY_0768 = new ElGamalGroupParams(

            new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B" +
                           "80DC1CD129024E088A67CC74020BBEA63B139B22514A087" +
                           "98E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE135" +
                           "6D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFF" +
                           "FFFFFFFFFFF", 16),

            new BigInteger("7FFFFFFFFFFFFFFFE487ED5110B4611A62633145" +
                           "C06E0E68948127044533E63A0105DF531D89CD9128A5043" +
                           "CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09A" +
                           "B6B6A8E122F242DABB312F3F637A262174D31D1B107FFFF" +
                           "FFFFFFFFFFF", 16),

            new BigInteger("2", 16) );

 private static final ElGamalGroupParams

        OAKLEY_1024 = new ElGamalGroupParams(

            new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B" +
                          "80DC1CD129024E088A67CC74020BBEA63B139B22514A0879" +
                          "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D" +
                          "6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6" +
                          "F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651" +
                          "ECE65381FFFFFFFFFFFFFFFF", 16),

            new BigInteger("7FFFFFFFFFFFFFFFE487ED5110B4611A62633145" +
                          "C06E0E68948127044533E63A0105DF531D89CD9128A5043C" +
                          "C71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6" +
                          "B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B" +
                          "7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328" +
                          "F67329C0FFFFFFFFFFFFFFFF", 16),

            new BigInteger("2", 16) );

 private static final ElGamalGroupParams

        OAKLEY_1536 = new ElGamalGroupParams(

            new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B" +
                          "80DC1CD129024E088A67CC74020BBEA63B139B22514A0879" +
                          "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D" +
                          "6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6" +
                          "F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651" +
                          "ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
                          "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED52907" +
                          "7096966D670C354E4ABC9804F1746C08CA237327FFFFFFFF" +
                          "FFFFFFFF", 16),

            new BigInteger("7FFFFFFFFFFFFFFFE487ED5110B4611A62633145" +
                          "C06E0E68948127044533E63A0105DF531D89CD9128A5043C" +
                          "C71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6" +
                          "B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B" +
                          "7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328" +
                          "F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD4" +
                          "7E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483" +
                          "B84B4B36B3861AA7255E4C0278BA36046511B993FFFFFFFF" +
                          "FFFFFFFF", 16),

            new BigInteger("2", 16) );




    public static ElGamalGroupParams getElGamalGroup( int keysize){
	
	switch(keysize)
        {
	case 2048:
	    return DIFFIE_2048;		
        case 768:
            return OAKLEY_0768;
        case 1024:
            return OAKLEY_1024;
        case 1536:
            return OAKLEY_1536;
        default:
            return null; // we don't have any
        }
    }
}// end class
