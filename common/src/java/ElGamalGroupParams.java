/* Created by: SELS Team
*
* Description: El Gamal params
*
* License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
*/

import java.math.BigInteger;
public final class ElGamalGroupParams{

    private BigInteger p,q,g; 
    
    ElGamalGroupParams(BigInteger p, BigInteger q, BigInteger g){
        this.p = p;
        this.q = q;
        this.g = g;
    }


    public BigInteger getP(){
        return this.p;
    }
   
    public BigInteger getQ(){
        return this.q;
    }

    public BigInteger getG(){
        return this.g;
    }
           
}// enc class

