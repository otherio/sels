/* Created by: SELS Team
*
* Description: El Gamal key generation
*
* License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt) 
*                   We use Bouncy Castle libraries. They are distributed under http://www.bouncycastle.org/licence.html
*/

import java.io.*;
import java.math.BigInteger;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.oiw.*;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;

public class ElGamalPublicPGKey
    implements ElGamalPublicKey
{
    private BigInteger              y;
    private ElGamalParameterSpec    elSpec;

    public ElGamalPublicPGKey(
        ElGamalPublicKeySpec    spec)
    {
        this.y = spec.getY();
        this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
    }

    public ElGamalPublicPGKey(
        ElGamalPublicKey    key)
    {
        this.y = key.getY();
        this.elSpec = key.getParameters();
    }

    public ElGamalPublicPGKey(
        ElGamalPublicKeyParameters  params)
    {
        this.y = params.getY();
        this.elSpec = new ElGamalParameterSpec(params.getParameters().getP(), params.getParameters().getG());
    }

    public ElGamalPublicPGKey(
        BigInteger              y,
        ElGamalParameterSpec    elSpec)
    {
        this.y = y;
        this.elSpec = elSpec;
    }

    public ElGamalPublicPGKey(
        SubjectPublicKeyInfo    info)
    {
        ElGamalParameter             params = new ElGamalParameter((ASN1Sequence)info.getAlgorithmId().getParameters());
        DERInteger              derY = null;

        try
        {
            derY = (DERInteger)info.getPublicKey();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid info structure in DSA public key");
        }

        this.y = derY.getValue();
        this.elSpec = new ElGamalParameterSpec(params.getP(), params.getG());
    }

    public String getAlgorithm()
    {
        return "ElGamal";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        SubjectPublicKeyInfo    info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG()).getDERObject()), new DERInteger(y));

        try
        {
            dOut.writeObject(info);
            dOut.close();
        }
        catch (IOException e)
        {
            throw new RuntimeException("Error encoding ElGamal public key");
        }

        return bOut.toByteArray();

    }

    public ElGamalParameterSpec getParameters()
    {
        return elSpec;
    }

    public BigInteger getY()
    {
        return y;
    }

    private void readObject(
        ObjectInputStream   in)
        throws IOException, ClassNotFoundException
    {
        this.y = (BigInteger)in.readObject();
        this.elSpec = new ElGamalParameterSpec((BigInteger)in.readObject(), (BigInteger)in.readObject());
    }

    private void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        out.writeObject(this.getY());
        out.writeObject(elSpec.getP());
        out.writeObject(elSpec.getG());
    }
}

