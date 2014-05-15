/* Created by: SELS Team
*
* Description: El Gamal key generation
*
* License: This code is a part of SELS distribution under NCSA/UIUC Open Source License (refer NCSA-license.txt)
*                   We use Bouncy Castle libraries. They are distributed under http://www.bouncycastle.org/licence.html
*/

import java.io.*;
import java.util.*;
import java.math.BigInteger;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.oiw.*;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;

public class ElGamalPrivatePGKey
    implements ElGamalPrivateKey, PKCS12BagAttributeCarrier
{
    BigInteger      x;

    ElGamalParameterSpec   elSpec;

    private Hashtable   pkcs12Attributes = new Hashtable();
    private Vector      pkcs12Ordering = new Vector();

    protected ElGamalPrivatePGKey()
    {
    }

    public ElGamalPrivatePGKey(
        ElGamalPrivateKey    key)
    {
        this.x = key.getX();
        this.elSpec = key.getParameters();
    }

    public ElGamalPrivatePGKey(
        ElGamalPrivateKeySpec    spec)
    {
        this.x = spec.getX();
        this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
    }

    public ElGamalPrivatePGKey(
        PrivateKeyInfo  info)
    {
        ElGamalParameter     params = new ElGamalParameter((ASN1Sequence)info.getAlgorithmId().getParameters());
        DERInteger      derX = (DERInteger)info.getPrivateKey();

        this.x = derX.getValue();
        this.elSpec = new ElGamalParameterSpec(params.getP(), params.getG());
    }

    public ElGamalPrivatePGKey(
        ElGamalPrivateKeyParameters  params)
    {
        this.x = params.getX();
        this.elSpec = new ElGamalParameterSpec(params.getParameters().getP(), params.getParameters().getG());
    }

    public String getAlgorithm()
    {
        return "ElGamal";
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        PrivateKeyInfo          info = new PrivateKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG()).getDERObject()), new DERInteger(getX()));

        try
        {
            dOut.writeObject(info);
            dOut.close();
        }
        catch (IOException e)
        {
            throw new RuntimeException("Error encoding ElGamal private key");
        }

        return bOut.toByteArray();
    }

    public ElGamalParameterSpec getParameters()
    {
        return elSpec;
    }

    public BigInteger getX()
    {
        return x;
    }

    private void readObject(
        ObjectInputStream   in)
        throws IOException, ClassNotFoundException
    {
        x = (BigInteger)in.readObject();

        this.elSpec = new ElGamalParameterSpec((BigInteger)in.readObject(), (BigInteger)in.readObject());
    }

    private void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        out.writeObject(this.getX());
        out.writeObject(elSpec.getP());
        out.writeObject(elSpec.getG());
    }

    public void setBagAttribute(
        DERObjectIdentifier oid,
        DEREncodable        attribute)
    {
        pkcs12Attributes.put(oid, attribute);
        pkcs12Ordering.addElement(oid);
    }

    public DEREncodable getBagAttribute(
        DERObjectIdentifier oid)
    {
        return (DEREncodable)pkcs12Attributes.get(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return pkcs12Ordering.elements();
    }
}
