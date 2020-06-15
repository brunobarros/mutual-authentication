package com.example.mutualauthentication.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

public class X509CertificateUtils {

    public static final String OID_FOR_CPF = "2.16.76.1.3.1";
    
    private static Logger log = LoggerFactory.getLogger(X509CertificateUtils.class);

    @SuppressWarnings("unchecked")
	public static String getOIDFromX509Certificate(X509Certificate cert) throws CertificateParsingException, IOException {
        Collection<List<?>> sans = X509ExtensionUtil.getSubjectAlternativeNames(cert);
        log.info("Read X509 SANs " + sans);
        for (List<?> san : sans) {

            log.info("Read X509 SAN " + san);
            int sanType = (int) san.get(0);
            if (sanType == GeneralName.otherName) {

                ASN1Sequence sanASN1Sequence = (ASN1Sequence) san.get(1);
                String oid = getSANFromASN1Sequence(sanASN1Sequence);
                if (oid != null) {
                    return oid;
                }
            }
        }
        return null;
    }

    private static String getSANFromASN1Sequence(ASN1Sequence sanASN1Sequence) throws IOException {
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) sanASN1Sequence.getObjectAt(0);
        if (!OID_FOR_CPF.equals(oid.getId())) {
            log.info("OID expected '" + OID_FOR_CPF + "' got '" + oid.getId() + "'.");
            return null;
        }

        ASN1TaggedObject sanASN1TaggedObject = (ASN1TaggedObject) sanASN1Sequence.getObjectAt(1);
        DERObject derObject = sanASN1TaggedObject.getObject();

        String valueOfTag;
        if (derObject instanceof ASN1String) {
        	valueOfTag = ((ASN1String) derObject).getString();
        	log.info("ASN1String={}", valueOfTag);
        	return valueOfTag;
        } else if (derObject instanceof DEROctetString) {  
            DEROctetString octet = (DEROctetString) derObject;  
            valueOfTag = new String(octet.getOctets()); 
            log.info("DEROctetString={}", valueOfTag);
            return valueOfTag;
        } else if (derObject instanceof DERPrintableString) {  
            DERPrintableString octet = (DERPrintableString) derObject;  
            valueOfTag = new String(octet.getOctets());
            log.info("DERPrintableString | new String(octet.getOctets()) = {}", valueOfTag);
            log.info("DERPrintableString | octet.getString() = {}", octet.getString());
            log.info("DERPrintableString | new String(octet.getEncoded()) = {}", new String(octet.getEncoded()));
            return valueOfTag;
        } else if (derObject instanceof DERUTF8String) {  
            DERUTF8String str = (DERUTF8String) derObject;  
            valueOfTag = str.getString(); 
            log.info("DERUTF8String={}", valueOfTag);
            return valueOfTag;
        }

        log.warn("Invalid ASN.1 Primitive class, expected (ASN1String or DEROctetString or DERPrintableString or DERUTF8String), got " + derObject.getClass());
        return null;
    }

	public static String getCpfFromSubjectAlternativeName(X509Certificate x509Certificate) throws CertificateParsingException, IOException {
		String oidFromX509Certificate = getOIDFromX509Certificate(x509Certificate);
		
		if (oidFromX509Certificate != null) {
			String cpf = oidFromX509Certificate.substring(8, 19);
			log.info("Got CPF={} from OID={}", cpf, oidFromX509Certificate);
			return cpf;
		}
		
		log.warn("OID {} from X509Certificate is null.", OID_FOR_CPF);
		return null;
	}
	
	@SuppressWarnings("unchecked")
	public static String getEmailFromSanX509Certificate(X509Certificate cert) throws CertificateParsingException {
		Collection<List<?>> sans = X509ExtensionUtil.getSubjectAlternativeNames(cert);
		log.info("Read X509 SANs " + sans);
		for (List<?> san : sans) {

			log.info("Read X509 SAN " + san);
			int sanType = (int) san.get(0);
			if (sanType == GeneralName.rfc822Name) {

				String rfc822Name = (String) san.get(1);
				log.info("rfc822Name={}", rfc822Name);
				return rfc822Name;
			}
		}
		
		log.warn("rfc822Name from X509Certificate doesn't exists.");
		return null;
	}

}