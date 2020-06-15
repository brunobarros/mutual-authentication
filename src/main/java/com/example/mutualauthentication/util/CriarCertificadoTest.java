package com.example.mutualauthentication.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;

public class CriarCertificadoTest {

    private static JcaX509ExtensionUtils extUtils;

    static SecureRandom rand;

    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            rand = SecureRandom.getInstance("SHA1PRNG");
            extUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            rand = new SecureRandom();
        }
    }

    /**
     * Cria um certificado de teste.
     *
     * O certificado é emitido pela AC criada pela classe {@link com.example.mutualauthentication.util.CriarAcTest}
     */
    public static void main(String[] args) throws Exception {
        KeyPair myKeyPair = genKeyPair(2048);

        String acSubject = "C=BR,O=TRT2,CN=AC Test";
        char[] password = "123456".toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        // carrega o certificado da AC
        InputStream in = new FileInputStream("actest.jks");
        ks.load(in, password);
        in.close();

        // obtém o certificado e as chaves da AC
        X509Certificate acCert = (X509Certificate) ks.getCertificate("main");
        KeyPair acKeyPair = new KeyPair(acCert.getPublicKey(), (PrivateKey) ks.getKey("main", password));

        System.out.println(acCert);

        // mudar os dados conforme necessário
        String cpf = "23446147292";
        String filename = "cpf" + cpf;
        String nome = "FULANO DE TAL";
        filename = "certificado_" + cpf; // nome do PFX e .cer
        // validade do certificado (em dias) - a data inicial é a atual menos 24 horas
        int validityDays = 365 * 3;
        X509Certificate cert = createCert("C=BR,O=ICP-Brasil,OU=AR Teste,OU=RFB e-CPF A3,OU=TESTE,CN=" + nome + ":" + cpf,
                new BigInteger("3333333333", 16), validityDays, myKeyPair, acKeyPair, acSubject, cpf, acCert);
        saveToKeystore(cert, myKeyPair.getPrivate(), filename + ".pfx", "PKCS12", acCert);
        saveToFile(cert, filename + ".cer");

        System.out.println(cert);
    }

    static void saveToKeystore(X509Certificate certificate, PrivateKey privKey, String file, String type, X509Certificate acCert) throws Exception {
        char[] password = "123456".toCharArray();
        KeyStore ks = KeyStore.getInstance(type);
        ks.load(null, password);

        ks.setKeyEntry("main", privKey, password, new Certificate[] { certificate, acCert });

        OutputStream out = new FileOutputStream(file);
        ks.store(out, password);
        out.close();
    }

    static void saveToFile(X509Certificate cert, String filename) throws IOException {
        JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(filename));
        pw.writeObject(cert);
        pw.close();
    }

    public static X509Certificate createCert(String subject, BigInteger serialNumber, int validityInDays, KeyPair myKeyPair, KeyPair acKeyPair,
            String acSubject, String cpf, X509Certificate acCert)
            throws Exception {
        // data-inicio 24 horas antes, pra evitar dessincronizacao entre maquinas, horario de verao
        LocalDate validityStart = LocalDate.now().minusDays(1);
        LocalDate validityEnd = validityStart.plus(validityInDays, ChronoUnit.DAYS);
        // data de validade do certificado não pode ser maior que da AC
        LocalDate validadeAC = acCert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        if (!validityEnd.isBefore(validadeAC)) {
            validityEnd = validadeAC.minus(24 * 20, ChronoUnit.HOURS);
        }
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(new X500Name(acSubject), serialNumber,
            // se estiver usando Java >= 8, use o java.time e troque esta linha para Date.from(validityStart), Date.from(validityEnd)
        		Date.valueOf(validityStart), Date.valueOf(validityEnd),
            new X500Name(subject), myKeyPair.getPublic());

        KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation);
        certBuilder.addExtension(Extension.keyUsage, false, usage);

        //Descomentar utilizando dependência org.bouncycastle.bcprov-jdk15on.1.65
        //ExtendedKeyUsage eku = new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth });
        //certBuilder.addExtension(Extension.extendedKeyUsage, false, eku);

        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(myKeyPair.getPublic()));

        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(acKeyPair.getPublic()));

        // --------------------------------------------------------------------
        // Subject Alternative Names
        ASN1EncodableVector subjAltNames = new ASN1EncodableVector();

        // OID 1
        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier("2.16.76.1.3.1"));
        // data de nascimento
        StringBuilder strOid1 = new StringBuilder("10101970")
                // CPF
                .append(cpf)
                // nis
                .append("00000000000")
                // RG
                .append("000000226148452SSPSP");
        otherName.add(new DERTaggedObject(true, 0, new DERPrintableString(strOid1.toString())));
        ASN1Object oid1 = new DERTaggedObject(false, GeneralName.otherName, new DERSequence(otherName));
        subjAltNames.add(oid1);

        // OID 6
        otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier("2.16.76.1.3.6"));
        // CEI
        String strOid6 = "000000000000";
        otherName.add(new DERTaggedObject(true, 0, new DERPrintableString(strOid6)));
        ASN1Object oid6 = new DERTaggedObject(false, GeneralName.otherName, new DERSequence(otherName));
        subjAltNames.add(oid6);

        // OID 5
        otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier("2.16.76.1.3.5"));
        // titulo de eleitor
        StringBuilder strOid5 = new StringBuilder("850544450191")
                // zona eleitoral
                .append("001")
                // secao
                .append("0401")
                // municipio e UF
                .append("SAO PAULOSP");
        otherName.add(new DERTaggedObject(true, 0, new DERPrintableString(strOid5.toString())));
        ASN1Object oid5 = new DERTaggedObject(false, GeneralName.otherName, new DERSequence(otherName));
        subjAltNames.add(oid5);

        certBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(subjAltNames));
        // --------------------------------------------------------------------

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(acKeyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certBuilder.build(signer));

        return cert;
    }

    public static X509Certificate createCertPJ(String subject, BigInteger serialNumber, int validityInDays, KeyPair myKeyPair, KeyPair acKeyPair,
            String acSubject, String cpfResp, String nomeResp, String cnpj, X509Certificate acCert)
            throws Exception {
        // data-inicio 24 horas antes, pra evitar dessincronizacao entre maquinas, horario de verao
        LocalDate validityStart = LocalDate.now().minusDays(1);
        LocalDate validityEnd = validityStart.plus(validityInDays, ChronoUnit.DAYS);
        // data de validade do certificado não pode ser maior que da AC
        LocalDate validadeAC = acCert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        if (!validityEnd.isBefore(validadeAC)) {
            validityEnd = validadeAC.minus(24 * 20, ChronoUnit.HOURS);
        }
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(new X500Name(acSubject), serialNumber,
            // se estiver usando Java >= 8, use o java.time e troque esta linha para Date.from(validityStart), Date.from(validityEnd)
            Date.valueOf(validityStart), Date.valueOf(validityEnd),
            new X500Name(subject), myKeyPair.getPublic());

        KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation);
        certBuilder.addExtension(Extension.keyUsage, false, usage);

        //Descomentar utilizando dependência org.bouncycastle.bcprov-jdk15on.1.65
        //ExtendedKeyUsage eku = new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth });
        //certBuilder.addExtension(Extension.extendedKeyUsage, false, eku);

        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(myKeyPair.getPublic()));

        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(acKeyPair.getPublic()));

        // --------------------------------------------------------------------
        // Subject Alternative Names
        ASN1EncodableVector subjAltNames = new ASN1EncodableVector();

        // OID 4
        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier("2.16.76.1.3.4"));
        // data de nascimento
        StringBuilder strOid1 = new StringBuilder("10101970")
                // CPF
                .append(cpfResp)
                // nis
                .append("00000000000")
                // RG
                .append("000000226148452SSPSP");
        otherName.add(new DERTaggedObject(true, 0, new DERPrintableString(strOid1.toString())));
        ASN1Object oid4 = new DERTaggedObject(false, GeneralName.otherName, new DERSequence(otherName));
        subjAltNames.add(oid4);

        // OID 2
        otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier("2.16.76.1.3.2"));
        // Nome do responsavel
        otherName.add(new DERTaggedObject(true, 0, new DERPrintableString(nomeResp)));
        ASN1Object oid2 = new DERTaggedObject(false, GeneralName.otherName, new DERSequence(otherName));
        subjAltNames.add(oid2);

        // OID 3
        otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier("2.16.76.1.3.3"));
        // CNPJ
        otherName.add(new DERTaggedObject(true, 0, new DERPrintableString(cnpj)));
        ASN1Object oid3 = new DERTaggedObject(false, GeneralName.otherName, new DERSequence(otherName));
        subjAltNames.add(oid3);

        // OID 7
        otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier("2.16.76.1.3.7"));
        // CEI
        String strOid7 = "000000000000";
        otherName.add(new DERTaggedObject(true, 0, new DERPrintableString(strOid7)));
        ASN1Object oid7 = new DERTaggedObject(false, GeneralName.otherName, new DERSequence(otherName));
        subjAltNames.add(oid7);

        certBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(subjAltNames));
        // --------------------------------------------------------------------

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(acKeyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certBuilder.build(signer));

        return cert;
    }

    public static KeyPair genKeyPair(int size) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        gen.initialize(size, rand);
        return gen.generateKeyPair();
    }
}