package com.redhat.akashche.keystoregen;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.util.Date;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class KeystoreGenerator {
    public static final Provider BCPROV = new BouncyCastleProvider();

    public KeyStore generate(KeystoreConfig cf) throws Exception {
        KeyStore store = KeyStore.getInstance(cf.getKeystoreType(), BCPROV);
        store.load(null, null);

        for (KeystoreConfig.Entry en : cf.getEntries()) {
            Keys keys = generateKeys(en);

            Certificate[] chain = new Certificate[3];
            chain[2] = createMasterCert(en, keys);
            chain[1] = createIntermediateCert(en, keys, (X509Certificate) chain[2]);
            chain[0] = createCert(en, keys);

            PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) keys.certPrivate;
            bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(en.getLabel()));
            bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keys.certPublic));
            store.setKeyEntry(en.getLabel(), keys.certPrivate, null, chain);
        }

        return store;
    }

    private Certificate createMasterCert(KeystoreConfig.Entry en, Keys keys) throws Exception {
        String label = en.getLabel() + "_CA";
        X500NameBuilder subject = new X500NameBuilder();
        subject.addRDN(BCStyle.C, en.getX500_C());
        subject.addRDN(BCStyle.O, en.getX500_O());
        subject.addRDN(BCStyle.OU, en.getX500_OU());
        subject.addRDN(BCStyle.CN, label);

        ContentSigner signer = new JcaContentSignerBuilder(en.getAlgorithm()).setProvider(BCPROV).build(keys.caPrivate);
        X509CertificateHolder holder = new JcaX509v3CertificateBuilder(subject.build(), BigInteger.valueOf(1),
                en.getValidFrom(), en.getValidTo(), subject.build(), keys.caPublic).build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BCPROV).getCertificate(holder);

        cert.checkValidity(new Date());
        cert.verify(keys.caPublic);

        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(label));
        return cert;
    }

    private Certificate createIntermediateCert(KeystoreConfig.Entry en, Keys keys, X509Certificate caCert) throws Exception {
        String label = en.getLabel() + "_INTERMEDIATE";
        X500NameBuilder subject = new X500NameBuilder();
        subject.addRDN(BCStyle.C, en.getX500_C());
        subject.addRDN(BCStyle.O, en.getX500_O());
        subject.addRDN(BCStyle.OU, en.getX500_OU());
        subject.addRDN(BCStyle.CN, label);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(caCert, BigInteger.valueOf(2),
                en.getValidFrom(), en.getValidTo(), subject.build(), keys.intPublic);
        JcaX509ExtensionUtils eu = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, eu.createSubjectKeyIdentifier(keys.intPublic));
        builder.addExtension(Extension.authorityKeyIdentifier, false, eu.createAuthorityKeyIdentifier(caCert));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder(en.getAlgorithm()).setProvider(BCPROV).build(keys.caPrivate));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BCPROV).getCertificate(holder);

        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,new DERBMPString(label));
        return cert;
    }

    private Certificate createCert(KeystoreConfig.Entry en, Keys keys) throws Exception {
        X500NameBuilder issuer = new X500NameBuilder();
        issuer.addRDN(BCStyle.C, en.getX500_C());
        issuer.addRDN(BCStyle.O, en.getX500_O());
        issuer.addRDN(BCStyle.OU, en.getX500_OU());
        issuer.addRDN(BCStyle.CN, en.getLabel() + "_INTERMEDIATE");

        String label = en.getLabel() + "_CERT";
        X500NameBuilder subject = new X500NameBuilder();
        subject.addRDN(BCStyle.C, en.getX500_C());
        subject.addRDN(BCStyle.O, en.getX500_O());
        subject.addRDN(BCStyle.OU, en.getX500_OU());
        subject.addRDN(BCStyle.CN, label);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer.build(), BigInteger.valueOf(3),
                en.getValidFrom(), en.getValidTo(), subject.build(), keys.certPublic);
        JcaX509ExtensionUtils eu = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, eu.createSubjectKeyIdentifier(keys.certPublic));
        builder.addExtension(Extension.authorityKeyIdentifier, false, eu.createAuthorityKeyIdentifier(keys.caPublic));
        X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder(en.getAlgorithm()).setProvider(BCPROV).build(keys.caPrivate));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BCPROV).getCertificate(holder);

        cert.checkValidity(new Date());
        cert.verify(keys.caPublic);

        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(label));
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, eu.createSubjectKeyIdentifier(keys.certPublic));
        return cert;
    }

    private Keys generateKeys(KeystoreConfig.Entry en) throws Exception {
        if ("RSA".equalsIgnoreCase(en.getKeyAlgorithm())) {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", BCPROV);
            keygen.initialize(en.getRsaKeySize(), new SecureRandom());
            KeyPair pair = keygen.generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance("RSA", BCPROV);
            KeySpec privSpec = new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded());
            KeySpec pubSpec = new X509EncodedKeySpec(pair.getPublic().getEncoded());
            return new Keys(kf.generatePrivate(privSpec), kf.generatePublic(pubSpec),
                    kf.generatePrivate(privSpec), kf.generatePublic(pubSpec),
                    kf.generatePrivate(privSpec), kf.generatePublic(pubSpec));
        } else if ("ECDSA".equalsIgnoreCase(en.getKeyAlgorithm())) {
            ECParameterSpec spec = ECNamedCurveTable.getParameterSpec(en.getEcdsaNamedCurve());
            if (null == spec) throw new IllegalArgumentException("Invalid 'ecdsaNamedCurve': [" + en.getEcdsaNamedCurve() + "]");
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("ECDSA", BCPROV);
            keygen.initialize(spec, new SecureRandom());
            KeyPair pair = keygen.generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance("ECDSA", BCPROV);
            KeySpec privSpec = new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded());
            KeySpec pubSpec = new X509EncodedKeySpec(pair.getPublic().getEncoded());
            return new Keys(kf.generatePrivate(privSpec), kf.generatePublic(pubSpec),
                    kf.generatePrivate(privSpec), kf.generatePublic(pubSpec),
                    kf.generatePrivate(privSpec), kf.generatePublic(pubSpec));
        } else throw new IllegalArgumentException("Unsupported 'keyAlgorithm': [" + en.getKeyAlgorithm() + "]");
    }

    private static class Keys {
        PrivateKey caPrivate;
        PublicKey caPublic;
        PrivateKey intPrivate;
        PublicKey intPublic;
        PrivateKey certPrivate;
        PublicKey certPublic;

        private Keys(PrivateKey caPrivate, PublicKey caPublic, PrivateKey intPrivate, PublicKey intPublic, PrivateKey certPrivate, PublicKey certPublic) {
            this.caPrivate = caPrivate;
            this.caPublic = caPublic;
            this.intPrivate = intPrivate;
            this.intPublic = intPublic;
            this.certPrivate = certPrivate;
            this.certPublic = certPublic;
        }
    }

}
