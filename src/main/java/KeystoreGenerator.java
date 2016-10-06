import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class KeystoreGenerator {
    public static final Provider BCPROV = new BouncyCastleProvider();

    private static final RSAPublicKeySpec RSA_PUB_KEY_SPEC = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

    private static final RSAPrivateCrtKeySpec RSA_PRIV_KEY_SPEC = new RSAPrivateCrtKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    public void generate(KeystoreConfig cf) throws Exception {
        KeyStore store = KeyStore.getInstance(cf.getKeystoreType(), BCPROV);
        store.load(null, null);

        for (KeystoreConfig.Entry en : cf.getEntries()) {
            final Keys keys;
            if ("RSA".equalsIgnoreCase(en.getKeyAlgorithm())) {
                KeyFactory kf = KeyFactory.getInstance("RSA", BCPROV);
                keys = new Keys(kf.generatePrivate(RSA_PRIV_KEY_SPEC), kf.generatePublic(RSA_PUB_KEY_SPEC),
                        kf.generatePrivate(RSA_PRIV_KEY_SPEC), kf.generatePublic(RSA_PUB_KEY_SPEC),
                        kf.generatePrivate(RSA_PRIV_KEY_SPEC), kf.generatePublic(RSA_PUB_KEY_SPEC));
            } else throw new IllegalArgumentException("Unsupported 'keyAlgorithm': [" + en.getKeyAlgorithm() + "]");

            Certificate[] chain = new Certificate[3];
            chain[2] = createMasterCert(en, keys);
            chain[1] = createIntermediateCert(en, keys, (X509Certificate) chain[2]);
            chain[0] = createCert(en, keys);

            PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) keys.certPrivate;
            bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(en.getLabel()));
            bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keys.certPublic));
            store.setKeyEntry(en.getLabel(), keys.certPrivate, null, chain);
        }

        try (FileOutputStream out = new FileOutputStream(cf.getFilename())) {
            store.store(out, cf.getPassword().toCharArray());
        }
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
