import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.Files;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import java.util.Enumeration;

import static org.apache.commons.io.IOUtils.closeQuietly;

/**
 * User: alexkasko
 * Date: 10/5/16
 */
public class KeystoreGeneratorTest {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final String KEYSTORE_PASSWORD = "passphrase";
    private static final String KEYSTORE_NAME = "test.p12";

    @Test
    public void test() throws Exception {
        File dir = null;
        FileInputStream fis = null;
        try {
            dir = Files.createTempDir();
            File keystoreFile = new File(dir, KEYSTORE_NAME);

            String config = new Gson().toJson(ImmutableMap.builder()
                    .put("keystoreType", "PKCS12")
                    .put("filename", keystoreFile.getAbsolutePath())
                    .put("password", KEYSTORE_PASSWORD)
                    .put("entries", ImmutableList.builder()
                            .add(ImmutableMap.builder()
                                    .put("label", "rsatest1")
                                    .put("algorithm", "SHA256WithRSA")
                                    .put("keyAlgorithm", "RSA")
                                    .put("validFrom", "2016-01-01")
                                    .put("validTo", "2030-12-31")
                                    .build())
                            .build())
                    .build());
            new KeystoreGenerator().generate(GSON.fromJson(config, KeystoreConfig.class));

            fis = new FileInputStream(keystoreFile);
            KeyStore ks = KeyStore.getInstance("PKCS12", "SunJSSE");
            ks.load(fis, KEYSTORE_PASSWORD.toCharArray());
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String al = aliases.nextElement();
                System.out.println("Label: [" + al + "]");
                X509Certificate cert = (X509Certificate) ks.getCertificate(al);
                System.out.println("  Algorithm: [" + cert.getSigAlgName() + "]");
                PublicKey key = cert.getPublicKey();
                if (key instanceof ECKey) {
                    ECKey eckey = (ECKey) key;
                    ECParameterSpec spec = eckey.getParams();
                    System.out.println("  EC spec: [" + spec + "]");
                }
                System.out.println(cert);
            }
        } finally {
            closeQuietly(fis);
            FileUtils.deleteDirectory(dir);
        }
    }
}
