import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

/**
 * User: alexkasko
 * Date: 10/6/16
 */
public class KeystoreConfig {
    private static final String ISO8601_FORMAT = "yyyy-MM-dd";

    private String keystoreType = "PKCS12";
    private String filename;
    private String password;
    private ArrayList<Entry> entries = new ArrayList<>();

    String getKeystoreType() {
        return keystoreType;
    }

    String getFilename() {
        return filename;
    }

    String getPassword() {
        return password;
    }

    public ArrayList<Entry> getEntries() {
        return entries;
    }

    public static class Entry {
        private String label;
        private String algorithm;
        private String rsaKeySize;
        private String ecdsaNamedCurve;
        private String keyAlgorithm;
        private String validFrom = "2016-01-01";
        private String validTo = "2030-12-31";
        private String x500_C = "US";
        private String x500_O = "Test Organizaion";
        private String x500_OU = "Development";

        String getLabel() {
            return label;
        }

        String getAlgorithm() {
            return algorithm;
        }

        String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        Date getValidFrom() {
            try {
                return new SimpleDateFormat(ISO8601_FORMAT).parse(validFrom);
            } catch (ParseException e) {
                throw new RuntimeException("Invalid date: [" + validFrom + "]");
            }
        }

        Date getValidTo() {
            try {
                return new SimpleDateFormat(ISO8601_FORMAT).parse(validTo);
            } catch (ParseException e) {
                throw new RuntimeException("Invalid date: [" + validTo + "]");
            }
        }

        public String getX500_C() {
            return x500_C;
        }

        public String getX500_O() {
            return x500_O;
        }

        public String getX500_OU() {
            return x500_OU;
        }

        public int getRsaKeySize() {
            return Integer.parseInt(rsaKeySize);
        }

        public String getEcdsaNamedCurve() {
            return ecdsaNamedCurve;
        }
    }
}


