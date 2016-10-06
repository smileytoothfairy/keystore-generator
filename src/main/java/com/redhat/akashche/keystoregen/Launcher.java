package com.redhat.akashche.keystoregen;

import com.google.gson.Gson;
import org.apache.commons.cli.*;

import java.io.*;
import java.nio.charset.Charset;
import java.security.KeyStore;

import static java.lang.System.out;

/**
 * User: alexkasko
 * Date: 10/6/16
 */
public class Launcher {
        private static final String VERSION = "Keystore Generator 1.0";
        private static final String HELP_OPTION = "help";
        private static final String VERSION_OPTION = "version";
        private static final String CONFIG_OPTION = "config";
        private static final String OUTPUT_OPTION = "output";
        private static final Options OPTIONS = new Options()
                .addOption("h", HELP_OPTION, false, "show this page")
                .addOption("v", VERSION_OPTION, false, "show version")
                .addOption("c", CONFIG_OPTION, true, "configuration file")
                .addOption("o", OUTPUT_OPTION, true, "output file");

        public static void main(String[] args) throws Exception {
            try {
                CommandLine cline = new GnuParser().parse(OPTIONS, args);
                if (cline.hasOption(VERSION_OPTION)) {
                    out.println(VERSION);
                } else if (cline.hasOption(HELP_OPTION)) {
                    throw new ParseException("Printing help page:");
                } else if (0 == cline.getArgs().length &&
                        cline.hasOption(CONFIG_OPTION) &&
                        cline.hasOption(OUTPUT_OPTION)) {
                    KeystoreConfig conf = parseConf(cline.getOptionValue(CONFIG_OPTION));
                    KeyStore ks = new KeystoreGenerator().generate(conf);
                    writeKeystore(conf, ks, cline.getOptionValue(OUTPUT_OPTION));
                } else {
                    throw new ParseException("Incorrect arguments received!");
                }
            } catch (ParseException e) {
                HelpFormatter formatter = new HelpFormatter();
                out.println(e.getMessage());
                out.println(VERSION);
                formatter.printHelp("java -jar keystoregen.jar -c config.json -o output.p12", OPTIONS);
            }
        }

        private static void writeKeystore(KeystoreConfig conf, KeyStore ks, String path) throws Exception {
            File file = new File(path);
            if (file.exists()) throw new IOException("Output file already exists: [" + path + "]");
            try (FileOutputStream os = new FileOutputStream(file)) {
                ks.store(os, conf.getPassword().toCharArray());
            }
        }

        private static KeystoreConfig parseConf(String path) throws IOException {
            File file = new File(path);
            if (!(file.exists() && file.isFile())) throw new IOException("Invalid config file: [" + path + "]");
            try (FileInputStream is = new FileInputStream(file)) {
                Reader re = new InputStreamReader(is, Charset.forName("UTF-8"));
                return new Gson().fromJson(re, KeystoreConfig.class);
            } catch (Exception e) {
                throw new RuntimeException("Invalid config file: [" + path + "]", e);
            }
        }
}
