package ru.voskhod.tests.esv;

import org.apache.log4j.Logger;
import ru.rt.server.esv.SignatureTool;
import ru.rt.server.esv.SignatureToolSoap;
import ru.rt.server.esv.VerificationResult;

import java.net.MalformedURLException;
import java.net.URL;

public class Client {

    private static Logger logger = Logger.getLogger(TestBase.class);
    private SignatureToolSoap signatureToolSoap;

    public Client(Config config) throws MalformedURLException {
        SignatureTool signatureTool = new SignatureTool(new URL(config.get("wsdlUrl")));
        signatureToolSoap = signatureTool.getSignatureToolSoap();
    }

    public VerificationResult verifyCertificate(byte[] certificate) {
        return signatureToolSoap.verifyCertificate(certificate);
    }
}
