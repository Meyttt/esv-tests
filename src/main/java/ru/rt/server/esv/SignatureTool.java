
package ru.rt.server.esv;

import java.net.MalformedURLException;
import java.net.URL;
import javax.xml.namespace.QName;
import javax.xml.ws.Service;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceException;
import javax.xml.ws.WebServiceFeature;


/**
 * This class was generated by the JAX-WS RI.
 * JAX-WS RI 2.2.4-b01
 * Generated source version: 2.2
 * 
 */
@WebServiceClient(name = "SignatureTool", targetNamespace = "http://esv.server.rt.ru", wsdlLocation = "http://10.215.0.56/ESV.Server/SignatureTool.asmx?wsdl")
public class SignatureTool
    extends Service
{

    private final static URL SIGNATURETOOL_WSDL_LOCATION;
    private final static WebServiceException SIGNATURETOOL_EXCEPTION;
    private final static QName SIGNATURETOOL_QNAME = new QName("http://esv.server.rt.ru", "SignatureTool");

    static {
        URL url = null;
        WebServiceException e = null;
        try {
            url = new URL("http://10.215.0.56/ESV.Server/SignatureTool.asmx?wsdl");
        } catch (MalformedURLException ex) {
            e = new WebServiceException(ex);
        }
        SIGNATURETOOL_WSDL_LOCATION = url;
        SIGNATURETOOL_EXCEPTION = e;
    }

    public SignatureTool() {
        super(__getWsdlLocation(), SIGNATURETOOL_QNAME);
    }

    public SignatureTool(WebServiceFeature... features) {
        super(__getWsdlLocation(), SIGNATURETOOL_QNAME, features);
    }

    public SignatureTool(URL wsdlLocation) {
        super(wsdlLocation, SIGNATURETOOL_QNAME);
    }

    public SignatureTool(URL wsdlLocation, WebServiceFeature... features) {
        super(wsdlLocation, SIGNATURETOOL_QNAME, features);
    }

    public SignatureTool(URL wsdlLocation, QName serviceName) {
        super(wsdlLocation, serviceName);
    }

    public SignatureTool(URL wsdlLocation, QName serviceName, WebServiceFeature... features) {
        super(wsdlLocation, serviceName, features);
    }

    /**
     * 
     * @return
     *     returns SignatureToolSoap
     */
    @WebEndpoint(name = "SignatureToolSoap")
    public SignatureToolSoap getSignatureToolSoap() {
        return super.getPort(new QName("http://esv.server.rt.ru", "SignatureToolSoap"), SignatureToolSoap.class);
    }

    /**
     * 
     * @param features
     *     A list of {@link javax.xml.ws.WebServiceFeature} to configure on the proxy.  Supported features not in the <code>features</code> parameter will have their default values.
     * @return
     *     returns SignatureToolSoap
     */
    @WebEndpoint(name = "SignatureToolSoap")
    public SignatureToolSoap getSignatureToolSoap(WebServiceFeature... features) {
        return super.getPort(new QName("http://esv.server.rt.ru", "SignatureToolSoap"), SignatureToolSoap.class, features);
    }

    private static URL __getWsdlLocation() {
        if (SIGNATURETOOL_EXCEPTION!= null) {
            throw SIGNATURETOOL_EXCEPTION;
        }
        return SIGNATURETOOL_WSDL_LOCATION;
    }

}
