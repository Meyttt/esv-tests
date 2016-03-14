
package ru.rt.server.esv;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for VerificationResultWithReport complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="VerificationResultWithReport">
 *   &lt;complexContent>
 *     &lt;extension base="{http://esv.server.rt.ru}VerificationResult">
 *       &lt;sequence>
 *         &lt;element name="Report" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "VerificationResultWithReport", propOrder = {
    "report"
})
@XmlSeeAlso({
    VerificationResultWithSignedReport.class
})
public class VerificationResultWithReport
    extends VerificationResult
{

    @XmlElement(name = "Report")
    protected byte[] report;

    /**
     * Gets the value of the report property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getReport() {
        return report;
    }

    /**
     * Sets the value of the report property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setReport(byte[] value) {
        this.report = value;
    }

}
