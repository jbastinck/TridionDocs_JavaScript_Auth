const crypto = require("crypto");
const request = require('request-promise-native');
const util = require('util');
const fs = require("fs");
const parseString =  require('xml2js').parseString;
const xml2js = require('xml2js');
const parseStringPromise = util.promisify(parseString);

const { sha1HmacDigest } = require("./hashing");
const { getFirstFromXML } = require('./xmlParsing');
const hashText = sha1HmacDigest
/**
 * Step 4 of the Login Process. Here we send the signed request to the server. 
 */
const getRequestToken = async function(res, baseUrl, debug, created, expires){
  const applicationUrl = `${baseUrl}ISHWS/Wcf/API25/Application.svc`

  // Step 2: Send a new request to Application.svc 
  const xencEncryptedDataFromLoginResponse = getFirstFromXML(res.raw, "xenc:EncryptedData", true)
  const securityTokenReferenceFromLoginResponse = getFirstFromXML(res.raw, "o:SecurityTokenReference", true)
  const keyIdentifier = getFirstFromXML(res.raw, "o:KeyIdentifier", true);
  // console.log("encrypted data")
  //console.log(xencEncryptedDataFromLoginResponse)
  // const created = new Date()
  // const expires = new Date() 

  /**
   * UNKNOWNS >>> 
   * - digestValue doesn't match
   * - signature Value --- what is it? 
   * - binary secret -- what is it? 
   */
  // Main Question is here:
  // Do we sign this with the private key ? Digest Value is different from Fiddler
  // console.log(res)
  const referenceElementForSigning = `<u:Timestamp><u:Created>${created.toISOString()}</u:Created><u:Expires>${expires.toISOString()}</u:Expires></u:Timestamp>`;
  const digestValue = hashText(referenceElementForSigning, res.encryptionKey) // Expected: EK3XBjVtGU+Pg14pwb37CJvP044= 

  const signedInfoElement = `
<SignedInfo>
  <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>
  <Reference URI="#_0">
    <Transforms>
      <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </Transforms>
    <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
    <DigestValue>${digestValue}</DigestValue>
  </Reference>
</SignedInfo>
`


  console.log("key identifier", keyIdentifier)

  // What am I signing in signature value ? 
  const signatureValue = hashText(signedInfoElement, res.encryptionKey)

  // What is this?
  const binarySecret = "9F9b026Fa+sqs2aqrBFVeoxOoBIq0I0o8mDjw5sNe0E="

  const applicationXML = `
  <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
    xmlns:a="http://www.w3.org/2005/08/addressing" 
    xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Header>
      <a:Action s:mustUnderstand="1">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/SCT</a:Action>
      <a:MessageID>urn:uuid:b1841bf0-633e-43fe-b3a2-7002eb9329ef</a:MessageID>
      <a:ReplyTo>
        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
      </a:ReplyTo>
      <a:To s:mustUnderstand="1">${applicationUrl}</a:To>
      <o:Security s:mustUnderstand="1" 
        xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <u:Timestamp u:Id="_0">
          <u:Created>${created.toISOString()}</u:Created>
          <u:Expires>${expires.toISOString()}</u:Expires>
        </u:Timestamp>
        ${xencEncryptedDataFromLoginResponse}
        <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
          ${signedInfoElement}
          <SignatureValue>${signatureValue}</SignatureValue>
          <KeyInfo>
            <o:SecurityTokenReference k:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" 
              xmlns:k="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd">
              ${keyIdentifier}
            </o:SecurityTokenReference>
          </KeyInfo>
        </Signature>
      </o:Security>
    </s:Header>
    <s:Body>
      <trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
        <trust:TokenType>http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct</trust:TokenType>
        <trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>
        <trust:Entropy>
          <trust:BinarySecret u:Id="uuid-d1dd602c-ced6-4d53-bfa1-64a3620b47be-1" Type="http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce">${binarySecret}</trust:BinarySecret>
        </trust:Entropy>
        <trust:KeySize>256</trust:KeySize>
      </trust:RequestSecurityToken>
    </s:Body>
  </s:Envelope>`


  /**
   * Convert to xml string by using xml2js library. 
   * This was experimental function to ensure proper formating in the file.
   */
  async function convertStringToXMLToString(str){
    const parsed = await parseStringPromise(str);
    //console.log(util.inspect(parsed, false, null))
    var builder = new xml2js.Builder();
    var xmlStr = builder.buildObject(parsed);
    //console.log(xmlStr)
    return xmlStr
  };




  return new Promise(async (resolve, reject) => {
    const requestOptions = {
      uri:applicationUrl,
      method: 'POST',
      body: applicationXML, // await convertStringToXMLToString(applicationXML) // use this to ensure proper formating of string.
      headers: {
        'Content-Type':'application/soap+xml',
        //'Accept-Encoding': 'gzip,deflate',
        'Content-Length':applicationXML.length,
        'SOAPAction':"UserNameWSTrustBinding_IWSTrust13Sync"
      }
    }
    const strForWriting = await convertStringToXMLToString(applicationXML);
    fs.writeFileSync("xmlout.xml", strForWriting ) ;
    // console.log(applicationXML);
    request(requestOptions).then(response => {
      console.log("resonse is back ");
  
      // console.log(Object.keys(response))
      console.log(response)
  
      //console.log(response.toJson())
      resolve(response)
    })
    .catch(err => {
      console.log("Error is back ");
      console.log(err.response.body)
      console.log("done writing error")
      reject(err)
    })
    console.log("returned")
    //console.log(res.responseXml)
  })
}

module.exports = { getRequestToken }
