const crypto = require("crypto");
const request = require('request-promise-native');
const util = require('util');
const fs = require("fs");
const parseString =  require('xml2js').parseString;
const xml2js = require('xml2js');
const parseStringPromise = util.promisify(parseString);

const { getFirstFromXML } = require('./xmlParsing');

/**
 * 
 * @param {string} baseUrl
 * @param {string} username 
 * @param {string} password 
 * @param {boolean=} debug
 * @param {Date=} created
 * @param {Date=} expires 
 */
const createLoginRequestXML = async function(baseUrl, username, password, debug, created, expires ) {
  if(!username || !password){
    throw new Error("Cannot get assymetric keys without username and password")
  }
  if(!created){
    created = new Date()
  }
  if(!expires){
    expires = new Date()
    expires.setMinutes(expires.getMinutes() + 5)
  }

  const loginUrl = `${baseUrl}ISHSTS/issue/wstrust/mixed/username`
  const applicationUrl = `${baseUrl}ISHWS/Wcf/API25/Application.svc`

  const xml = `<soap:Envelope xmlns:ns="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Header xmlns:wsa="http://www.w3.org/2005/08/addressing">
      <wsse:Security soap:mustUnderstand="true" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
          <wsu:Timestamp wsu:Id="TS-CF7FD14FE6988DFBBF15838499247891">
            <wsu:Created>${created.toISOString()}</wsu:Created>
            <wsu:Expires>${expires.toISOString()}</wsu:Expires>
          </wsu:Timestamp>
          <wsse:UsernameToken>
            <wsse:Username>${username}</wsse:Username>
            <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${password}</wsse:Password>
          </wsse:UsernameToken>
      </wsse:Security>
      <wsa:Action soap:mustUnderstand="1">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action>
      <wsa:ReplyTo soap:mustUnderstand="1">
          <wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address>
      </wsa:ReplyTo>
      <wsa:MessageID soap:mustUnderstand="1">uuid:770d85cb-527e-46a5-8eeb-93fda0d2583d</wsa:MessageID>
      <wsa:To soap:mustUnderstand="1">${loginUrl}</wsa:To>
    </soap:Header>
    <soap:Body>
      <trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
          <!--You have a CHOICE of the next 1 items at this level-->
          <!--You may enter ANY elements at this point-->
          <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
            <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
                <wsa:Address>${applicationUrl}</wsa:Address>
            </wsa:EndpointReference>
          </wsp:AppliesTo>
          <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey</trust:KeyType>
          <trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>
          <trust:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</trust:TokenType>
      </trust:RequestSecurityToken>
    </soap:Body>
  </soap:Envelope>`

  debug && fs.writeFileSync("login-request.xml", xml);

  const requestOptions = {
    uri:loginUrl,
    method: 'POST',
    body: xml,
    headers: {
      'Content-Type':'application/soap+xml',
      //'Accept-Encoding': 'gzip,deflate',
      'Content-Length':xml.length,
      'SOAPAction':"UserNameWSTrustBinding_IWSTrust13Sync"
    }
  }

  async function getXML(){
    return new Promise( (resolve, reject) => {
      request(requestOptions).then(response => {
        debug && fs.writeFileSync("login-reponse.xml", response);
        parseString(response, function(err, result){
          if(err){
            reject(err);
          } else {
            const encryptionKey = getFirstFromXML(response, "e:CipherValue");
            const encryptedData = getFirstFromXML(response, "xenc:CipherValue");
            const proofToken = getFirstFromXML(response, "trust:BinarySecret");
            // console.log(result)
            //console.log("result is back ")
            const responseObj = {
              raw: response,
              responseXml: result,
              encryptionKey,
              encryptedData,
              proofToken
            }
            resolve(responseObj);
          }
        })
      })
    })
  }

  const allres = await getXML()
  console.log("Returning from getXML")
  return allres
}


module.exports = {
  createLoginRequestXML
}
