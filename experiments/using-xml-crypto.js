const fs = require("fs");
const xpath = require('xpath')
const dom = require('xmldom').DOMParser
var SignedXml = require('xml-crypto').SignedXml	  



// XML Crypto is a library that's designed to sign a xml properly. 

const signXml = function(){
  console.log("yes yes ")
  fs.read
  const xml = fs.readFileSync("xmlout.xml", "utf8");
  // lets experiment with xpath
  //console.log(xml)
  const doc = new dom().parseFromString(xml)
  const nodes = xpath.select("//*[name()='u:Timestamp']", doc)
  //console.log(nodes)

  // experiment with xml crypto
  const exampleKey = `
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL4vpoH3H3byehjj7RAGxefGRATiq4mXtzc9Q91W7uT0DTaFEbjzVch9aGsNjmLs4QHsoZbuoUmi0st4x5z9SQpTAKC/dW8muzacT3E7dJJYh03MAO6RiH4LG34VRTq1SQN6qDt2rCK85eG45NHI4jceptZNu6Zot1zyO5/PYuFpAgMBAAECgYAhspeyF3M/xB7WIixy1oBiXMLYisESFAumgfhwU2LotkVRD6rgNl1QtMe3kCNWa9pCWQcYkxeI0IzA+JmFu2shVvoRoL7eV4VCe1Af33z24E46+cY5grxNhHt/LyCnZKcitvCcrzXExUc5n6KngX0mMKgkW7skZDwsnKzhyUV8wQJBAN2bQMeASQVOqdfqBdFgC/NPnKY2cuDi6h659QN1l+kgX3ywdZ7KKftJo1G9l45SN9YpkyEd9zEO6PMFaufJvZUCQQDbtAWxk0i8BT3UTNWCT/9bUQROPcGZagwwnRFByX7gpmfkf1ImIvbWVXSpX68/IjbjSkTw1nj/Yj1NwFZ0nxeFAkEAzPhRpXVBlPgaXkvlz7AfvY+wW4hXHyyi0YK8XdPBi25XA5SPZiylQfjtZ6iN6qSfYqYXoPT/c0/QJR+orvVJNQJBANhRPNXljVTK2GDCseoXd/ZiI5ohxg+WUaA/1fDvQsRQM7TQA4NXI7BO/YmSk4rW1jIeOxjiIspY4MFAIh+7UL0CQFL6zTg6wfeMlEZzvgqwCGoLuvTnqtvyg45z7pfcrg2cHdgCXIy9kErcjwGiu6BOevEA1qTWRk+bv0tknWvcz/s=
-----END PRIVATE KEY-----
`
  const sig = new SignedXml()
  sig.addReference("//*[name()='u:Timestamp']")
  sig.signingKey = exampleKey
  sig.computeSignature(xml)
  fs.writeFileSync("signed.xml", sig.getSignedXml())

}

module.exports = signXml
