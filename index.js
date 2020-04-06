const { createLoginRequestXML } = require("./helpers/getKeysForLogin");
const crypto = require("crypto");
require('dotenv').config()

function sha1HmacDigest(text, privateKey){
  if(!privateKey){
    throw new Error("Private key is required")
  }
  const hmac = crypto.createHmac('sha1',privateKey);
  hmac.update(text);
  return hmac.digest('base64')
}

async function main(){
  const username =  process.env.TRIDION_USERNAME
  const password = process.env.TRIDION_PASSWORD
  const baseUrl = process.env.TRIDION_BASE_URL
  const loginUrl = `${baseUrl}ISHSTS/issue/wstrust/mixed/username`

  // in Step 3: We will get the private and public keys
  const { raw, responseXml, encryptionKey, encryptedData, proofToken } = await createLoginRequestXML(baseUrl, username, password)
  console.log(encryptionKey);
}
main()
