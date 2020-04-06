const { createLoginRequestXML } = require("./helpers/getKeysForLogin");
const { getRequestToken } = require("./helpers/getRequestToken");
const signXml = require("./experiments/using-xml-crypto");
const crypto = require("crypto");
const fs = require("fs");
require('dotenv').config()

async function main(){
  // Setup variables. 
  const username =  process.env.TRIDION_USERNAME
  const password = process.env.TRIDION_PASSWORD
  const baseUrl = process.env.TRIDION_BASE_URL
  const created = new Date()
  const expires = new Date()
  expires.setMinutes(expires.getMinutes() + 5)
  const debug = true

  // Invoke Steps below. We are going to skip the steps 1 and 2 for now, since they are fairly simple operations

  // Step 1: Get WSDL file 
  // Step 2: Extract Login URL from WSDL file

  // Step 3: We will get the private and public keys
  const res = await createLoginRequestXML(baseUrl, username, password,debug, created, expires )
  const { raw, responseXml, encryptionKey, encryptedData, proofToken } = res; // In case we need.
  console.log("key is ", encryptionKey )
  // Step 4: 
  await getRequestToken(res, baseUrl, debug, created, expires).catch(err => console.log("error in step 4"));
}

// Experiments. 
/**
 * We want to to use xml-crypto to sign the xml correctly. However, we need input xml. We get the input xml from the response of step 3.
 */
signXml();
//main()
