const crypto = require("crypto");

function sha1HmacDigest(text, privateKey){
  if(!privateKey){
    throw new Error("Private key is required")
  }
  const hmac = crypto.createHmac('sha1',privateKey);
  hmac.update(text);
  return hmac.digest('base64')
}

module.exports = {
  sha1HmacDigest
}
