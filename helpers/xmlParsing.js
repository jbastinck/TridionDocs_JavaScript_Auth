const getFirstFromXML = function(xmlRawStr, tag, returnXML){
  // Given a raw xml string, it finds string matching <tag> and </tag> and returns the value inside in string format. 
  const startTag = xmlRawStr.indexOf(`<${tag}`) // not including the > because there could be parameters.
  const endTag = xmlRawStr.indexOf(`</${tag}>`) 


  // console.log(startTag, endTag)

  const xml = xmlRawStr.substring(startTag , endTag + `</${tag}>`.length)
  const content = xmlRawStr.substring(startTag + `</${tag}>`.length, endTag)

  if(returnXML){
    return xml
  }
  return content

}

module.exports = {
  getFirstFromXML
}
