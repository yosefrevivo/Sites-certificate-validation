const express = require("express");
const {
  setPrivateKey,
  setPublicKey,
  createSign,
  verifySign
} = require("digital-signature");

const PORT = process.env.PORT || 3001;
const SEVEN_DAYS = 1000 * 60 * 60 * 24 * 7;
const ROOT_PUB_KEY = "r0DgmpbU1USlCVUVTQ9S2P4si01hcVDmpk8O1SdXCU2TJagJcgB68k568w66m1NeiuuMIx";

const app = express();

const TRUSTED = [
  {
    name: "root",
    issuer: "root",
    signature: "",
    expired: new Date(Date.now() + SEVEN_DAYS),
    publicKey: ROOT_PUB_KEY,
  }
];

const MY_CERTIFICATE_CHAIN = {};
const MY_PRIVATE_KEY = Math.random().toString(36);
const MY_PUBLIC_KEY = Math.random().toString(36);
const MY_NAME = 'curClientName_example';

// check if given certificate is trusted
function isTrusted(certificate) {

  // check if certificate is expired
  if (!certificate || certificate.expired < new Date()) return false;

  // return if the cur client know the certificate.
  return TRUSTED.some(trusted => {
    return (
      certificate &&
      certificate.name === trusted.name &&
      certificate.issuer === trusted.issuer &&
      certificate.signature === trusted.signature &&
      certificate.publicKey === trusted.publicKey
    );
  });

}

// check if the given issuer is really the issuer of the given certificate.
function isIssuer(issuer, curr) {

  // set the pub key to the issuer certificate public key.
  setPublicKey(issuer.publicKey);

  // verify with the public key that the issuer is who he says he is.
  return verifySign(curr.name, curr.signature);

}

// check if full chain is trusted.
function isTrustedChain(chain, nameToVerify) {

  // if the chain is empty, return false.
  if(!chain || chain.length < 1) return false;

  // if the chain root is not trusted, return false.
  if(!isTrusted(chain[0])) return false;

  // iterate over the chain to check for each certificate if it is trusted.
  for(let i = 1; i < chain.length; i++) {

    // if is the last one, check if it is the nameToVerify.
    if(i === chain.length - 1 && chain[i].name !== nameToVerify) return false;

    // else, verify if the issuer is the issuer of the next certificate.
    if(!isIssuer(chain[i], chain[i + 1])) return false;

    // else, also if the current certificate expired, return false.
    if(chain[i].expired < new Date()) return false;

    // we know that the current certificate is trusted, so add it to the known Trusted certificates.
    TRUSTED.push(chain[i]);

  }

  // if all is ok, return true.
  return true;

}

// function that signs the given certificate.
function signCertificate(certificate) {

  // check if the certificate is valid.
  if(!certificate || !certificate.name || !certificate.publicKey) return false;

  // generate the signature.
  setPrivateKey(MY_PRIVATE_KEY);
  setPublicKey(MY_PUBLIC_KEY);
  const signature = createSign(certificate.name);

  // override the given certificate with the new signature.
  certificate.signature = signature;
  certificate.issuer = MY_NAME;
  certificate.expired = new Date(Date.now() + SEVEN_DAYS);

  // return the updated certificate.
  return certificate;
    
}

// return the current user certificate if he is an authorized signer, else null.
app.get("/getCertifications", (req, res) => {
  res.json(MY_CERTIFICATE_CHAIN);
});

// post req to sign a certificate.
app.get("/signCertificate", (req, res) => {
  
    // get the certificate to sign.
    const certificate = req.body;
    
    // return all the path certificates.
    res.json([...MY_CERTIFICATE_CHAIN, signCertificate(certificate)]);

});

// change my certificate chain to given post req certificate chain.
app.post("/setCertifications", (req, res) => {

  // get the certificate chain.
  const certificateChain = req.body;

  // return err if the curr certificate chain is untrusted.
  if(!isTrustedChain(certificateChain, MY_NAME)) return res.json({err: "untrusted chain"});

  // return not me err if the last in the chain is not me.
  if(certificateChain[certificateChain.length - 1].name !== MY_NAME) return res.json({err: "not me"});

  // set the certificate chain.
  MY_CERTIFICATE_CHAIN = certificateChain;

  // return that all is ok.
  res.json({ok: true});

});

app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});