/**
 * OOXML Validator module
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ooxmlvalidator
 */
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import * as xmldsigjs from 'xmldsigjs';
import * as xadesjs from 'xadesjs';
import * as pvutils from 'pvutils';
import * as jszip from 'jszip';
import './webcrypto';

/**
  * A trust store.
  * @typedef {Object} TrustStore
  * @property {string} name - The name of the trust store.
  * @property {Array<pkijs.Certificate>} certificates - All the certificates
  * contained in the trust store.
  */

/**
 * Trust store verification status.
 * @typedef {Object} TrustStoreStatus
 * @property {string} name - The name of the trust store.
 * @property {boolean} status - True if the certificate chains to this trust
 * store, false otherwise.
 */

/**
 * Timestamp token and associated certificates.
 * @typedef {Object} TimestampTokenCerts
 * @property {pkijs.ContentInfo} contentInfo - The timestamp token.
 * @property {Array<pkijs.Certificate>} certificates - The associated
 * certificates.
 */

/**
 * Hashing algorithm specification.
 * @typedef {Object} HashAlgorithm
 * @property {string} name - The name of the algorithm.
 */

/**
 * XML transformation specification.
 * @typedef {Object} Transformation
 * @typedef {string} name - The type of the transformation
 * (relationshiptransform or c14n).
 * @typedef {Object} data - Associated data based on the transformation.
 */

/**
 * Verify if a certificate chains to some trusted CAs.
 * @param {pkijs.Certificate} certificate - The certificate that will be
 * checked.
 * @param {Array<pkijs.Certificate>} chain - Additional certificates in the
 * chain.
 * @param {Array<pkijs.Certificate>} trustedCAs - The trusted CAs
 * @return {Promise<boolean>} A promise that is resolved with a boolean value
 * stating if the certificate was verified or not.
 */
function verifyChain(certificate, chain, trustedCAs) {
  if(certificate === null)
    return Promise.resolve(false);

  return Promise.resolve().then(() => {
    const certificateChainEngine = new pkijs.CertificateChainValidationEngine({
      certs: chain,
      trustedCerts: trustedCAs.filter(cert => typeof cert !== 'undefined')
    });
    certificateChainEngine.certs.push(certificate);

    return certificateChainEngine.verify();
  }).then(result => {
    return result.result;
  }, result => {
    return false;
  });
}

/**
 * Extract the timestamp from a signature.
 * @param {SignedXml} signedXml - The signed XML.
 * @return {TimestampTokenCerts} The signature and signing cert, or null if no
 * timestamp exists.
 */
function extractTimestamp(signedXml) {
  if(!('UnsignedProperties' in signedXml) ||
    !('UnsignedSignatureProperties' in signedXml.UnsignedProperties))
    return null

  let sigTimeStamp;
  signedXml.UnsignedProperties.UnsignedSignatureProperties.items
    .forEach(item => {
      if(item.localName === 'SignatureTimeStamp')
        sigTimeStamp = item;
    });

  if(typeof sigTimeStamp === 'undefined')
    return null;

  if(!('EncapsulatedTimeStamp' in sigTimeStamp))
    return null;

  let encTimeStamp;
  sigTimeStamp.EncapsulatedTimeStamp.items.forEach(item => {
    if(item.localName === 'EncapsulatedTimeStamp')
      encTimeStamp = item;
  });

  if(typeof encTimeStamp === 'undefined')
    return null;

  const asn1 = asn1js.fromBER(encTimeStamp.Value.buffer);

  let contentInfo;
  try {
    contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  } catch(ex) {
    return null;
  }

  let validationData;
  try {
    validationData = signedXml.UnsignedProperties.UnsignedSignatureProperties
      .GetElement('TimeStampValidationData')
  } catch(ex) {
    return null;
  }

  const certEls = validationData.getElementsByTagNameNS(
    'http://uri.etsi.org/01903/v1.3.2#', 'EncapsulatedX509Certificate');
  const certificates = [];
  for(let i = 0; i < certEls.length; i++) {
    const pem = certEls[i].textContent;
    const certDer = pvutils.stringToArrayBuffer(pvutils.fromBase64(pem));
    const asn1 = asn1js.fromBER(certDer);
    const cert = new pkijs.Certificate({ schema: asn1.result });
    certificates.push(cert);
  }

  return {
    contentInfo,
    certificates
  };
}

/**
 * Validate the hash of a file.
 * TODO: Also validate content types based on https://www.ecma-international.org/activities/Office%20Open%20XML%20Formats/Draft%20ECMA-376%203rd%20edition,%20March%202011/Office%20Open%20XML%20Part%202%20-%20Open%20Packaging%20Conventions.pdf.
 * @param {JSZip} zip - The OOXML file.
 * @param {string} filename - The filename.
 * @param {HashAlgorithm} hashAlgo - The hash algorithm.
 * @param {ArrayBuffer} hash - The expected hash of the file.
 * @param {Array<Transformation>} transforms - The transforms to be applied to
 * the file.
 * @return {Promise<boolean>} A promise that is resolved with true if the
 * hash has validated, otherwise false.
 */
function validateFile(zip, filename, hashAlgo, hash, transforms) {
  return Promise.resolve().then(() => {
    if(filename[0] === '/')
      filename = filename.slice(1);

    if(transforms.length === 0)
      return zip.file(filename).async('uint8array');
    else
      return zip.file(filename).async('string');
  }).then(cont => {
    const crypto = pkijs.getCrypto();

    if(transforms.length === 0)
      return crypto.digest(hashAlgo, cont);

    const xmlDoc = xadesjs.Parse(cont, 'application/xml');
    let doc;

    transforms.forEach(trans => {
      if(trans.name === 'relationshiptransform') {
        const relsEl = xmlDoc.getElementsByTagName('Relationships')[0];
        const rels = Array.prototype.slice.call(
          relsEl.getElementsByTagName('Relationship'));

        const finalRels = [];
        rels.forEach(rel => {
          const id = rel.getAttribute('Id');
          const type = rel.getAttribute('Type');

          if((trans.data.ids.indexOf(id) === -1) &&
            (trans.data.types.indexOf(type) === -1)) {
            rel.parentNode.removeChild(rel);
          } else {
            // We must add TargetMode with the default value Internal if no
            // such attribute exists
            if(!rel.hasAttributeNS(undefined, 'TargetMode'))
              rel.setAttributeNS(undefined, 'TargetMode', 'Internal');
            finalRels.push(rel);
          }
        });

        finalRels.sort((a, b) => {
          const leftId = a.getAttribute('Id');
          const rightId = b.getAttribute('Id');

          if(leftId === rightId)
            return 0;
          if(leftId < rightId)
            return -1;
          return 1;
        });

        finalRels.forEach(rel => relsEl.appendChild(rel));
      } else if(trans.name === 'c14n') {
        // We assume c14n is always the last transformation.
        const transform = new xmldsigjs.XmlDsigC14NTransform();
        transform.LoadInnerXml(xmlDoc);
        doc = transform.GetOutput();
      }
    });

    if(typeof doc === 'undefined')
      doc = xmlDoc.toString();

    const tempBuffer = new ArrayBuffer(doc.length);
    const view = new Uint8Array(tempBuffer);

    for(let i = 0; i < doc.length; i++)
      view[i] = doc.charCodeAt(i);

    return crypto.digest(hashAlgo, tempBuffer);
  }).then(res => {
    const view1 = new Uint8Array(hash);
    const view2 = new Uint8Array(res);

    if(view1.length !== view2.length)
      return false;

    for(let i = 0; i < view1.length; i++) {
      if(view1[i] !== view2[i])
        return false;
    }

    return true;
  });
}

/**
 * Validate a single signature.
 * @param {JSZip} zip - The OOXML file.
 * @param {integer} num - The number of the signature.
 * @param {Array<TrustStore>} trustedSigningCAs - Trusted document signing CAs.
 * @param {Array<TrustStore>} trustedTimestampingCAs - Trusted document
 * timestamping CAs.
 * @return {Promise<SignatureInfo>} A promise that is resolved with a
 * SignatureInfo object containing information about the signature.
 */
function validateSig(zip, num, trustedSigningCAs, trustedTimestampingCAs) {
  const sigInfo = new SignatureInfo(num);
  let sequence = Promise.resolve();
  let xmlDoc, signedXml, tsToken;

  sequence = sequence.then(() => {
    return zip.file(`_xmlsignatures/sig${num}.xml`).async('string');
  }).then(cont => {
    xmlDoc = xadesjs.Parse(cont, 'application/xml');
    const xmlSig = xmlDoc.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#', 'Signature');
    signedXml = new xadesjs.SignedXml(xmlDoc);
    signedXml.LoadXml(xmlSig[0]);

    sigInfo.cert = signedXml.signature.KeyInfo.items[0]
      .X509CertificateList[0].simpl;

    return signedXml.Verify();
  }).then(res => {
    return res;
  }).catch(e => {
    return false;
  }).then(res => {
    sigInfo.sigVerified = res;

    let packageObject;
    Array.prototype.slice.call(xmlDoc.getElementsByTagName('Object'))
      .forEach(obj => {
        if(obj.getAttribute('Id') === 'idPackageObject')
          packageObject = obj;
      });

    if(typeof packageObject === 'undefined')
      return [ false ];

    const refs = Array.prototype.slice.call(
      packageObject.getElementsByTagName('Reference'));
    const checkList = [];
    refs.forEach(ref => {
      let uri = ref.getAttribute('URI');
      const n = uri.indexOf('?');
      if(n !== -1)
        uri = uri.substring(0, n);

      const algorithm = xmldsigjs.CryptoConfig.CreateHashAlgorithm(ref
        .getElementsByTagName('DigestMethod')[0].getAttribute('Algorithm'))
        .algorithm;

      // We assume the same algorithm is used for all files
      sigInfo.hashAlgorithm = algorithm.name;

      const b64Hash = ref.getElementsByTagName('DigestValue')[0].textContent;
      const hash = pvutils.stringToArrayBuffer(pvutils.fromBase64(b64Hash));

      const transforms = [];
      const transformEls = Array.prototype.slice.call(
        ref.getElementsByTagName('Transforms'));
      transformEls.forEach(transformEl => {
        for(let i = 0; i < transformEl.childNodes.length; i++) {
          const transform = transformEl.childNodes[i];
          const ooxmlns = 'http://schemas.openxmlformats.org/package/2006';
          if(transform.getAttribute('Algorithm') ===
            `${ooxmlns}/RelationshipTransform`) {
            const transformData = {
              ids: [],
              types: []
            };

            const idEls = transform.getElementsByTagNameNS(
              `${ooxmlns}/digital-signature`, 'RelationshipReference');
            for(let j = 0; j < idEls.length; j++)
              transformData.ids.push(idEls[j].getAttribute('SourceId'));

            const idTypes = transform.getElementsByTagNameNS(
              `${ooxmlns}/digital-signature`, 'RelationshipsGroupReference');
            for(let j = 0; j < idTypes.length; j++)
              transformData.types.push(idTypes[j].getAttribute('SourceType'));

            transforms.push({
              name: 'relationshiptransform',
              data: transformData
            });
          } else if(transform.getAttribute('Algorithm') ===
            'http://www.w3.org/TR/2001/REC-xml-c14n-20010315') {
            transforms.push({
              name: 'c14n'
            });
          } else {
            return [ false ];
          }
        }
      });

      checkList.push({
        uri,
        algorithm,
        hash,
        transforms
      });
    });

    return Promise.all(checkList.map(entry =>
      validateFile(zip, entry.uri, entry.algorithm, entry.hash,
        entry.transforms)));
  }).then(res => {
    sigInfo.hashVerified = res.reduce((a, b) => a && b);
  });

  trustedSigningCAs.forEach(truststore => {
    sequence = sequence.then(() => verifyChain(sigInfo.cert, [],
      truststore.certificates)).then(result => {
      sigInfo.signerVerified.push({
        name: truststore.name,
        status: result
      });
    });
  });

  sequence = sequence.then(() => {
    tsToken = extractTimestamp(signedXml);
    if(tsToken !== null) {
      sigInfo.hasTS = true;

      const tsSigned = new pkijs.SignedData({
        schema: tsToken.contentInfo.content
      });

      const transform = new xmldsigjs.XmlDsigC14NTransform();
      transform.LoadInnerXml(signedXml.XmlSignature.GetChild('SignatureValue'));
      let sigValueCanon = transform.GetOutput();
      // According to https://www.w3.org/TR/REC-xml/#sec-line-ends, parsers
      // should convert any EOL to \n. This fixes a bug in an older xmldsig
      // version.
      sigValueCanon = sigValueCanon.replace(/&#xD;/g, '');

      return tsSigned.verify({
        signer: 0,
        data: pvutils.stringToArrayBuffer(sigValueCanon),
        checkChain: false,
        extendedMode: true
      });
    } else {
      return false;
    }
  }).then(result => {
    if(tsToken !== null) {
      sigInfo.tsVerified = result.signatureVerified;
      sigInfo.tsCert = result.signerCertificate;
    }
  }).catch(e => {
    console.log(e);
    if(tsToken !== null) {
      sigInfo.tsVerified = false;
      sigInfo.tsCert = e.signerCertificate;
    }
  });

  trustedTimestampingCAs.forEach(truststore => {
    sequence = sequence.then(() => {
      if(tsToken !== null)
        return verifyChain(sigInfo.tsCert, [], truststore.certificates);
    }).then(result => {
      if(tsToken !== null) {
        sigInfo.tsCertVerified.push({
          name: truststore.name,
          status: result
        });
      }
    });
  });

  return sequence.then(() => sigInfo);
}

/**
 * Object validation information.
 */
export class ValidationInfo {
  /**
   * Generate an empty ValidationInfo object.
   * @constructor
   */
  constructor() {
    /**
     * @type {boolean}
     * @description A valid file.
     */
    this.isValid = false;
    /**
     * @type {boolean}
     * @description A signed file.
     */
    this.isSigned = false;
    /**
     * @type {Array<SignatureInfo>}
     * @description Validation information for all signatures.
     */
    this.signatures = [];
  }

  /**
   * Check if all signatures have been verified.
   */
  get sigVerified() {
    let verified = true;

    this.signatures.forEach(sigInfo => {
      verified &= sigInfo.sigVerified;
    });

    return verified;
  }

  /**
   * Check if all hashes correspond to the signed data.
   */
  get hashVerified() {
    let verified = true;

    this.signatures.forEach(sigInfo => {
      verified &= sigInfo.hashVerified;
    });

    return verified;
  }

  /**
   * Check if all signers have been verified against a truststore.
   * @param {string} signingTruststore - The name of the signing truststore.
   * @param {string} timestampingTruststore - The name of the timestamping
   * truststore.
   * @return {boolean} True if the file was verified against both truststores,
   * false otherwise.
   */
  isSignersVerified(signingTruststore, timestampingTruststore) {
    let verified = true;

    this.signatures.forEach(sigInfo => {
      verified &= sigInfo.isSignersVerified(signingTruststore,
        timestampingTruststore);
    });

    return verified;
  }
}

/**
 * Single signature validation information.
 */
export class SignatureInfo {
  /**
   * Generate an empty SignatureInfo object.
   * @param {Object} id - The signature's identifier.
   * @constructor
   */
  constructor(id) {
    /**
     * @type {Object}
     * @description An identifier for the signature.
     */
    this.id = id;
    /**
     * @type {boolean}
     * @description Signed hash has been verified.
     */
    this.sigVerified = false;
    /**
     * @type {boolean}
     * @description The hash corresponds to the signed data.
     */
    this.hashVerified = false;
    /**
     * @type {string}
     * @description The algorithm that was used to hash the data.
     */
    this.hashAlgorithm = '';
    /**
     * @type {Array<TrustStoreStatus>}
     * @description Signer certificate chains to a trusted signing CA.
     */
    this.signerVerified = [];
    /**
     * @type {boolean}
     * @description A timestamped OOXML file.
     */
    this.hasTS = false;
    /**
     * @type {boolean}
     * @description The timestamp has been verified.
     */
    this.tsVerified = false;
    /**
     * @type {Array<TrustStoreStatus>}
     * @description The certificate of the timestamp chains to a trusted
     * timestamping CA.
     */
    this.tsCertVerified = [];
    /**
     * @type {pkijs.Certificate}
     * @description The signer's certificate.
     */
    this.cert = null;
    /**
     * @type {pkijs.Certificate}
     * @description The timestamp authority's certificate.
     */
    this.tsCert = null;
  }

  /**
   * Check if the file verified was a valid signed OOXML whose signature and
   * signed hash have been verified.
   */
  get isValidSigned() {
    return this.isValid & this.isSigned & this.sigVerified & this.hashVerified;
  }

  /**
   * Check if the file verified was a valid signed and timestamped OOXML whose
   * signature, signed hash and timestamp have been verified.
   */
  get isValidSignedTimestamped() {
    return this.isValid & this.isSigned & this.sigVerified &
      this.hashVerified & this.hasTS & this.tsVerified;
  }

  /**
   * Check if the signer has been verified against a truststore. If the file is
   * timestamped, then the timestamp signer will also be checked against another
   * truststore.
   * @param {string} signingTruststore - The name of the signing truststore.
   * @param {string} timestampingTruststore - The name of the timestamping
   * truststore.
   * @return {boolean} True if the file was verified against both truststores,
   * false otherwise.
   */
  isSignersVerified(signingTruststore, timestampingTruststore) {
    if(!this.isValid || !this.isSigned)
      return false;

    let verified = false;
    this.signerVerified.forEach(signer => {
      if(signer.name === signingTruststore)
        verified = signer.status;
    });
    if(verified === false)
      return false;

    if(this.hasTS) {
      verified = false;
      this.tsCertVerified.forEach(signer => {
        if(signer.name === timestampingTruststore)
          verified = signer.status;
      });
      if(verified === false)
        return false;
    }

    return true;
  }
};

/**
 * OOXML Validator class
 */
export class OOXMLValidator {
  /**
   * Load an OOXML file from a buffer.
   * @param {ArrayBuffer} buffer - The buffer containing the OOXML file.
   */
  constructor(buffer) {
    /**
     * @type {Array<TrustStore>}
     * @description Trusted document signing CAs.
     */
    this.trustedSigningCAs = [];
    /**
     * @type {Array<TrustStore>}
     * @description Trusted document timestamping CAs.
     */
    this.trustedTimestampingCAs = [];
    /**
     * @type {ValidationInfo}
     * @description A ValidationInfo object holding the validation results.
     */
    this.ooxmlInfo = new ValidationInfo();
    /**
     * @type {ArrayBuffer}
     * @description The contents of the OOXML file.
     */
    this.fileContents = buffer;
    /**
     * @type {JSZip}
     * @description The file as a zip structure.
     */
    this.zip = null;
  }

  /**
   * Add a trust store to the document signing trust stores.
   * @param {TrustStore} truststore - The trust store to add.
   */
  addSigningTruststore(truststore) {
    this.trustedSigningCAs.push(truststore);
  }

  /**
   * Remove a trust store from the document signing trust stores by name.
   * @param {string} name - The name of the trust store to remove.
   */
  removeSigningTruststore(name) {
    let idx;

    for(idx = 0; idx < this.trustedSigningCAs.length; idx++) {
      if(this.trustedSigningCAs[idx].name === name) {
        this.trustedSigningCAs.splice(idx, 1);
        idx--;
      }
    }
  }

  /**
   * Add a trust store to the timestamping trust stores.
   * @param {TrustStore} truststore - The trust store to add.
   */
  addTimestampingTruststore(truststore) {
    this.trustedTimestampingCAs.push(truststore);
  }

  /**
   * Remove a trust store from the document signing trust stores by name.
   * @param {string} name - The name of the trust store to remove.
   */
  removeTimestampingTruststore(name) {
    let idx;

    for(idx = 0; idx < this.trustedTimestampingCAs.length; idx++) {
      if(this.trustedTimestampingCAs[idx].name === name) {
        this.trustedTimestampingCAs.splice(idx, 1);
        idx--;
      }
    }
  }

  /**
   * Validate the OOXML file.
   * @return {Promise<ValidationInfo>} A promise that is resolved with an
   * ValidationInfo object containing the validation results.
   */
  validate() {
    let sequence = Promise.resolve();

    sequence = sequence.then(() => jszip.loadAsync(this.fileContents))
      .then(zip => {
        this.zip = zip;
        this.ooxmlInfo.isValid = true;

        const sigs = Object.keys(zip.files).filter(name =>
          name.match(/_xmlsignatures\/sig[0-9]+.xml/)).map(name =>
          name.replace('_xmlsignatures/sig', '').replace('.xml', ''));
        if(sigs.length === 0)
          throw new Error('Unsigned OOXML file');

        this.ooxmlInfo.isSigned = true;

        return Promise.all(sigs.map(num => validateSig(zip, num,
          this.trustedSigningCAs, this.trustedTimestampingCAs)));
      }, e => {
        throw new Error('Invalid OOXML file');
      }).then(res => {
        this.ooxmlInfo.signatures = res.slice();
      }).catch(() => {});

    return sequence.then(() => this.ooxmlInfo);
  }
}
