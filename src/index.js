/**
 * OOXML Validator module
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ooxmlvalidator
 */
import { Certificate, ContentInfo, SignedData, getCrypto } from 'pkijs';
import { fromBER } from 'asn1js';
import { Parse as XmlCoreParse } from 'xml-core';
import { CryptoConfig, XmlDsigC14NTransform } from 'xmldsigjs';
import { Parse as XadesjsParse, SignedXml } from 'xadesjs';
import { fromBase64, stringToArrayBuffer } from 'pvutils';
import { loadAsync } from 'jszip';
import { SignatureInfo, TrustStoreList, ValidationInfo, verifyChain } from 'eslutils';
import './webcrypto';

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
 * @property {string} name - The type of the transformation
 * (relationshiptransform or c14n).
 * @property {Object} data - Associated data based on the transformation.
 */

/**
 * Default content type for a specific extension.
 * @typedef {Object} Default
 * @property {string} extension - The extension of the file.
 * @property {string} contentType - The content type.
 */

/**
 * Content type override for a specific file.
 * @typedef {Object} Override
 * @property {string} part - The name of the file.
 * @property {string} contentType - The content type.
 */

/**
 * Content types contained in the OOXML file.
 * @typedef {Object} ContentTypes
 * @property {Array<Default>} defaults - The default content types based on the
 * extension of the file.
 * @property {Array<Override>} overrides - Overrides for specific files.
 */

/**
 * Extract the timestamp from a signature.
 * @param {SignedXml} signedXml - The signed XML.
 * @return {TimestampTokenCerts} The signature and signing cert, or null if no
 * timestamp exists.
 */
function extractTimestamp(signedXml) {
  if(!('UnsignedProperties' in signedXml) ||
    !('UnsignedSignatureProperties' in signedXml.UnsignedProperties))
    return null;

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

  const asn1 = fromBER(encTimeStamp.Value.buffer);

  let contentInfo;
  try {
    contentInfo = new ContentInfo({ schema: asn1.result });
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
    const certDer = stringToArrayBuffer(fromBase64(pem));
    const asn1 = fromBER(certDer);
    const cert = new Certificate({ schema: asn1.result });
    certificates.push(cert);
  }

  return {
    contentInfo,
    certificates
  };
}

/**
 * Load and parse content types.
 * @param {JSZip} zip - The OOXML file.
 * @return {Promise<ContentTypes>} A promise that is resolved with an object
 * containing all the necessary content type information.
 */
function loadContentTypes(zip) {
  return Promise.resolve().then(() => {
    return zip.file('[Content_Types].xml').async('string');
  }).then(cont => {
    const xmlDoc = XmlCoreParse(cont);
    const types = xmlDoc.getElementsByTagName('Types');

    if(types.length !== 1)
      return undefined;

    const defaults = [];
    const overrides = [];

    const defaultEls = Array.prototype.slice.call(
      types[0].getElementsByTagName('Default'));
    defaultEls.forEach(el => {
      defaults.push({
        extension: el.getAttribute('Extension'),
        contentType: el.getAttribute('ContentType')
      });
    });

    const overrideEls = Array.prototype.slice.call(
      types[0].getElementsByTagName('Override'));
    overrideEls.forEach(el => {
      overrides.push({
        part: el.getAttribute('PartName'),
        contentType: el.getAttribute('ContentType')
      });
    });

    return {
      defaults,
      overrides
    }
  });
}

/**
 * Find the content type of a file.
 * @param {string} filename - The filename.
 * @param {ContentTypes} contentTypes - The OOXML content types as a
 * ContentTypes object.
 * @return {string} The filename's content type.
 */
function getContentType(filename, contentTypes) {
  let contentType;

  contentTypes.overrides.forEach(override => {
    if(override.part === filename)
      contentType = override.contentType;
  });

  if(typeof contentType !== 'undefined')
    return contentType;

  const extension = filename.split('.').pop();

  contentTypes.defaults.forEach(def => {
    if(def.extension === extension)
      contentType = def.contentType;
  });

  return contentType;
}

/**
 * Validate the hash of a file.
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
    const crypto = getCrypto();

    if(transforms.length === 0)
      return crypto.digest(hashAlgo, cont);

    const xmlDoc = XmlCoreParse(cont, 'application/xml');
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
        const transform = new XmlDsigC14NTransform();
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
 * @param {eslutils.TrustStoreList} trustedSigningCAs - Trusted document
 * signing CAs.
 * @param {eslutils.TrustStoreList} trustedTimestampingCAs - Trusted document
 * timestamping CAs.
 * @return {Promise<eslutils.SignatureInfo>} A promise that is resolved with a
 * SignatureInfo object containing information about the signature.
 */
function validateSig(zip, num, trustedSigningCAs, trustedTimestampingCAs) {
  const sigInfo = new SignatureInfo(num);
  let sequence = Promise.resolve();
  let xmlDoc, signedXml, tsToken, contentTypes;

  sequence = sequence.then(() => loadContentTypes(zip)).then(result => {
    contentTypes = result;
  }).then(() => {
    return zip.file(`_xmlsignatures/sig${num}.xml`).async('string');
  }).then(cont => {
    xmlDoc = XadesjsParse(cont, 'application/xml');
    const xmlSig = xmlDoc.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#', 'Signature');
    signedXml = new SignedXml(xmlDoc);
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

    try {
      const unsignedSigProps = signedXml.UnsignedProperties.UnsignedSignatureProperties;
      unsignedSigProps.items.forEach(item => {
        if(item.localName !== 'CertificateValues')
          return;

        sigInfo.certBundle = [];
        if('EncapsulatedX509Certificates' in item) {
          item.EncapsulatedX509Certificates.items.forEach(rawCert => {
            const asn1 = fromBER(rawCert.Value.buffer);
            sigInfo.certBundle.push(new Certificate({ schema: asn1.result }));
          });
        }
      });
    } catch(ex) {
      // If there are no certs, ignore it.
    }

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
    let err = false;
    refs.forEach(ref => {
      if(err === true)
        return;
      let uri = ref.getAttribute('URI');
      const n = uri.indexOf('?');
      let contentType;

      if(n !== -1) {
        const params = uri.substring(n + 1);
        uri = uri.substring(0, n);
        params.split('&').forEach(param => {
          const n2 = param.indexOf('=');
          const key = param.substring(0, n2);
          if(key === 'ContentType')
            contentType = param.substring(n2 + 1);
        });
      } else {
        err = true;
        return;
      }

      if(typeof contentType === 'undefined') {
        err = true;
        return;
      }

      if(getContentType(uri, contentTypes) !== contentType) {
        err = true;
        return;
      }

      const algorithm = CryptoConfig.CreateHashAlgorithm(ref
        .getElementsByTagName('DigestMethod')[0].getAttribute('Algorithm'))
        .algorithm;

      // We assume the same algorithm is used for all files
      sigInfo.hashAlgorithm = algorithm.name;

      const b64Hash = ref.getElementsByTagName('DigestValue')[0].textContent;
      const hash = stringToArrayBuffer(fromBase64(b64Hash));

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
            err = true;
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
    if(err === true)
      return [ false ];

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
      sigInfo.tsCertBundle = tsToken.certificates.slice();

      const tsSigned = new SignedData({
        schema: tsToken.contentInfo.content
      });

      const transform = new XmlDsigC14NTransform();
      transform.LoadInnerXml(signedXml.XmlSignature.GetChild('SignatureValue'));
      let sigValueCanon = transform.GetOutput();
      // According to https://www.w3.org/TR/REC-xml/#sec-line-ends, parsers
      // should convert any EOL to \n. This fixes a bug in an older xmldsig
      // version.
      sigValueCanon = sigValueCanon.replace(/&#xD;/g, '');

      return tsSigned.verify({
        signer: 0,
        data: stringToArrayBuffer(sigValueCanon),
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
    if(tsToken !== null) {
      sigInfo.tsVerified = false;
      sigInfo.tsCert = e.signerCertificate;
    }
  });

  trustedTimestampingCAs.forEach(truststore => {
    sequence = sequence.then(() => {
      if(tsToken !== null)
        return verifyChain(sigInfo.tsCert, tsToken.certificates,
          truststore.certificates);
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
 * OOXML Validator class
 */
export class OOXMLValidator {
  /**
   * Load an OOXML file from a buffer.
   * @param {ArrayBuffer} buffer - The buffer containing the OOXML file.
   */
  constructor(buffer) {
    /**
     * @type {eslutils.TrustStoreList}
     * @description Trusted document signing CAs.
     */
    this.trustedSigningCAs = new TrustStoreList();
    /**
     * @type {eslutils.TrustStoreList}
     * @description Trusted document timestamping CAs.
     */
    this.trustedTimestampingCAs = new TrustStoreList();
    /**
     * @type {eslutils.ValidationInfo}
     * @description A ValidationInfo object holding the validation results.
     */
    this.validationInfo = new ValidationInfo();
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
    this.trustedSigningCAs.addTrustStore(truststore);
  }

  /**
   * Remove a trust store from the document signing trust stores by name.
   * @param {string} name - The name of the trust store to remove.
   */
  removeSigningTruststore(name) {
    this.trustedSigningCAs.removeTrustStore(name);
  }

  /**
   * Add a trust store to the timestamping trust stores.
   * @param {TrustStore} truststore - The trust store to add.
   */
  addTimestampingTruststore(truststore) {
    this.trustedTimestampingCAs.addTrustStore(truststore);
  }

  /**
   * Remove a trust store from the document signing trust stores by name.
   * @param {string} name - The name of the trust store to remove.
   */
  removeTimestampingTruststore(name) {
    this.trustedTimestampingCAs.removeTrustStore(name);
  }

  /**
   * Validate the OOXML file.
   * @return {Promise<eslutils.ValidationInfo>} A promise that is resolved with
   * a ValidationInfo object containing the validation results.
   */
  validate() {
    let sequence = Promise.resolve();

    sequence = sequence.then(() => loadAsync(this.fileContents))
      .then(zip => {
        this.zip = zip;
        this.validationInfo.isValid = true;

        const sigs = Object.keys(zip.files).filter(name =>
          name.match(/_xmlsignatures\/sig[0-9]+.xml/)).map(name =>
          name.replace('_xmlsignatures/sig', '').replace('.xml', ''));
        if(sigs.length === 0)
          throw new Error('Unsigned OOXML file');

        this.validationInfo.isSigned = true;

        return Promise.all(sigs.map(num => validateSig(zip, num,
          this.trustedSigningCAs, this.trustedTimestampingCAs)));
      }, e => {
        throw new Error('Invalid OOXML file');
      }).then(res => {
        this.validationInfo.signatures = res.slice();
      }).catch(() => {});

    return sequence.then(() => this.validationInfo);
  }
}
