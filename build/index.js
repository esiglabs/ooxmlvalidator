'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.OOXMLValidator = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }(); /**
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      * OOXML Validator module
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      *
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      * By Fotis Loukos <me@fotisl.com>
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      * @module ooxmlvalidator
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      */


var _pkijs = require('pkijs');

var pkijs = _interopRequireWildcard(_pkijs);

var _asn1js = require('asn1js');

var asn1js = _interopRequireWildcard(_asn1js);

var _xmlCore = require('xml-core');

var xmlcore = _interopRequireWildcard(_xmlCore);

var _xmldsigjs = require('xmldsigjs');

var xmldsigjs = _interopRequireWildcard(_xmldsigjs);

var _xadesjs = require('xadesjs');

var xadesjs = _interopRequireWildcard(_xadesjs);

var _pvutils = require('pvutils');

var pvutils = _interopRequireWildcard(_pvutils);

var _jszip = require('jszip');

var jszip = _interopRequireWildcard(_jszip);

var _eslutils = require('eslutils');

var eslutils = _interopRequireWildcard(_eslutils);

require('./webcrypto');

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

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
  if (!('UnsignedProperties' in signedXml) || !('UnsignedSignatureProperties' in signedXml.UnsignedProperties)) return null;

  var sigTimeStamp = void 0;
  signedXml.UnsignedProperties.UnsignedSignatureProperties.items.forEach(function (item) {
    if (item.localName === 'SignatureTimeStamp') sigTimeStamp = item;
  });

  if (typeof sigTimeStamp === 'undefined') return null;

  if (!('EncapsulatedTimeStamp' in sigTimeStamp)) return null;

  var encTimeStamp = void 0;
  sigTimeStamp.EncapsulatedTimeStamp.items.forEach(function (item) {
    if (item.localName === 'EncapsulatedTimeStamp') encTimeStamp = item;
  });

  if (typeof encTimeStamp === 'undefined') return null;

  var asn1 = asn1js.fromBER(encTimeStamp.Value.buffer);

  var contentInfo = void 0;
  try {
    contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  } catch (ex) {
    return null;
  }

  var validationData = void 0;
  try {
    validationData = signedXml.UnsignedProperties.UnsignedSignatureProperties.GetElement('TimeStampValidationData');
  } catch (ex) {
    return null;
  }

  var certEls = validationData.getElementsByTagNameNS('http://uri.etsi.org/01903/v1.3.2#', 'EncapsulatedX509Certificate');
  var certificates = [];
  for (var i = 0; i < certEls.length; i++) {
    var pem = certEls[i].textContent;
    var certDer = pvutils.stringToArrayBuffer(pvutils.fromBase64(pem));
    var _asn = asn1js.fromBER(certDer);
    var cert = new pkijs.Certificate({ schema: _asn.result });
    certificates.push(cert);
  }

  return {
    contentInfo: contentInfo,
    certificates: certificates
  };
}

/**
 * Load and parse content types.
 * @param {JSZip} zip - The OOXML file.
 * @return {Promise<ContentTypes>} A promise that is resolved with an object
 * containing all the necessary content type information.
 */
function loadContentTypes(zip) {
  return Promise.resolve().then(function () {
    return zip.file('[Content_Types].xml').async('string');
  }).then(function (cont) {
    var xmlDoc = xmlcore.Parse(cont);
    var types = xmlDoc.getElementsByTagName('Types');

    if (types.length !== 1) return undefined;

    var defaults = [];
    var overrides = [];

    var defaultEls = Array.prototype.slice.call(types[0].getElementsByTagName('Default'));
    defaultEls.forEach(function (el) {
      defaults.push({
        extension: el.getAttribute('Extension'),
        contentType: el.getAttribute('ContentType')
      });
    });

    var overrideEls = Array.prototype.slice.call(types[0].getElementsByTagName('Override'));
    overrideEls.forEach(function (el) {
      overrides.push({
        part: el.getAttribute('PartName'),
        contentType: el.getAttribute('ContentType')
      });
    });

    return {
      defaults: defaults,
      overrides: overrides
    };
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
  var contentType = void 0;

  contentTypes.overrides.forEach(function (override) {
    if (override.part === filename) contentType = override.contentType;
  });

  if (typeof contentType !== 'undefined') return contentType;

  var extension = filename.split('.').pop();

  contentTypes.defaults.forEach(function (def) {
    if (def.extension === extension) contentType = def.contentType;
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
  return Promise.resolve().then(function () {
    if (filename[0] === '/') filename = filename.slice(1);

    if (transforms.length === 0) return zip.file(filename).async('uint8array');else return zip.file(filename).async('string');
  }).then(function (cont) {
    var crypto = pkijs.getCrypto();

    if (transforms.length === 0) return crypto.digest(hashAlgo, cont);

    var xmlDoc = xmlcore.Parse(cont, 'application/xml');
    var doc = void 0;

    transforms.forEach(function (trans) {
      if (trans.name === 'relationshiptransform') {
        var relsEl = xmlDoc.getElementsByTagName('Relationships')[0];
        var rels = Array.prototype.slice.call(relsEl.getElementsByTagName('Relationship'));

        var finalRels = [];
        rels.forEach(function (rel) {
          var id = rel.getAttribute('Id');
          var type = rel.getAttribute('Type');

          if (trans.data.ids.indexOf(id) === -1 && trans.data.types.indexOf(type) === -1) {
            rel.parentNode.removeChild(rel);
          } else {
            // We must add TargetMode with the default value Internal if no
            // such attribute exists
            if (!rel.hasAttributeNS(undefined, 'TargetMode')) rel.setAttributeNS(undefined, 'TargetMode', 'Internal');
            finalRels.push(rel);
          }
        });

        finalRels.sort(function (a, b) {
          var leftId = a.getAttribute('Id');
          var rightId = b.getAttribute('Id');

          if (leftId === rightId) return 0;
          if (leftId < rightId) return -1;
          return 1;
        });

        finalRels.forEach(function (rel) {
          return relsEl.appendChild(rel);
        });
      } else if (trans.name === 'c14n') {
        // We assume c14n is always the last transformation.
        var transform = new xmldsigjs.XmlDsigC14NTransform();
        transform.LoadInnerXml(xmlDoc);
        doc = transform.GetOutput();
      }
    });

    if (typeof doc === 'undefined') doc = xmlDoc.toString();

    var tempBuffer = new ArrayBuffer(doc.length);
    var view = new Uint8Array(tempBuffer);

    for (var i = 0; i < doc.length; i++) {
      view[i] = doc.charCodeAt(i);
    }return crypto.digest(hashAlgo, tempBuffer);
  }).then(function (res) {
    var view1 = new Uint8Array(hash);
    var view2 = new Uint8Array(res);

    if (view1.length !== view2.length) return false;

    for (var i = 0; i < view1.length; i++) {
      if (view1[i] !== view2[i]) return false;
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
  var sigInfo = new eslutils.SignatureInfo(num);
  var sequence = Promise.resolve();
  var xmlDoc = void 0,
      signedXml = void 0,
      tsToken = void 0,
      contentTypes = void 0;

  sequence = sequence.then(function () {
    return loadContentTypes(zip);
  }).then(function (result) {
    contentTypes = result;
  }).then(function () {
    return zip.file('_xmlsignatures/sig' + num + '.xml').async('string');
  }).then(function (cont) {
    xmlDoc = xadesjs.Parse(cont, 'application/xml');
    var xmlSig = xmlDoc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');
    signedXml = new xadesjs.SignedXml(xmlDoc);
    signedXml.LoadXml(xmlSig[0]);

    sigInfo.cert = signedXml.signature.KeyInfo.items[0].X509CertificateList[0].simpl;

    return signedXml.Verify();
  }).then(function (res) {
    return res;
  }).catch(function (e) {
    return false;
  }).then(function (res) {
    sigInfo.sigVerified = res;

    var packageObject = void 0;
    Array.prototype.slice.call(xmlDoc.getElementsByTagName('Object')).forEach(function (obj) {
      if (obj.getAttribute('Id') === 'idPackageObject') packageObject = obj;
    });

    if (typeof packageObject === 'undefined') return [false];

    var refs = Array.prototype.slice.call(packageObject.getElementsByTagName('Reference'));
    var checkList = [];
    var err = false;
    refs.forEach(function (ref) {
      if (err === true) return;
      var uri = ref.getAttribute('URI');
      var n = uri.indexOf('?');
      var contentType = void 0;

      if (n !== -1) {
        var params = uri.substring(n + 1);
        uri = uri.substring(0, n);
        params.split('&').forEach(function (param) {
          var n2 = param.indexOf('=');
          var key = param.substring(0, n2);
          if (key === 'ContentType') contentType = param.substring(n2 + 1);
        });
      } else {
        err = true;
        return;
      }

      if (typeof contentType === 'undefined') {
        err = true;
        return;
      }

      if (getContentType(uri, contentTypes) !== contentType) {
        err = true;
        return;
      }

      var algorithm = xmldsigjs.CryptoConfig.CreateHashAlgorithm(ref.getElementsByTagName('DigestMethod')[0].getAttribute('Algorithm')).algorithm;

      // We assume the same algorithm is used for all files
      sigInfo.hashAlgorithm = algorithm.name;

      var b64Hash = ref.getElementsByTagName('DigestValue')[0].textContent;
      var hash = pvutils.stringToArrayBuffer(pvutils.fromBase64(b64Hash));

      var transforms = [];
      var transformEls = Array.prototype.slice.call(ref.getElementsByTagName('Transforms'));
      transformEls.forEach(function (transformEl) {
        for (var i = 0; i < transformEl.childNodes.length; i++) {
          var transform = transformEl.childNodes[i];
          var ooxmlns = 'http://schemas.openxmlformats.org/package/2006';
          if (transform.getAttribute('Algorithm') === ooxmlns + '/RelationshipTransform') {
            var transformData = {
              ids: [],
              types: []
            };

            var idEls = transform.getElementsByTagNameNS(ooxmlns + '/digital-signature', 'RelationshipReference');
            for (var j = 0; j < idEls.length; j++) {
              transformData.ids.push(idEls[j].getAttribute('SourceId'));
            }var idTypes = transform.getElementsByTagNameNS(ooxmlns + '/digital-signature', 'RelationshipsGroupReference');
            for (var _j = 0; _j < idTypes.length; _j++) {
              transformData.types.push(idTypes[_j].getAttribute('SourceType'));
            }transforms.push({
              name: 'relationshiptransform',
              data: transformData
            });
          } else if (transform.getAttribute('Algorithm') === 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315') {
            transforms.push({
              name: 'c14n'
            });
          } else {
            err = true;
          }
        }
      });

      checkList.push({
        uri: uri,
        algorithm: algorithm,
        hash: hash,
        transforms: transforms
      });
    });
    if (err === true) return [false];

    return Promise.all(checkList.map(function (entry) {
      return validateFile(zip, entry.uri, entry.algorithm, entry.hash, entry.transforms);
    }));
  }).then(function (res) {
    sigInfo.hashVerified = res.reduce(function (a, b) {
      return a && b;
    });
  });

  trustedSigningCAs.forEach(function (truststore) {
    sequence = sequence.then(function () {
      return eslutils.verifyChain(sigInfo.cert, [], truststore.certificates);
    }).then(function (result) {
      sigInfo.signerVerified.push({
        name: truststore.name,
        status: result
      });
    });
  });

  sequence = sequence.then(function () {
    tsToken = extractTimestamp(signedXml);
    if (tsToken !== null) {
      sigInfo.hasTS = true;

      var tsSigned = new pkijs.SignedData({
        schema: tsToken.contentInfo.content
      });

      var transform = new xmldsigjs.XmlDsigC14NTransform();
      transform.LoadInnerXml(signedXml.XmlSignature.GetChild('SignatureValue'));
      var sigValueCanon = transform.GetOutput();
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
  }).then(function (result) {
    if (tsToken !== null) {
      sigInfo.tsVerified = result.signatureVerified;
      sigInfo.tsCert = result.signerCertificate;
    }
  }).catch(function (e) {
    if (tsToken !== null) {
      sigInfo.tsVerified = false;
      sigInfo.tsCert = e.signerCertificate;
    }
  });

  trustedTimestampingCAs.forEach(function (truststore) {
    sequence = sequence.then(function () {
      if (tsToken !== null) return eslutils.verifyChain(sigInfo.tsCert, [], truststore.certificates);
    }).then(function (result) {
      if (tsToken !== null) {
        sigInfo.tsCertVerified.push({
          name: truststore.name,
          status: result
        });
      }
    });
  });

  return sequence.then(function () {
    return sigInfo;
  });
}

/**
 * OOXML Validator class
 */

var OOXMLValidator = exports.OOXMLValidator = function () {
  /**
   * Load an OOXML file from a buffer.
   * @param {ArrayBuffer} buffer - The buffer containing the OOXML file.
   */
  function OOXMLValidator(buffer) {
    _classCallCheck(this, OOXMLValidator);

    /**
     * @type {eslutils.TrustStoreList}
     * @description Trusted document signing CAs.
     */
    this.trustedSigningCAs = new eslutils.TrustStoreList();
    /**
     * @type {eslutils.TrustStoreList}
     * @description Trusted document timestamping CAs.
     */
    this.trustedTimestampingCAs = new eslutils.TrustStoreList();
    /**
     * @type {eslutils.ValidationInfo}
     * @description A ValidationInfo object holding the validation results.
     */
    this.validationInfo = new eslutils.ValidationInfo();
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


  _createClass(OOXMLValidator, [{
    key: 'addSigningTruststore',
    value: function addSigningTruststore(truststore) {
      this.trustedSigningCAs.addTrustStore(truststore);
    }

    /**
     * Remove a trust store from the document signing trust stores by name.
     * @param {string} name - The name of the trust store to remove.
     */

  }, {
    key: 'removeSigningTruststore',
    value: function removeSigningTruststore(name) {
      this.trustedSigningCAs.removeTrustStore(name);
    }

    /**
     * Add a trust store to the timestamping trust stores.
     * @param {TrustStore} truststore - The trust store to add.
     */

  }, {
    key: 'addTimestampingTruststore',
    value: function addTimestampingTruststore(truststore) {
      this.trustedTimestampingCAs.addTrustStore(truststore);
    }

    /**
     * Remove a trust store from the document signing trust stores by name.
     * @param {string} name - The name of the trust store to remove.
     */

  }, {
    key: 'removeTimestampingTruststore',
    value: function removeTimestampingTruststore(name) {
      this.trustedTimestampingCAs.removeTrustStore(name);
    }

    /**
     * Validate the OOXML file.
     * @return {Promise<eslutils.ValidationInfo>} A promise that is resolved with
     * a ValidationInfo object containing the validation results.
     */

  }, {
    key: 'validate',
    value: function validate() {
      var _this = this;

      var sequence = Promise.resolve();

      sequence = sequence.then(function () {
        return jszip.loadAsync(_this.fileContents);
      }).then(function (zip) {
        _this.zip = zip;
        _this.validationInfo.isValid = true;

        var sigs = Object.keys(zip.files).filter(function (name) {
          return name.match(/_xmlsignatures\/sig[0-9]+.xml/);
        }).map(function (name) {
          return name.replace('_xmlsignatures/sig', '').replace('.xml', '');
        });
        if (sigs.length === 0) throw new Error('Unsigned OOXML file');

        _this.validationInfo.isSigned = true;

        return Promise.all(sigs.map(function (num) {
          return validateSig(zip, num, _this.trustedSigningCAs, _this.trustedTimestampingCAs);
        }));
      }, function (e) {
        throw new Error('Invalid OOXML file');
      }).then(function (res) {
        _this.validationInfo.signatures = res.slice();
      }).catch(function () {});

      return sequence.then(function () {
        return _this.validationInfo;
      });
    }
  }]);

  return OOXMLValidator;
}();
//# sourceMappingURL=index.js.map