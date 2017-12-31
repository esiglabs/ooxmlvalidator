# Javascript signed OOXML Validator

This module allows you to validate signed OOXML files. It has support for checking signatures, timestamps and several other features.

# Installation

Use:

    npm run build

to build the module.

Use:

    npm run generate-docs

to generate the documentation

# Usage

You can use the module as follows:

    const ooxmlvalidator = require('ooxmlvalidator');
    let docx = new ooxmlvalidator.OOXMLValidator(fs.readFileSync('sample.docx'));
    docx.addSigningTruststore(loadTrustStoreFromJSON('sign.json'));
    docx.addTimestampingTruststore(loadTrustStoreFromJSON('timestamp.json'));
    docx.validate().then(result => console.log(result));

After validation you can also access the `validationInfo` field of the validator to get the validation results. Please note that validation does not finish after the `validate()` call since it returns a `Promise`, so it's better to use `Promise` chaining or `await` in async functions.

# License

Copyright (c) 2017, Fotis Loukos
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

