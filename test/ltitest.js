
const assert = require('chai').assert;
const mocha = require('mocha')
const CryptoJS = require('crypto-js');
var aws4 = require('aws4')
const fs = require('fs');
const request = require('request-promise-native');
const argv = require('yargs').argv
var testdata;
var testjson;

describe(`VHL LTI Gateway Service Health Check`, function () {

  it('TC01: Validate LTI Service Response', async function () {
    this.timeout(30000);
    testdata = fs.readFileSync('./testdata/' + argv.env + '.json')
    testjson = JSON.parse(testdata)
    const nonce = generatenonce();
    const timestamp = generatetimestamp();
    const signature = generatesignature("qasecret", nonce, timestamp, "", testjson)
    var result = await methsubmit(nonce, timestamp, signature, testjson);
    console.log(result)
   console.log("ltiResponse: " + result)
    assert.include(result, "Validated Successfully", result);

  });

});
function getparams(nonce, timestamp, signature, testjson) {
  testjson.lti_params["oauth_nonce"] = nonce,
    testjson.lti_params["oauth_timestamp"] = timestamp,
    testjson.lti_params["oauth_signature"] = signature
  return testjson;
}


async function methsubmit(nonce, timestamp, signature, testjson) {
  let api_url =testjson.api_url;
  /** LTI GAteway API path */
  let api_path = testjson.api_path;
  /** LTI GAteway host value */
  let api_host = testjson.api_host;
  let bodyparams = getparams(nonce, timestamp, signature, testjson);

  const options = {
    url: api_url,
    path: api_path,
    method: 'POST',
    body: JSON.stringify(bodyparams),
    service: 'execute-api',
    host: api_host,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;',
    }
  };
  /** LTI Gateway API IAM user key and secret */
  aws4.sign(options, {
    accessKeyId: argv.AKeyId,
    secretAccessKey: argv.SAKey
  })
  try {
    const ltiResponse = await request(options);
    return ltiResponse;
  } catch (e) {
        return e;
    }
  }
function generatenonce() {
  return Math.random()
    .toString(36)
    .replace(/[^a-z]/, "")
    .substr(2);
}

function generatetimestamp() {
  return Math.floor(new Date().getTime() / 1000);
}

function generatesignature(consumer_secret, nonce, timestamp, signature, testjson) {
  let bodyparams = getparams(nonce, timestamp, signature, testjson).lti_params;
  let hitUrl = "https://dummyurl.com/";
  let method = "post";
  var toreturn = build_signature_raw(
    hitUrl,
    method,
    bodyparams,
    consumer_secret
  );
  return toreturn;
}

function build_signature_raw(req_url, method, params, consumer_secret) {
  var sig;
  sig = [
    method.toUpperCase(),
    special_encode(req_url),
    _clean_request_body(params),
  ];
  return sign_string(sig.join("&"), consumer_secret);
}

function special_encode(string) {
  return encodeURIComponent(string)
    .replace(/[!'()]/g, escape)
    .replace(/\*/g, "%2A");
}

function _clean_request_body(body) {
  var self = this;
  var cleanParams, encodeParam, out;
  out = [];
  encodeParam = function (key, val) {
    return key + "=" + special_encode(val);
  };
  cleanParams = function (params) {
    var i, key, len, val, vals;
    if (typeof params !== "object") {
      return;
    }
    for (key in params) {
      vals = params[key];
      if (key === "oauth_signature") {
        continue;
      }
      if (Array.isArray(vals) === true) {
        for (i = 0, len = vals.length; i < len; i++) {
          val = vals[i];
          out.push(encodeParam(key, val));
        }
      } else {
        out.push(encodeParam(key, vals));
      }
    }
  };
  cleanParams(body);
  return special_encode(out.sort().join("&"));
}

function sign_string(str, key) {
  key = key + "&";
  var hash = CryptoJS.HmacSHA1(str, key);
  var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);
  return hashInBase64
}
