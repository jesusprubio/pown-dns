/*
  Copyright Jesús Pérez <jesusprubio@fsf.org>
            Sergio García <s3rgio.gr@gmail.com>

  This code may only be used under the MIT license found at
  https://opensource.org/licenses/MIT.
*/

'use strict';

const dns = require('dns');
const pMap = require('p-map');
const promisify = require('es6-promisify');

const dnsResolve = promisify(dns.resolve);


// TODO: Get dynamically (if possible)
const recordTypes = [
  'A', 'AAAA', 'MX', 'TXT', 'SRV', 'PTR', 'NS',
  'CNAME', 'SOA', 'NAPTR',
];


// DNS resolve adding the record type "ANY". The core should
// eventually support it and this method should not be needed:
// https://nodejs.org/api/dns.html#dns_dns_resolve_hostname_rrtype_callback
module.exports = (domain, rtype) =>
  new Promise((resolve) => {
    let finalTypes;

    // Single record type support.
    if (rtype !== 'ANY') {
      finalTypes = [rtype];
    } else {
      finalTypes = recordTypes;
    }

    // We can't return the result of the ".map" directly because we
    // need to massage the returned data.
    const result = {};
    const request = type =>
      new Promise((resolveReq) => {
        dnsResolve(domain, type)
        .then((res) => {
          result[type] = res;
          resolveReq();
        })
        // We resolve the promise instead of reject to avoid a break.
        // We didn't store the result in this case.
        .catch(() => resolveReq());
      });

    // The supported ones are less than 10.
    pMap(finalTypes, request, { concurrency: 10 })
    .then(() => resolve(result));
  });
