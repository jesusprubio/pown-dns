/*
  Copyright Jesús Pérez <jesusprubio@fsf.org>
            Sergio García <s3rgio.gr@gmail.com>

  This code may only be used under the MIT license found at
  https://opensource.org/licenses/MIT.
*/

'use strict';

// To test:
// - https://digi.ninja/projects/zonetransferme.php
// - POWN_ROOT=./ pown dns -t zonetransfer.me -s 81.4.108.41 -a


const defaults = {
  server: '198.101.242.72',
  rtype: 'ANY',
  rate: 10,
  bing: false,
  axfr: false,
};


exports.yargs = {
  command: 'dns',
  describe: 'DNS lookup (and reverse), brute-forcing and zone transfer.',

  builder: {
    target: {
      type: 'string',
      alias: 't',
      describe: 'Domain (resolution) or IP address (reverse)',
    },
    server: {
      type: 'string',
      alias: 's',
      describe: `DNS server to use (reverse) [${defaults.server}] (DuckDuckGo)`,
    },
    rtype: {
      type: 'string',
      alias: 'r',
      describe: 'Type of DNS records to resolve (if a domain passed as "rhost")' +
                ` [${defaults.rtype}] (all record types)`,
    },
    // TODO: Send a PR to allow to use external files.
    brute: {
      type: 'string',
      alias: 'b',
      describe: 'Perform also a brute-force (if the target is a domain).' +
                'This options sets the dictionary for bruteforcing [top_50, top_100 ...].' +
                'Please check the library: https://github.com/skepticfx/subquest' +
                'In this case you need to set the server, the default is not going to be used.',
    },
    rate: {
      type: 'number',
      alias: 'ra',
      describe: `Number of requests at the same time (when brute-force) [${defaults.rate})]`,
    },
    bing: {
      type: 'boolean',
      alias: 'bi',
      describe: `Use Bing search to list all possible subdomains [${defaults.bing})]`,
    },
    axfr: {
      type: 'boolean',
      alias: 'a',
      describe: `Try a zone transfer [${defaults.axfr})]`,
    },
    // TODO: Add support.
    // timeout: {
    //   type: 'number',
    //   alias: 't',
    //   describe: `Request timeout [${defaults.timeout}]`,
    // },
  },

  handler: (argv = {}) => {
    // TODO: Add a rule to force them always here at the init.
    /* eslint-disable global-require */
    const net = require('net');
    const dns = require('dns');

    // const lodash = require('lodash');
    const promisify = require('es6-promisify');
    const logger = require('pown-logger');
    const axfr = require('dns-axfr').resolveAxfr;
    const subquest = require('subquest');

    const resolveAny = require('./lib/resolveAny');
    /* eslint-enable global-require */


    const dnsReverse = promisify(dns.reverse);
    const dnsAxfr = promisify(axfr);


    // TODO: get from yargs
    logger.title(this.yargs.command);

    if (!argv.target) { throw new Error('The option "target" is mandatory'); }

    const server = argv.server || defaults.server;
    const rtype = argv.rtype || defaults.rtype;

    dns.setServers([server]);

    // TODO: Check for private
    let isDomain = false;
    let req;
    if (net.isIP(argv.target)) {
      req = dnsReverse(argv.target);
    } else {
      isDomain = true;
      req = resolveAny(argv.target, rtype);
    }

    req
    .then(res => logger.result('Lookup', res))
    .catch((err) => { throw err; });

    if (!isDomain) { return; }

    const rate = argv.rate || defaults.rate;
    const dic = argv.brute || defaults.brute;
    const bing = argv.bing || defaults.bing;

    // We can do this in parallel.
    if (argv.brute || argv.axfr) {
      // if (server === defaults.server) {
      //   throw new Error('Please change the server, we love ducks :)');
      // }
    }

    if (argv.brute) {
      subquest.getSubDomains({
        host: argv.target,
        dnsServer: server,
        dictionary: dic,
        rateLimit: rate,
        bingSearch: bing,
      })
      .on('end', res => logger.result('Subdomains', res))
      .on('error', (err) => { throw err; });
    }

    if (argv.axfr) {
      const msg = 'Zone transfer';

      dnsAxfr(server, argv.target)
      .then((res) => {
        logger.result(msg);
        logger.chunks(res.answers);
      })
      .catch((err) => {
        // Expected result, not vulnerable.
        if (err === -3) {
          logger.result(msg, []);
        } else {
          throw err;
        }
      });
    }
  },
};
