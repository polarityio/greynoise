'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

const MAX_PARALLEL_LOOKUPS = 10;

let Logger;
let requestWithDefaults;

function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.debug(entities);

  entities.forEach((entity) => {
    //do the lookup
    let requestOptions = {
      method: 'GET',
      uri: options.url + '/context/' + entity.value,
      headers: {
        key: options.apiKey
      },
      json: true
    };

    Logger.trace({ uri: options }, 'Request URI');

    tasks.push(function(done) {
      requestWithDefaults(requestOptions, function(httpError, res, body) {
        Logger.trace({ body: body, statusCode: res.statusCode }, 'Result of Lookup');

        if (httpError) {
          return done({ detail: 'Unexpected HTTP request error', httpError });
        }

        let result = {};
        let error = null;

        if (res.statusCode === 200) {
          if (options.ignoreNonSeen && body.seen === false) {
            // cache these as a miss
            result = {
              entity: entity,
              body: null
            };
          } else {
            result = {
              entity: entity,
              body: body
            };
          }
        } else if (res.statusCode === 400) {
          result = {
            entity: entity,
            body: null
          };
        } else if (res.statusCode === 429) {
          error = {
            body,
            detail: "Too many requests.  You've hit the rate limit"
          };
        } else if (res.statusCode === 401) {
          error = {
            body,
            detail: 'Unauthorized: Please check your API key'
          };
        } else {
          // unexpected response received
          error = {
            body,
            detail: `Unexpected HTTP status code [${res.statusCode}] received`
          };
        }

        done(error, result);
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body === null || (Array.isArray(result.body) && result.body.length === 0)) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: [],
            details: result.body
          }
        });
      }
    });

    cb(null, lookupResults);
  });
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a valid API key'
    });
  }
  cb(null, errors);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
