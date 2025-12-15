'use strict';

const request = require('postman-request');
const { version: packageVersion } = require('./package.json');
const async = require('async');
const util = require('util');

const MAX_PARALLEL_LOOKUPS = 10;
const MAX_GN_TAGS = 2;
const USER_AGENT = `greynoise-polarity-integration-v${packageVersion}`;
const RAW_DATA_LIMIT = 250;

// noise and seen properties are used interchangeably
// noise/seen means the IP is an Internet Scanner

let Logger;
let requestWithDefaults;
let requestWithDefaultsAsync;

function startup(logger) {
  Logger = logger;
  let defaults = {};

  requestWithDefaults = request.defaults(defaults);
  requestWithDefaultsAsync = util.promisify(requestWithDefaults);
}

async function doLookup(entities, options, cb) {
  Logger.trace({ entities }, 'doLookup');
  const { validIps, validCves } = getValidIpsAndCves(entities);

  useGreynoiseApi(validIps, validCves, options, cb);
}

/**
 * Given an array of entity objects, only return valid IPs and CVEs.
 *
 * @param entities
 * @returns {*}
 */
const getValidIpsAndCves = (entities) => {
  const validIps = [];
  const validCves = [];

  entities.forEach((entity) => {
    if (entity.isIP && isValidIp(entity)) {
      validIps.push(entity);
    } else if (entity.type === 'cve') {
      validCves.push(entity);
    }
  });

  return { validIps, validCves };
};

const useGreynoiseApi = async (ips, cves, options, cb) => {
  const tasks = [];

  ips.forEach((entity) => {
    tasks.push((done) => {
      const requestOptions = {
        method: 'GET',
        uri: `${options.subscriptionUrl}/v3/ip/${entity.value}`,
        headers: {
          key: options.apiKey,
          'User-Agent': USER_AGENT
        },
        json: true
      };
      Logger.trace({ requestOptions }, 'IP request options');
      requestWithDefaults(requestOptions, (error, response, body) => {
        if (error) return done(error);
        done(null, { response, entity, type: 'ip' });
      });
    });
  });

  cves.forEach((entity) => {
    tasks.push((done) => {
      const requestOptions = {
        method: 'GET',
        uri: `${options.subscriptionUrl}/v1/cve/${entity.value}`,
        headers: {
          key: options.apiKey,
          'User-Agent': USER_AGENT
        },
        json: true
      };
      Logger.trace({ requestOptions }, 'CVE request options');
      requestWithDefaults(requestOptions, (error, response, body) => {
        if (error) return done(error);
        done(null, { response, entity, type: 'cve' });
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err }, 'Error in async.parallelLimit');
      return cb(err);
    }

    const lookupResults = [];

    results.forEach((result) => {
      const { response, entity, type } = result;
      const { statusCode, body } = response;

      Logger.trace({ response }, 'New Processing result');

      if (type === 'cve') {
        if (statusCode === 200 && body && body.id) {
          lookupResults.push({
            entity,
            data: {
              summary: getCveSummaryTags(body),
              details: {
                ...body,
                hasResult: true,
                usingApiKey: !!options.apiKey,
                apiService: 'unified'
              }
            }
          });
        } else if (statusCode === 404) {
          lookupResults.push({
            entity,
            data: {
              summary: ['CVE not found'],
              details: { hasResult: false, apiService: 'unified' }
            }
          });
        } else if (statusCode === 429) {
          lookupResults.push({
            entity,
            data: {
              summary: ['Lookup limit reached'],
              details: { limitHit: true, apiService: 'unified' }
            }
          });
        } else {
          lookupResults.push({ entity, data: null });
        }
        return;
      }

      // IP processing
      const error = handleAsyncHttpResponse(statusCode, body);
      if (error) {
        if (statusCode === 404) {
          if (!options.ignoreNonSeen) {
            lookupResults.push({
              entity,
              data: {
                summary: ['IP address has not been seen'],
                details: { hasResult: false, apiService: 'unified' }
              }
            });
          } else {
            lookupResults.push({ entity, data: null });
          }
        } else if (statusCode === 429) {
          lookupResults.push({
            entity,
            data: {
              summary: ['Lookup limit reached'],
              details: { limitHit: true, apiService: 'unified' }
            }
          });
        } else {
          lookupResults.push({ entity, data: null });
        }
        return;
      }

      lookupResults.push({
        entity,
        data: {
          summary: getSummaryTags(body),
          details: {
            ...body,
            apiService: 'unified',
            usingApiKey: !!options.apiKey,
            hasResult: true
          }
        }
      });
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
};

function errorToPojo(err) {
  return err instanceof Error
    ? {
        ...err,
        name: err.name,
        message: err.message,
        stack: err.stack,
        detail: err.message ? err.message : err.detail ? err.detail : 'Unexpected error encountered'
      }
    : err;
}

function handleAsyncHttpResponse(statusCode, body) {
  if (statusCode === 200) {
    return;
  } else if (statusCode === 400) {
    return {
      body,
      detail: 'Bad Requests.'
    };
  } else if (statusCode === 429) {
    return {
      body,
      detail: "Too many requests. You've hit the rate limit"
    };
  } else if (statusCode === 401) {
    return {
      body,
      detail: body && body.message ? body.message : 'Unauthorized: Please check your API key'
    };
  } else if (statusCode === 404) {
    return {
      body,
      detail: 'Not Found'
    };
  } else {
    // unexpected response received
    return {
      body,
      detail: `Unexpected HTTP status code [${statusCode}] received`
    };
  }
}

const isLoopBackIp = (entity) => {
  return entity.startsWith('127');
};

const isLinkLocalAddress = (entity) => {
  return entity.startsWith('169');
};

const isPrivateIP = (entity) => {
  return entity.isPrivateIP === true;
};

const isValidIp = (entity) => {
  return !(isLoopBackIp(entity.value) || isLinkLocalAddress(entity.value) || isPrivateIP(entity));
};

const getSummaryTags = (data) => {
  let tags = [];

  if (!data) {
    return ['IP address has not been seen'];
  }

  if (data.limitHit) {
    return ['Lookup limit reached'];
  }

  if (data.business_service_intelligence.found) {
    tags.push(`Category: ${data.business_service_intelligence.category}`);
    tags.push(`Trust Level: ${data.business_service_intelligence.trust_level}`);
    tags.push(`Name: ${data.business_service_intelligence.name}`);
  }

  if (data.internet_scanner_intelligence.found) {
    tags.push(`Classification: ${data.internet_scanner_intelligence.classification}`);
    tags.push(`Organization: ${data.internet_scanner_intelligence.metadata.organization}`);
  }

  return tags;
};

function getCveSummaryTags(data) {
  const tags = [];
  if (data && data.details && typeof data.details.cve_cvss_score === 'number') {
    tags.push(`CVSS: ${data.details.cve_cvss_score}`);
  }
  if (data && data.exploitation_details && data.exploitation_details.epss_score) {
    tags.push(`EPSS: ${data.exploitation_details.epss_score}`);
  }
  return tags;
}

function validateOptions(userOptions, cb) {
  let errors = [];

  if (
    typeof userOptions.subscriptionUrl.value !== 'string' ||
    (typeof userOptions.subscriptionUrl.value === 'string' && userOptions.subscriptionUrl.value.length === 0)
  ) {
    errors.push({
      key: 'subscriptionUrl',
      message: 'You must provide a Greynoise API URL.  The default value is "https://api.greynoise.io".'
    });
  }

  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'An API Key is required to use Greynoise.'
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
