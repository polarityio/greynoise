'use strict';

const request = require('postman-request');
const config = require('./config/config');
const { version: packageVersion } = require('./package.json');
const async = require('async');
const fs = require('fs');
const _ = require('lodash');
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

function startup (logger) {
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
  requestWithDefaultsAsync = util.promisify(requestWithDefaults);
}

async function doLookup (entities, options, cb) {
  Logger.trace({ entities }, 'doLookup');
  const { validIps, validCves } = getValidIpsAndCves(entities);

  if (options.subscriptionApi) {
    // subscription API searches both IPs and CVEs
    try {
      await useGreynoiseSubscriptionApi(validIps, validCves, options, cb);
    } catch (error) {
      Logger.error(error);
      cb(errorToPojo(error));
    }
  } else {
    // community api only searches IPs
    useGreynoiseCommunityApi(validIps, options, cb);
  }
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

const useGreynoiseCommunityApi = (entities, options, cb) => {
  let lookupResults = [];
  let tasks = [];

  entities.forEach((entity) => {
    let requestOptions = {
      method: 'GET',
      uri: options.subscriptionUrl + '/v3/community/' + entity.value,
      headers: {
        key: options.apiKey,
        'User-Agent': USER_AGENT
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'request options');

    tasks.push(function (done) {
      requestWithDefaults(requestOptions, function (error, res, body) {
        let processedResult = handleRestError(error, entity, res, body);

        if (processedResult.error) {
          done(processedResult);
          return;
        }

        done(null, processedResult);
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      Logger.trace({ result }, 'Community Result');
      if ((result.body === null || result.body.length === 0) && options.ignoreNonSeen) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: getCommunitySummaryTags(result.body),
            details: {
              ...result.body,
              apiService: 'community',
              usingApiKey: options.apiKey ? true : false,
              hasResult: result.body !== null
            }
          }
        });
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
};

function handleRestError (error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }

  if (res.statusCode === 200) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 400) {
    if (body.message.includes('Request is not a valid routable IPv4 address')) {
      result = {
        entity: entity,
        body: null
      };
    } else {
      result = {
        error: 'Bad Request',
        detail: body.message
      };
    }
  } else if (res.statusCode === 404) {
    // 'IP not observed scanning the internet or contained in RIOT data set.'
    result = {
      entity: entity,
      body: null
    };
  } else if (res.statusCode === 429) {
    result = {
      entity: entity,
      body: { limitHit: true }
    };
  } else {
    result = {
      error: 'Unexpected Error',
      statusCode: res ? res.statusCode : 'Unknown',
      detail: 'An unexpected error occurred',
      body
    };
  }

  return result;
}

function errorToPojo (err) {
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

const useGreynoiseSubscriptionApi = async (ips, cves, options, cb) => {
  let lookupResults = [];
  let tasks = [];

  if (ips.length > 0) {
    // Returns an array of results for each IP that specifies whether or not
    // the specific IP is in the riot or noise datasets.  If data exists for
    // either dataset we then lookup the actual data.
    const ipMultiResults = await getIpDataMulti(ips, options);

    ipMultiResults.forEach((ip) => {
      tasks.push(async () => {
        let results = {};

        results.entity = ip.entity;

        if (ip.data.noise) {
          results.noiseData = await getIpNoiseData(ip.entity, options);
        }

        if (ip.data.riot) {
          results.riotData = await getIpRiotData(ip.entity, options);
        }

        return results;
      });
    });
  }

  cves.forEach((cveEntity) => {
    tasks.push((done) => {
      getCveData(cveEntity, options, done);
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) return cb(err);

    results.forEach((result) => {
      if (result.entity.type === 'cve') {
        Logger.trace({ result }, 'CVE Result');
        if (result && result.stats) {
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: getCveSummaryTags(result),
              details: {
                stats: result.stats,
                hasResult: true,
                apiService: 'subscription'
              }
            }
          });
        } else {
          lookupResults.push({
            entity: result.entity,
            data: null
          });
        }
        return;
      }

      if (result.entity.type === 'IPv4' && (result.riotData || result.noiseData)) {
        let details = {
          ...result.riotData,
          ...result.noiseData,
          apiService: 'subscription',
          hasResult: true
        };

        // For raw data fields we display in the template we want to truncate them as they
        // be very long and cause rendering issues.

        let scanData = _.get(details, 'raw_data.scan', []);
        if (scanData.length > RAW_DATA_LIMIT) {
          details.raw_data.scan = scanData.slice(0, RAW_DATA_LIMIT);
          details.raw_data.truncatedScan = true;
        }

        let ja3Data = _.get(details, 'raw_data.ja3', []);
        if (ja3Data.length > RAW_DATA_LIMIT) {
          details.raw_data.ja3 = ja3Data.slice(0, RAW_DATA_LIMIT);
          details.raw_data.truncatedJa3 = true;
        }

        let webPaths = _.get(details, 'raw_data.web.paths', []);
        if (webPaths.length > RAW_DATA_LIMIT) {
          details.raw_data.web.paths = webPaths.slice(0, RAW_DATA_LIMIT);
          details.raw_data.truncatedWebPaths = true;
        }

        let userAgents = _.get(details, 'raw_data.web.useragents', []);
        if (webPaths.length > RAW_DATA_LIMIT) {
          details.raw_data.web.useragents = userAgents.slice(0, RAW_DATA_LIMIT);
          details.raw_data.truncatedUserAgents = true;
        }

        let hassh = _.get(details, 'raw_data.hassh', []);
        if (webPaths.length > RAW_DATA_LIMIT) {
          details.raw_data.hassh = hassh.slice(0, RAW_DATA_LIMIT);
          details.raw_data.truncatedHassh = true;
        }

        Logger.trace({ details }, 'IPPPPPPPPP');

        /// if community on this raw_data wont be there.
        let rawDataLength = scanData.length + ja3Data.length + webPaths.length + userAgents.length + hassh.length;

        if (_.get(details, '.raw_data')) {
          details.raw_data.totalRawData = rawDataLength;
        }

        lookupResults.push({
          entity: result.entity,
          data: {
            summary: getSubscriptionSummaryTags(details),
            details
          }
        });
      } else if (!options.ignoreNonSeen) {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: ['IP address has not been seen'],
            details: {
              hasResult: false
            }
          }
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      }
    });

    Logger.trace({ lookupResults }, 'response returned to client');
    cb(null, lookupResults);
  });
};

const getIpDataMulti = async (ipEntities, options) => {
  const ipMap = new Map();
  const ipStrings = [];

  ipEntities.forEach((entity) => {
    ipStrings.push(entity.value);
    ipMap.set(entity.value, entity);
  });

  const requestOptions = {
    method: 'post',
    uri: options.subscriptionUrl + '/v2/noise/multi/quick',
    headers: {
      key: options.apiKey,
      'User-Agent': USER_AGENT
    },
    body: {
      ips: ipEntities.map((entity) => entity.value)
    },
    json: true
  };

  const { statusCode, body } = await requestWithDefaultsAsync(requestOptions);
  const error = handleAsyncHttpResponse(statusCode, body);

  if (error) {
    throw error;
  } else {
    const results = [];
    body.forEach((ip) => {
      results.push({
        data: {
          ...ip
        },
        entity: ipMap.get(ip.ip)
      });
    });
    return results;
  }
};

function handleAsyncHttpResponse (statusCode, body) {
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
      detail: 'Too many requests.  You've hit the rate limit'
    };
  } else if (statusCode === 401) {
    return {
      body,
      detail: body && body.message ? body.message : 'Unauthorized: Please check your API key'
    };
  } else if (statusCode === 404) {
    return {
      body,
      help: 'The default enterprise subscription url is `https://api.greynoise.io`.  Ensure you are using the correct URL.',
      detail: 'Provided URL or Endpoint could not be found'
    };
  } else {
    // unexpected response received
    return {
      body,
      detail: `Unexpected HTTP status code [${statusCode}] received`
    };
  }
}

async function getIpNoiseData (entity, options) {
  let noiseContextRequestOptions = {
    method: 'GET',
    uri: options.subscriptionUrl + '/v2/noise/context/' + entity.value,
    headers: {
      key: options.apiKey,
      'User-Agent': USER_AGENT
    },
    json: true
  };

  const { statusCode, body } = await requestWithDefaultsAsync(noiseContextRequestOptions);
  const error = handleAsyncHttpResponse(statusCode, body);

  Logger.trace({ noiseContextRequestOptions, statusCode, body }, 'Subscription Noise lookup results');

  if (error) {
    throw error;
  } else {
    return body;
  }
}

async function getIpRiotData (entity, options) {
  let riotIpRequestOptions = {
    method: 'GET',
    uri: `${options.subscriptionUrl}/v2/riot/${entity.value}`,
    headers: {
      key: options.apiKey,
      'User-Agent': USER_AGENT
    },
    json: true
  };

  const { statusCode, body } = await requestWithDefaultsAsync(riotIpRequestOptions);
  const error = handleAsyncHttpResponse(statusCode, body);

  Logger.trace({ riotIpRequestOptions, statusCode, body }, 'Subscription RIOT lookup results');

  if (error) {
    throw error;
  } else {
    return body;
  }
}

const getCveData = (entity, options, done) => {
  const gnqlStatsRequestOptions = {
    method: 'GET',
    uri: `${options.subscriptionUrl}/v2/experimental/gnql/stats`,
    qs: {
      //count: 3,
      query: `cve:${entity.value}`
    },
    headers: {
      key: options.apiKey,
      'User-Agent': USER_AGENT
    },
    json: true
  };
  requestWithDefaults(gnqlStatsRequestOptions, function (err, response, body) {
    if (err) return done({ detail: 'Unexpected GNQL Stats Query HTTP request error', err });
    processGnqlStatsRequestResults(response, body, entity, options, done);
  });
};

const processGnqlStatsRequestResults = (response, body, entity, options, done) => {
  let result = {};
  let error = null;

  if (response.statusCode === 200) {
    if (body.count === 0) {
      result = { entity };
    } else {
      result = { entity, stats: body.stats };
    }
  } else if (response.statusCode === 400) {
    result = { body };
  } else if (response.statusCode === 429) {
    error = {
      body,
      detail: body && body.message ? body.message : 'Too many requests.  You've hit the rate limit'
    };
  } else if (response.statusCode === 401) {
    error = {
      body,
      detail: body && body.message ? body.message : 'Unauthorized: Please check your API key'
    };
  } else if (response.statusCode === 404) {
    error = {
      body,
      help: 'The default enterprise subscription url is `https://api.greynoise.io`.  Ensure you are using the correct URL.',
      detail: 'Provided URL or Endpoint could not be found'
    };
  } else {
    // unexpected response received
    error = {
      body,
      detail: body && body.message ? body.message : `Unexpected HTTP status code [${response.statusCode}] received`
    };
  }

  done(error, result);
};

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

const getCommunitySummaryTags = (data) => {
  let tags = [];

  if (!data) {
    return ['IP address has not been seen'];
  }

  if (data.limitHit) {
    return ['Lookup limit reached'];
  }

  if (data.noise) {
    tags.push(`Classification: ${data.classification}`);
    tags.push('Internet scanner');
  }

  if (data.riot) {
    // RIOT tags are done in green
    tags.push(`Classification: RIOT`);
  }

  if (data.name && data.name !== 'unknown') {
    if (data.riot) {
      tags.push(`Provider: ${data.name}`);
    } else if (data.noise) {
      tags.push(`Riot: ${data.name}`);
    } else {
      tags.push(`Name: ${data.name}`);
    }
  }

  return tags;
};

const getSubscriptionSummaryTags = (data) => {
  let tags = [];

  if (data) {
    if (data.seen) {
      tags.push(`Classification: ${data.classification}`);
      tags.push('Internet scanner');
    }

    if (data.bot)
      tags.push({
        icon: 'robot',
        text: 'bot'
      });

    if (data.vpn) {
      tags.push({
        icon: 'shield-alt',
        text: 'VPN'
      });
    }

    if (data.metadata) {
      if (data.metadata.tor) {
        tags.push({
          icon: 'user-secret',
          text: 'TOR'
        });
      }
      if (data.metadata.organization) {
        tags.push(`Org: ${data.metadata.organization}`);
      }
    }

    if (Array.isArray(data.tags) && data.tags.length > 0) {
      for (let i = 0; i < data.tags.length && i < MAX_GN_TAGS; i++) {
        tags.push(`${data.tags[i]}`);
      }

      if (data.tags.length > MAX_GN_TAGS) {
        tags.push(`+${data.tags.length - MAX_GN_TAGS} tags`);
      }
    }

    if (data.actor) {
      if (data.actor !== 'unknown') {
        tags.push(`Actor: ${data.actor}`);
      }
    }

    if (data.riot) {
      if (data.trust_level) {
        if (data.trust_level === '1') {
          // Only RIOT IPs with a trust level of 1 are given the green threshold checkmark
          tags.push({
            type: 'RIOT',
            text: `Classification: RIOT`
          });
          tags.push(`Trust Level: 1 - Reasonably Ignore`);
        } else if (data.trust_level === '2') {
          tags.push('Classification: RIOT');
          tags.push(`Trust Level: 2 - Commonly Seen`);
        } else {
          tags.push('Classification: RIOT');
          tags.push(`Trust Level: ${data.trust_level}`);
        }
      } else {
        tags.push('Classification: RIOT');
      }

      if (data.name) {
        tags.push(data.name);
      }
    }
  }

  return _.uniq(tags);
};

function getCveSummaryTags (data) {
  const tags = [];
  if (data.stats) {
    if (data.stats && data.stats.countries) {
      tags.push(`Top Country: ${data.stats.countries[0].country} (${data.stats.countries[0].count})`);
    }

    if (data.stats && data.stats.tags) {
      tags.push(`Top Tag: ${data.stats.tags[0].tag} (${data.stats.tags[0].count})`);
    }

    if (data.stats.classifications) {
      data.stats.classifications.forEach((classification) => {
        if (classification.classification === 'malicious') {
          tags.push(`Malicious: ${classification.count}`);
        }
      });
    }
  }
  return tags;
}

function validateOptions (userOptions, cb) {
  const errors = [];

  if (userOptions.subscriptionApi.value === true && userOptions.apiKey.value.length === 0) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a GreyNoise API key if using the subscription API'
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
