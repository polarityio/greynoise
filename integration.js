'use strict';

const request = require('postman-request');
const config = require('./config/config');
const { version: packageVersion } = require('./package.json');
const async = require('async');
const fs = require('fs');
const _ = require('lodash/fp');
const util = require('util');

const MAX_PARALLEL_LOOKUPS = 10;
const MAX_GN_TAGS = 2;

// noise and seen properties are used interchangeably
// noise/seen means the IP is an Internet Scanner

let Logger;
let requestWithDefaults;
let requestWithDefaultsAsync;

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
  requestWithDefaultsAsync = util.promisify(requestWithDefaults);
}

function doLookup(entities, options, cb) {
  Logger.trace({ entities }, 'doLookup');

  if (options.subscriptionApi) {
    // subscription API searches both IPs and CVEs
    const validIpsAndCves = getValidIpsAndCves(entities);
    useGreynoiseSubscriptionApi(validIpsAndCves, options, cb);
  } else {
    // community api only searches IPs
    const validIpEntities = getValidIps(entities);
    useGreynoiseCommunityApi(validIpEntities, options, cb);
  }
}

/**
 * Given an array of entity objects, only return valid IPs.  This ignores
 * any CVEs that are passed to the integration as well as non-valid IPs
 *
 * @param entities
 * @returns {*}
 */
const getValidIps = (entities) => {
  return entities.reduce((accum, entity) => {
    if (entity.isIP && isValidIp(entity)) {
      accum.push(entity);
    }
    return accum;
  }, []);
};

/**
 * Given an array of entity objects, only return valid IPs and CVEs.
 *
 * @param entities
 * @returns {*}
 */
const getValidIpsAndCves = (entities) => {
  return entities.reduce((accum, entity) => {
    if (entity.isIP && isValidIp(entity)) {
      accum.push(entity);
    } else if (entity.type === 'cve') {
      accum.push(entity);
    }
    return accum;
  }, []);
};

const useGreynoiseCommunityApi = (entities, options, cb) => {
  let lookupResults = [];
  let tasks = [];

  entities.forEach((entity) => {
    let requestOptions = {
      method: 'GET',
      uri: options.url + '/v3/community/' + entity.value,
      headers: {
        key: options.apiKey,
        'User-Agent': `greynoise-community-polarity-integration-v${packageVersion}`
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

function handleRestError(error, entity, res, body) {
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
    // "IP not observed scanning the internet or contained in RIOT data set."
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

const useGreynoiseSubscriptionApi = (entities, options, cb) => {
  let lookupResults = [];
  let tasks = [];

  entities.forEach((entity) => {
    Logger.trace({ uri: options }, 'Request URI');

    tasks.push(function (done) {
      if (entity.isIP) {
        getIpData(entity, options, done);
      } else if (entity.type === 'cve') {
        getCveData(entity, options, done);
      } else {
        done({ err: 'Unsupported entity type' });
      }
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) return cb(err);

    results.forEach((result) => {
      if (result.entity.type === 'cve') {
        Logger.trace({ result }, 'CVE Result');
        if (result && result.body && result.body.data) {
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: getSubscriptionSummaryTags(result),
              details: {
                ...result.body,
                ...result.rBody,
                ...result.statBody,
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
      }

      if (result.entity.type === 'IPv4') {
        if (result && result.rBody) {
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: getSubscriptionSummaryTags(result),
              details: {
                ...result.body,
                ...result.rBody,
                ...result.statBody,
                apiService: 'subscription',
                hasResult: true
              }
            }
          });
        } else if (result && result.body && result.body.seen) {
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: getSubscriptionSummaryTags(result),
              details: {
                ...result.body,
                ...result.rBody,
                ...result.statBody,
                apiService: 'subscription',
                hasResult: true
              }
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
      }
    });
    Logger.trace({ lookupResults }, 'response returned to client');
    cb(null, lookupResults);
  });
};

const runMultiQuickLookup = async (ipEntities, options) => {
  const requestOptions = {
    method: 'post',
    headers: {
      key: options.apiKey,
      'User-Agent': `greynoise-polarity-integration-v${packageVersion}`
    },
    data: {
      ips: ipEntities.map((entity) => entity.value)
    },
    json: true
  };

  const { statusCode, body } = await requestWithDefaultsAsync(requestOptions);
};

const getIpData = (entity, options, done) => {
  let noiseContextRequestOptions = {
    method: 'GET',
    uri: options.url + '/v2/noise/context/' + entity.value,
    headers: {
      key: options.apiKey,
      'User-Agent': `greynoise-polarity-integration-v${packageVersion}`
    },
    json: true
  };

  requestWithDefaults(noiseContextRequestOptions, function (ncHttpError, ncRes, ncBody) {
    if (ncHttpError) return done({ detail: 'Unexpected Noise Context HTTP request error', ncHttpError });

    Logger.trace({ ncBody, ncStatusCode: ncRes ? ncRes.statusCode : 'N/A' }, 'Noise Context');
    let riotIpRequestOptions = {
      method: 'GET',
      uri: `${options.url}/v2/riot/${entity.value}`,
      headers: {
        key: options.apiKey,
        'User-Agent': `greynoise-polarity-integration-v${packageVersion}`
      },
      json: true
    };

    requestWithDefaults(riotIpRequestOptions, function (rhttpError, rRes, rBody) {
      if (rhttpError) return done({ detail: 'Unexpected Riot IP HTTP request error', rhttpError });
      processNoiseContextRequestResult(entity, options, ncRes, ncBody, (ncError, ncResult) => {
        if (ncError) return done(ncError);

        let result, error;

        if (rRes.statusCode === 200) {
          if (!rBody.riot) {
            // cache these as a miss
            result = ncResult;
          } else {
            result = {
              ...ncResult,
              rBody: rBody
            };
          }
        } else if ([400, 404].includes(rRes.statusCode)) {
          result = ncResult;
        } else if (rRes.statusCode === 429) {
          error = {
            ...ncResult,
            rBody: rBody,
            detail: "Too many requests.  You've hit the rate limit"
          };
        } else if (rRes.statusCode === 401) {
          error = {
            ...ncResult,
            rBody: rBody,
            detail: 'Unauthorized: Please check your API key'
          };
        } else {
          // unexpected response received
          error = {
            ...ncResult,
            rBody: rBody,
            detail: `Unexpected HTTP status code on Riot IP search [${rRes.statusCode}] received`
          };
        }

        done(error, result);
      });
    });
  });
};

const processNoiseContextRequestResult = (entity, options, res, body, done) => {
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
      detail: body && body.message ? body.message : 'Unauthorized: Please check your API key'
    };
  } else {
    // unexpected response received
    error = {
      body,
      detail: `Unexpected HTTP status code [${res.statusCode}] received`
    };
  }

  done(error, result);
};

const getCveData = (entity, options, done) => {
  const gnqlRequestOptions = {
    method: 'GET',
    uri: `${options.url}/v2/experimental/gnql`,
    qs: {
      size: 10,
      query: `cve:${entity.value}`
    },
    headers: {
      key: options.apiKey,
      'User-Agent': `greynoise-polarity-integration-v${packageVersion}`
    },
    json: true
  };
  requestWithDefaults(gnqlRequestOptions, function (httpError, res, body) {
    if (httpError) return done({ detail: 'Unexpected GNQL Query HTTP request error', httpError });

    const gnqlStatsRequestOptions = {
      method: 'GET',
      uri: `${options.url}/v2/experimental/gnql/stats`,
      qs: {
        count: 3,
        query: `cve:${entity.value}`
      },
      headers: {
        key: options.apiKey,
        'User-Agent': `greynoise-polarity-integration-v${packageVersion}`
      },
      json: true
    };
    requestWithDefaults(gnqlStatsRequestOptions, function (shttpError, sRes, sBody) {
      if (shttpError) return done({ detail: 'Unexpected GNQL Stats Query HTTP request error', shttpError });

      processGnqlRequestResult(entity, options, res, body, (error, gnqlResult) => {
        if (error) return done(error);
        processGnqlStatsRequestResults(options, sRes, sBody, gnqlResult, done);
      });
    });
  });
};

const processGnqlRequestResult = (entity, options, res, body, done) => {
  let result = {};
  let error = null;

  if (res.statusCode === 200) {
    if (options.ignoreNonSeen && body.count === 0) {
      result = { entity, body: null };
    } else {
      result = { entity, body };
    }
  } else if (res.statusCode === 400) {
    result = { entity, body: null };
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
};

const processGnqlStatsRequestResults = (options, res, statBody, gnqlResult, done) => {
  let result = {};
  let error = null;

  if (res.statusCode === 200) {
    if (options.ignoreNonSeen && statBody.count === 0) {
      result = { ...gnqlResult };
    } else {
      result = { ...gnqlResult, statBody };
    }
  } else if (res.statusCode === 400) {
    result = { ...gnqlResult };
  } else if (res.statusCode === 429) {
    error = {
      statBody,
      detail: "Too many requests.  You've hit the rate limit"
    };
  } else if (res.statusCode === 401) {
    error = {
      statBody,
      detail: 'Unauthorized: Please check your API key'
    };
  } else {
    // unexpected response received
    error = {
      statBody,
      detail: `Unexpected HTTP status code [${res.statusCode}] received`
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
    return ['Has not been seen'];
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
    tags.push(`Name: ${data.name}`);
  }

  return tags;
};

const getSubscriptionSummaryTags = (data) => {
  let tags = [];
  // subscription non-riot

  if (data.body) {
    if (data.body.seen) {
      tags.push(`Classification: ${data.body.classification}`);
      tags.push('Internet scanner');
    }
    if (data.body) {
      if (data.body.bot)
        tags.push({
          icon: 'robot',
          text: 'bot'
        });

      if (data.body.vpn) {
        tags.push({
          icon: 'shield-alt',
          text: 'VPN'
        });
      }
    }

    if (data.body && data.body.metadata) {
      if (data.body.metadata.tor) {
        tags.push(`TOR exit node`);
      }
      if (data.body.metadata.organization) {
        tags.push(`Org: ${data.body.metadata.organization}`);
      }
    }

    if (data.body && Array.isArray(data.body.tags) && data.body.tags.length > 0) {
      for(let i=0; i<data.body.tags.length && i < MAX_GN_TAGS; i++){
        tags.push(`${data.body.tags[i]}`);
      }

      if(data.body.tags.length > MAX_GN_TAGS){
        tags.push(`+${data.body.tags.length - MAX_GN_TAGS} tags`);
      }
    }

    if (data.body && data.body.actor) {
      if (data.body.actor !== 'unknown') {
        tags.push(`Actor: ${data.body.actor}`);
      }
    }
  }

  if (data.rBody) {
    if (data.rBody.riot) {
      tags.push({
        type: 'RIOT',
        text: `Classification: RIOT`
      });

      if (data.rBody.trust_level) {
        if (data.rBody.trust_level === '1') {
          tags.push(`Trust Level: 1 - Reasonably Ignore`);
        } else if (data.rBody.trust_level === '2') {
          tags.push(`Trust Level: 2 - Commonly Seen`);
        } else {
          tags.push(`Trust Level: ${data.rBody.trust_level}`);
        }
      }

      if (data.rBody.name) {
        tags.push(data.rBody.name);
      }
    }
  }

  if (data.entity.type === 'cve') {
    if (data.body.count === 0) {
      tags.push('No Associated IP addresses');
    }

    if (data.statBody.stats) {
      if (data.statBody.stats && data.statBody.stats.countries) {
        tags.push(`Top Country: ${data.statBody.stats.countries[0].country} (${data.statBody.stats.countries.length})`);
      }

      if (data.statBody.stats && data.statBody.stats.tags) {
        tags.push(`Top Tag: ${data.statBody.stats.tags[0].tag} (${data.statBody.stats.tags.length})`);
      }

      if (data.statBody.stats.classifications) {
        data.statBody.stats.classifications.forEach((classification) => {
          if (classification.classification === 'malicious') {
            tags.push(`Malicious: ${classification.count}`);
          }
        });
      }
    }
  }

  return _.uniq(tags);
};

function validateOptions(userOptions, cb) {
  const errors = [];

  if (
      userOptions.subscriptionApi.value === true && userOptions.apiKey.value.length === 0
  ) {
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
