'use strict';

const request = require('request');
const config = require('./config/config');
const { version: packageVersion } = require('./package.json');
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
  Logger.trace({ entities });

  if(!options.apiKey) {
    useGreynoiseCommunityApi(entities, options, cb);
  } else {
    useGreynoiseStandardApi(entities, options, cb);
  }
}

const useGreynoiseCommunityApi = (entities, options, cb) => {
  let lookupResults = [];
  let tasks = [];

  entities.forEach((entity) => {
    let requestOptions = {
      method: 'GET',
      uri: 'https://api.greynoise.io/v3/community/' + entity.value,
      headers: {
        'User-Agent': `greynoise-community-polarity-integration-v${packageVersion}`
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'Request Options');

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
      if (options.maliciousOnly === true && getIsMalicious(result) === false) return;

      if (result.body === null || result.body.length === 0) {
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
      error: 'Too Many Requests',
      detail: body.message
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

function getIsMalicious(result) {
  if (result.body && result.body.classification && result.body.classification === 'malicious') {
    return true;
  } else {
    return false;
  }
}

const useGreynoiseStandardApi = (entities, options, cb) => {
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
    if (
      (result.body === null || (Array.isArray(result.body) && result.body.length === 0)) &&
      !(result.riotBody && result.riotBody.riot) &&
      !(result.statBody && result.statBody.count > 0)
    ) {
      lookupResults.push({
        entity: result.entity,
        data: null
      });
    } else {
      lookupResults.push({
        entity: result.entity,
        data: {
          summary: [],
          details: { ...result.body, ...result.riotBody, ...result.statBody }
        }
      });
    }
  });

  cb(null, lookupResults);
});
};

const getIpData = (entity, options, done) => {
  let noiseContextRequestOptions = {
    method: 'GET',
    uri: options.url + '/noise/context/' + entity.value,
    headers: {
      key: options.apiKey,
      'User-Agent': `greynoise-polarity-integration-v${packageVersion}`
    },
    json: true
  };
  requestWithDefaults(noiseContextRequestOptions, function (ncHttpError, ncRes, ncBody) {
    if (ncHttpError) return done({ detail: 'Unexpected Noise Context HTTP request error', ncHttpError });

    let riotIpRequestOptions = {
      method: 'GET',
      uri: `${options.url}/riot/${entity.value}`,
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
              riotBody: rBody
            };
          }
        } else if ([400, 404].includes(rRes.statusCode)) {
          result = ncResult;
        } else if (rRes.statusCode === 429) {
          error = {
            ...ncResult,
            riotBody: rBody,
            detail: "Too many requests.  You've hit the rate limit"
          };
        } else if (rRes.statusCode === 401) {
          error = {
            ...ncResult,
            riotBody: rBody,
            detail: 'Unauthorized: Please check your API key'
          };
        } else {
          // unexpected response received
          error = {
            ...ncResult,
            riotBody: rBody,
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
}

const getCveData = (entity, options, done) => {
  const gnqlRequestOptions = {
    method: 'GET',
    uri: `${options.url}/experimental/gnql`,
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
      uri: `${options.url}/experimental/gnql/stats`,
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

function validateOptions(userOptions, cb) {
  const urlError = userOptions.url.value && userOptions.url.value.endsWith('/')
    ? [{ key: 'url', message: 'Your Url must not end with "/".' }]
    : [];

  cb(null, urlError);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
