"use strict";

const request = require("postman-request");
const config = require("./config/config");
const { version: packageVersion } = require("./package.json");
const async = require("async");
const fs = require("fs");
const _ = require("lodash");
const util = require("util");

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

  if (typeof config.request.cert === "string" && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === "string" && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === "string" && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === "string" && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === "string" && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === "boolean") {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
  requestWithDefaultsAsync = util.promisify(requestWithDefaults);
}

async function doLookup(entities, options, cb) {
  Logger.trace({ entities }, "doLookup");
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
    } else if (entity.type === "cve") {
      validCves.push(entity);
    }
  });

  return { validIps, validCves };
};

const useGreynoiseApi = async (ips, cves, options, cb) => {
  try {
    const ipPromises = ips.map((entity) => {
      const requestOptions = {
        method: "GET",
        uri: `${options.subscriptionUrl}/v3/ip/${entity.value}`,
        headers: {
          key: options.apiKey,
          "User-Agent": USER_AGENT
        },
        json: true
      };
      Logger.trace({ requestOptions }, "IP request options");
      return requestWithDefaultsAsync(requestOptions).then((response) => ({ response, entity, type: "ip" }));
    });

    const cvePromises = cves.map((entity) => {
      const requestOptions = {
        method: "GET",
        uri: `${options.subscriptionUrl}/v1/cve/${entity.value}`,
        headers: {
          key: options.apiKey,
          "User-Agent": USER_AGENT
        },
        json: true
      };
      Logger.trace({ requestOptions }, "CVE request options");
      return requestWithDefaultsAsync(requestOptions).then((response) => ({ response, entity, type: "cve" }));
    });

    const settledResults = await Promise.allSettled([...ipPromises, ...cvePromises]);
    const lookupResults = [];

    settledResults.forEach((result) => {
      if (result.status === "rejected") {
        // This can happen for network errors, etc.
        Logger.error({ error: result.reason }, "Request failed");
        // We could push an error result here if we wanted to show it in the UI
        return;
      }

      const { response, entity, type } = result.value;
      const { statusCode, body } = response;

      Logger.trace({ response }, "New Processing result");

      if (type === "cve") {
        if (statusCode === 200 && body && body.id) {
          lookupResults.push({
            entity,
            data: {
              summary: getCveSummaryTags(body),
              details: {
                ...body,
                hasResult: true,
                usingApiKey: !!options.apiKey,
                apiService: "unified"
              }
            }
          });
        } else if (statusCode === 404 && !options.ignoreNonSeen) {
          lookupResults.push({
            entity,
            data: {
              summary: ["CVE not found"],
              details: { hasResult: false, apiService: "unified" }
            }
          });
        } else if (statusCode === 429) {
          lookupResults.push({
            entity,
            data: {
              summary: ["Lookup limit reached"],
              details: { limitHit: true, apiService: "unified" }
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
                summary: ["IP address has not been seen"],
                details: { hasResult: false, apiService: "unified" }
              }
            });
          } else {
            lookupResults.push({ entity, data: null });
          }
        } else if (statusCode === 429) {
          lookupResults.push({
            entity,
            data: {
              summary: ["Lookup limit reached"],
              details: { limitHit: true, apiService: "unified" }
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
            apiService: "unified",
            usingApiKey: !!options.apiKey,
            hasResult: true
          }
        }
      });
    });

    Logger.debug({ lookupResults }, "Results");
    cb(null, lookupResults);
  } catch (error) {
    Logger.error({ error }, "Error in useGreynoiseApi");
    cb(errorToPojo(error));
  }
};

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: "HTTP Request Error"
    };
  }

  if (res.statusCode === 200) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 400) {
    if (body.message.includes("Request is not a valid routable IPv4 address")) {
      result = {
        entity: entity,
        body: null
      };
    } else {
      result = {
        error: "Bad Request",
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
      error: "Unexpected Error",
      statusCode: res ? res.statusCode : "Unknown",
      detail: "An unexpected error occurred",
      body
    };
  }

  return result;
}

function errorToPojo(err) {
  return err instanceof Error
    ? {
        ...err,
        name: err.name,
        message: err.message,
        stack: err.stack,
        detail: err.message ? err.message : err.detail ? err.detail : "Unexpected error encountered"
      }
    : err;
}

function handleAsyncHttpResponse(statusCode, body) {
  if (statusCode === 200) {
    return;
  } else if (statusCode === 400) {
    return {
      body,
      detail: "Bad Requests."
    };
  } else if (statusCode === 429) {
    return {
      body,
      detail: "Too many requests. You've hit the rate limit"
    };
  } else if (statusCode === 401) {
    return {
      body,
      detail: body && body.message ? body.message : "Unauthorized: Please check your API key"
    };
  } else if (statusCode === 404) {
    return {
      body,
      detail: "Not Found"
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
  return entity.startsWith("127");
};

const isLinkLocalAddress = (entity) => {
  return entity.startsWith("169");
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
    return ["IP address has not been seen"];
  }

  if (data.limitHit) {
    return ["Lookup limit reached"];
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
  if (data && data.details && typeof data.details.cve_cvss_score === "number") {
    tags.push(`CVSS: ${data.details.cve_cvss_score}`);
  }
  if (data && data.exploitation_details && data.exploitation_details.epss_score) {
    tags.push(`EPSS: ${data.exploitation_details.epss_score}`);
  }
  return tags;
}

function validateOptions(userOptions, cb) {
  const errors = [];

  if (userOptions.subscriptionApi.value === true && userOptions.apiKey.value.length === 0) {
    errors.push({
      key: "apiKey",
      message: "You must provide a GreyNoise API key if using the subscription API"
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
