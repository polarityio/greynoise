module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'GreyNoise',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'GN',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'GreyNoise Intelligence is a cyber security company that collects, labels, and analyzes Internet-wide scan and attack data',
  entityTypes: ['IPv4', 'cve'],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/gn.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/gn-block.js'
    },
    template: {
      file: './templates/gn-block.hbs'
    }
  },
  summary: {
    component: {
      file: './components/summary.js'
    },
    template: {
      file: './templates/summary.hbs'
    }
  },
  defaultColor: 'light-pink',
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',
    // If set to false, the integration will ignore SSL errors.  This will allow the integration to connect
    // to the response without valid SSL certificates.  Please note that we do NOT recommending setting this
    // to false in a production environment.
    rejectUnauthorized: true
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'subscriptionUrl',
      name: 'GreyNoise API URL',
      description: 'The base URL to the GreyNoise API you wish to use. Defaults to "https://api.greynoise.io".',
      default: 'https://api.greynoise.io',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'apiKey',
      name: 'API Key',
      description:
        'Account API key used to access GreyNoise API.',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'subscriptionApi',
      name: 'Search using the Subscription API',
      description:
          'If checked, the integration will search using the GreyNoise Subscription Based APIs.  When unchecked, the GreyNoise Community API will be used (only supports IP lookups)',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'ignoreNonSeen',
      name: 'Ignore IPs that have not been seen',
      description:
        'If checked, IPs that have not been seen by GreyNoise will not be displayed in the Polarity Overlay window.',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    }
  ]
};
