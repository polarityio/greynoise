'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  tags: Ember.computed.alias('details.tags'),
  trustLevel: Ember.computed('details.business_service_intelligence.trust_level', function () {
    let trustLevel = this.get('details.business_service_intelligence.trust_level');
    if (trustLevel === '1') {
      return '1 - Reasonably Ignore';
    }
    if (trustLevel === '2') {
      return '2 - Commonly Seen';
    }
    return trustLevel;
  }),
  showAllTags: false,
  showCopyMessage: false,
  maxInitialTagsToShow: 15,
  maxInitialCountriesToShow: 10,
  expandableTitleStates: {},
  uniqueIdPrefix: '',
  activeTab: '',
  associationsPageSize: 10,
  associationsPageNumber: 0,
  tagsToShow: Ember.computed('block._state.showAllTags', function () {
    let tags;
    if (this.get('block.entity.type') === 'cve') {
      tags = this.get('details.stats.tags');
    } else {
      tags = this.get('tags');
    }
    if (this.get('block._state.showAllTags')) {
      return tags;
    }
    return tags.slice(0, this.maxInitialTagsToShow);
  }),
  countriesToShow: Ember.computed('block._state.showAllCountries', function () {
    let countries;
    countries = this.get('details.stats.countries');

    if (this.get('block._state.showAllCountries')) {
      return countries;
    }
    return countries.slice(0, this.maxInitialCountriesToShow);
  }),
  // Start of Port Paging/Filter Data
  portCurrentPage: 1,
  portPageSize: 10,
  portData: Ember.computed.alias('details.internet_scanner_intelligence.raw_data.scan'),
  portFilterValue: '',
  portFilteredData: Ember.computed('portData.length', 'portFilterValue', function () {
    let filterValue = this.get('portFilterValue');

    if (filterValue) {
      filterValue = filterValue.toLowerCase().trim();
      if (filterValue.length > 0) {
        return this.get('portData').filter((entry) => {
          return entry.port.toString().includes(filterValue) || entry.protocol.toLowerCase().includes(filterValue);
        });
      }
    }

    return this.get('portData');
  }),
  portIsPrevButtonsDisabled: Ember.computed('portCurrentPage', function () {
    return this.get('portCurrentPage') === 1;
  }),
  portIsNextButtonDisabled: Ember.computed('portFilteredData.length', 'portPageSize', 'portCurrentPage', function () {
    const totalResults = this.get('portFilteredData.length');
    const totalPages = Math.ceil(totalResults / this.get('portPageSize'));
    return this.get('portCurrentPage') === totalPages;
  }),
  portPagingStartItem: Ember.computed('portCurrentPage', 'portPageSize', function () {
    return (this.get('portCurrentPage') - 1) * this.get('portPageSize') + 1;
  }),
  portPagingEndItem: Ember.computed('portPagingStartItem', function () {
    return this.get('portPagingStartItem') - 1 + this.get('portPageSize');
  }),
  portFilteredPagingData: Ember.computed('portFilteredData.length', 'portPageSize', 'portCurrentPage', function () {
    if (!this.get('portFilteredData')) {
      return [];
    }
    const startIndex = (this.get('portCurrentPage') - 1) * this.get('portPageSize');
    const endIndex = startIndex + this.get('portPageSize');

    return this.get('portFilteredData').slice(startIndex, endIndex);
  }),
  // End of Port Paging Data
  pagedAssociations: Ember.computed(
    'details.internet_scanner_intelligence.tags.[]',
    'associationsPageNumber',
    function () {
      const tags = this.get('details.internet_scanner_intelligence.tags');
      if (!tags) {
        return [];
      }
      const startIndex = this.get('associationsPageNumber') * this.get('associationsPageSize');
      const endIndex = startIndex + this.get('associationsPageSize');
      return tags.slice(startIndex, endIndex);
    }
  ),
  associationsStartItem: Ember.computed('associationsPageNumber', function () {
    return this.get('associationsPageNumber') * this.get('associationsPageSize') + 1;
  }),
  associationsEndItem: Ember.computed('pagedAssociations.[]', 'associationsStartItem', function () {
    return this.get('associationsStartItem') + this.get('pagedAssociations.length') - 1;
  }),
  isPrevAssociationsButtonsDisabled: Ember.computed('associationsPageNumber', function () {
    return this.get('associationsPageNumber') === 0;
  }),
  isNextAssociationsButtonDisabled: Ember.computed(
    'associationsPageNumber',
    'details.internet_scanner_intelligence.tags.[]',
    function () {
      const pageNumber = this.get('associationsPageNumber');
      const pageSize = this.get('associationsPageSize');
      const totalTags = this.get('details.internet_scanner_intelligence.tags.length');
      return (pageNumber + 1) * pageSize >= totalTags;
    }
  ),
  init() {
    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.activeTab', 'info');
    }

    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));
    console.log(this.get('details'), 'DETAILS');
    this._super(...arguments);
  },
  actions: {
    copyData: function () {
      const savedShowAllTags = this.get('block._state.showAllTags');
      const savedActiveTab = this.get('block._state.activeTab');

      let containerId = null;

      const idTypes = {
        info: `information-container-${this.get('uniqueIdPrefix')}`,
        activity: `activity-container-${this.get('uniqueIdPrefix')}`
      };

      if (this.get('details.apiService') === 'subscription') {
        if (this.get('block.entity.type') === 'cve') {
          containerId = `cve-container-${this.get('uniqueIdPrefix')}`;
        } else {
          containerId = idTypes[this.get('block._state.activeTab')];
        }
      } else {
        containerId = `community-container-${this.get('uniqueIdPrefix')}`;
      }

      this.set('block._state.showAllTags', true);

      Ember.run.scheduleOnce('afterRender', this, this.copyElementToClipboard, containerId);
      Ember.run.scheduleOnce('destroy', this, this.restoreCopyState, savedActiveTab, savedShowAllTags);
    },
    changeTab: function (tabName) {
      this.set('block._state.activeTab', tabName);
    },
    toggleExpandableTitle: function (index) {
      const modifiedExpandableTitleStates = Object.assign({}, this.get('expandableTitleStates'), {
        [index]: !this.get('expandableTitleStates')[index]
      });
      this.set(`expandableTitleStates`, modifiedExpandableTitleStates);
    },
    toggleShowTags: function () {
      this.toggleProperty('block._state.showAllTags');
    },
    toggleShowCountries: function () {
      this.toggleProperty('block._state.showAllCountries');
    },
    // Port Paging Actions
    portPrevPage() {
      let portCurrentPage = this.get('portCurrentPage');

      if (portCurrentPage > 1) {
        this.set('portCurrentPage', portCurrentPage - 1);
      }
    },
    portNextPage() {
      const totalResults = this.get('portFilteredData.length');
      const totalPages = Math.ceil(totalResults / this.get('portPageSize'));
      let currentPage = this.get('portCurrentPage');
      if (currentPage < totalPages) {
        this.set('portCurrentPage', currentPage + 1);
      }
    },
    portFirstPage() {
      this.set('portCurrentPage', 1);
    },
    portLastPage() {
      const totalResults = this.get('portFilteredData.length');
      const totalPages = Math.ceil(totalResults / this.get('portPageSize'));
      this.set('portCurrentPage', totalPages);
    },
    // End Port Paging Actions
    
    // For Associations Pagination
    nextAssociationsPage: function () {
      this.incrementProperty('associationsPageNumber');
    },
    prevAssociationsPage: function () {
      this.decrementProperty('associationsPageNumber');
    },
    firstAssociationsPage: function () {
      this.set('associationsPageNumber', 0);
    },
    lastAssociationsPage: function () {
      const totalTags = this.get('details.internet_scanner_intelligence.tags.length');
      const pageSize = this.get('associationsPageSize');
      this.set('associationsPageNumber', Math.floor(totalTags / pageSize));
    }
  },
  copyElementToClipboard(element) {
    window.getSelection().removeAllRanges();
    let range = document.createRange();

    range.selectNode(typeof element === 'string' ? document.getElementById(element) : element);
    window.getSelection().addRange(range);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
  },
  restoreCopyState(savedActiveTab, savedShowAllTags) {
    this.set('activeTab', savedActiveTab);
    this.set('showCopyMessage', true);

    this.set('block._state.showAllTags', savedShowAllTags);

    setTimeout(() => {
      if (!this.isDestroyed) {
        this.set('showCopyMessage', false);
      }
    }, 2000);
  }
});
