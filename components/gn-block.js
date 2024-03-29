'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  tags: Ember.computed.alias('details.tags'),
  trustLevel: Ember.computed('details.trust_level', function () {
    let trustLevel = this.get('details.trust_level');
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
  init () {
    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.activeTab', 'info');
    }

    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));

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

      if (this.get('block.userOptions.subscriptionApi')) {
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
    }
  },
  copyElementToClipboard (element) {
    window.getSelection().removeAllRanges();
    let range = document.createRange();

    range.selectNode(typeof element === 'string' ? document.getElementById(element) : element);
    window.getSelection().addRange(range);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
  },
  restoreCopyState (savedActiveTab, savedShowAllTags) {
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
