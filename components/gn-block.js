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
  maxInitialTagsToShow: 15,
  expandableTitleStates: {},
  tagsToShow: Ember.computed('block._state.showAllTags', function () {
    if (this.get('block._state.showAllTags')) {
      return this.get('tags');
    }
    return this.get('tags').slice(0, this.maxInitialTagsToShow);
  }),
  init() {
    const rawDataLength =
      (this.get('details.raw_data.scan') || []).length +
      (this.get('details.raw_data.web.paths') || []).length +
      (this.get('details.raw_data.web.useragents') || []).length +
      (this.get('details.raw_data.ja3') || []).length;

    this.set('rawDataLength', rawDataLength);
    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.activeTab', 'info');
    }

    this._super(...arguments);
  },
  actions: {
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
    }
  }
});
