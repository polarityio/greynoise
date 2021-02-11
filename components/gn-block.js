'use strict'
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  tags: Ember.computed.alias('details.tags'),
  showTags: [],
  showAllTags: true,
  rawDataOpen: false,
  expandableTitleStates: {},
  init() {
    this.set('showTags', this.get('tags') || []);

    const rawDataLength =
      (this.get('details.raw_data.scan') || []).length +
      (this.get('details.raw_data.web.paths') || []).length +
      (this.get('details.raw_data.web.useragents') || []).length +
      (this.get('details.raw_data.ja3') || []).length;

    this.set('rawDataLength', rawDataLength);
    this.set('rawDataOpen', rawDataLength <= 4);

    this._super(...arguments);
  },
  actions: {
    toggleExpandableTitle: function (index) {
      const modifiedExpandableTitleStates = Object.assign({}, this.get('expandableTitleStates'), {
        [index]: !this.get('expandableTitleStates')[index]
      });

      this.set(`expandableTitleStates`, modifiedExpandableTitleStates);
    },
    toggleShowTags: function () {
      if (this.get('showAllTags')) {
        this.set('showTags', this.get('tags').slice(0, 3));
      } else {
        this.set('showTags', this.get('tags'));
      }

      this.toggleProperty('showAllTags');
      this.get('block').notifyPropertyChange('data');
    },
    toggleRawDataOpen: function () {
      this.toggleProperty('rawDataOpen');
    }
  }
});
