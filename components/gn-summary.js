'use strict'
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  tags: Ember.computed.alias('details.tags'),
  additionalTags: [],
  torExitNode: false,
  init() {
    if (this.get('details').seen) {
      this.set('moreThan1Tags', this.get('tags').length > 1);
      this.set('additionalTags', this.get('tags') ? this.get('tags').slice(0, 1) : []);
      this.set('torExitNode', this.get('details').metadata.tor);
    }

    this._super(...arguments);
  },
});
