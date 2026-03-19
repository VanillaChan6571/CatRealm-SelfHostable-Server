const router = require('express').Router();
const {
  handleChannelWebhookRequest,
  handleCategoryWebhookRequest,
  handleSimpleChannelWebhookRequest,
  handleSimpleCategoryWebhookRequest,
} = require('../webhooks');

router.post('/channel/:webhookId', (req, res) => {
  try {
    res.json(handleChannelWebhookRequest(req));
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Webhook request failed' });
  }
});

router.post('/category/:webhookId', (req, res) => {
  try {
    res.json(handleCategoryWebhookRequest(req));
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Webhook request failed' });
  }
});

router.post('/simple/channel/:webhookId/:token', (req, res) => {
  try {
    res.json(handleSimpleChannelWebhookRequest(req));
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Webhook request failed' });
  }
});

router.post('/simple/category/:webhookId/:token', (req, res) => {
  try {
    res.json(handleSimpleCategoryWebhookRequest(req));
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Webhook request failed' });
  }
});

module.exports = router;
