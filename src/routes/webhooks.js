const router = require('express').Router();
const {
  handleChannelWebhookRequest,
  handleCategoryWebhookRequest,
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

module.exports = router;
