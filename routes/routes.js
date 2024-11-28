const express = require('express');
const router = express.Router();
// const APIService = require('../api');

const axios = require('axios');
const FLASK_API_URL = "http://localhost:5000";

// axios.get(`${FLASK_API_URL}/example-endpoint`)
//   .then(response => console.log(response.data))
//   .catch(error => console.error(error));

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

router.get('/', (req, res) => {
    res.render('index', { 
      title: 'sadsda',
    });
  });
  router.get('/index', (req, res) => {
    res.render('index', { 
      title: 'sadsda',
    });
  });

  router.post('/encrypt', (req, res) => {

    const { 
      message, 
      encryptionType, 
      encryptKey 
    } = req.body;
    console.log("BODY");
    console.log(req.body);
    if (!message || !encryptionType || !encryptKey) {
      console.log("aAADAW");
      console.log(message);
      console.log(encryptionType);
      console.log(encryptKey);
      return res.status(400).json({ error: 'missing fields' });
  }
    const encryptedMessage = `testasdasd ${message} ${encryptionType} key- ${encryptKey}`;

    res.json({ encryptedMessage });
});

module.exports = router;