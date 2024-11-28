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
    const encryptedMessage = `testencryption ${message} ${encryptionType} key- ${encryptKey}`;
    console.log(encryptedMessage);
    res.json({ encryptedMessage });
});

router.post('/decrypt', (req, res) => {

  const { 
    encryptedMessage, 
    decryptionType, 
    decryptKey 
  } = req.body;
  console.log(req.body);
  if (!encryptedMessage || !decryptionType || !decryptKey) {
    console.log("missing decrypt field");
    console.log(message);
    console.log(decryptionType);
    console.log(decryptKey);
    return res.status(400).json({ error: 'missing fields' });
}
  const decryptedMessage = `testdecryption ${encryptedMessage} ${decryptionType} key- ${decryptKey}`;
  console.log(decryptedMessage);
  res.json({ decryptedMessage });
});

module.exports = router;