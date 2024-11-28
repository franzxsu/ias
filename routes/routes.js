const express = require('express');
const router = express.Router();
// const APIService = require('../api');

const axios = require('axios');
const FLASK_API_URL = "http://localhost:5000";

// axios.get(`${FLASK_API_URL}/example-endpoint`)
//   .then(response => console.log(response.data))
//   .catch(error => console.error(error));

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
module.exports = router;