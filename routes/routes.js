const express = require('express');
const router = express.Router();
// const APIService = require('../api');

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