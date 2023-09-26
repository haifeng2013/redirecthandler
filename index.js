'use strict'

const express = require('express');
// const serverless = require('serverless-http');
const port = process.env.PORT || 3004;
const app = express();
app.get('/', (req, res) => {
    const r = res.send('Namaste 🙏');
    console.log(r)
    return r;
});
app.listen(port, () => 
  console.log(`Server is listening on port ${port}.`)
);
