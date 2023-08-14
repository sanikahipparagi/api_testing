require('./config/db.js');

const app = require('express')();
const port = 3000;

const UserRouter = require('./api/User');

const bodyParser = require('express').json;
app.use(bodyParser());

app.use('/user', UserRouter)

app.listen(port, () => {
  console.log(`server is running on port ${port}`);
})