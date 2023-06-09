const express = require('express');
const dotenv = require('dotenv');
const mysql = require('mysql');
dotenv.config({ path: './.env' });
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const checkAuth = require('./middleware/checkAuth');

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
});

db.connect((err) => {
  if (err) {
    console.log(err);
  } else {
    console.log('mysql connected');
  }
});

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const newPassword = await bcrypt.hash(password, 10);
  const status = 'active'; // set default status as active
  const currentTime = new Date().toISOString(); // get current time in ISO string format

  const sqlQuery = `SELECT * FROM users WHERE email='${email}'`;
  const sqlQuery1 = `INSERT INTO users (name, email, password, last_login_time, registration_time, status) VALUES (?,?,?,?,?,?)`;

  await db.query(sqlQuery, async (error, data) => {
    try {
      if (data.length) {
        return res.status(400).json({ message: 'User already exists' });
      }
      if (data.length === 0) {
        await db.query(
          sqlQuery1,
          [name, email, newPassword, currentTime, currentTime, status], // add last_login_time, registration_time, and status values
          (error, result) => {
            if (result) {
              return res.json({
                status: 200,
                message: 'New user',
                data: result,
              });
            } else {
              return res.json({ status: 400, message: error });
            }
          }
        );
      }
    } catch (error) {
      return res.json({ status: 400, message: error });
    }
  });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  db.query(
    'SELECT * FROM users WHERE email = ?',
    [email],
    async function (error, results, fields) {
      if (error) {
        return res.send({
          code: 400,
          failed: 'error occurred',
          error: error,
        });
      } else {
        if (results.length > 0) {
          const user = results[0];
          if (user.status === 'blocked') {
            return res.json({
              code: 403,
              error: 'User account is blocked',
            });
          } else {
            const comparison = await bcrypt.compare(password, user.password);
            if (comparison) {
              const token = await jwt.sign(
                { email: email },
                process.env.MY_SECRET,
                {
                  expiresIn: '1h',
                }
              );

              // Update last_login_time
              db.query(
                'UPDATE users SET last_login_time = ? WHERE email = ?',
                [new Date().toISOString(), email],
                function (error, results, fields) {
                  if (error) {
                    console.error(error);
                  }
                }
              );

              return res.json({ token: token });
            } else {
              return res.send({
                code: 204,
                error: 'Email or password does not match',
              });
            }
          }
        } else {
          return res.send({
            code: 206,
            error: 'Email does not exist',
          });
        }
      }
    }
  );
});

app.get('/dashboard', checkAuth, async (req, res) => {
  const userId = req.user.email;
  const sqlQuery = `SELECT * FROM users`;

  await db.query(sqlQuery, (error, results) => {
    if (error) {
      res.status(500).json({ message: 'Error getting dashboard data' });
    } else {
      return res.json({ data: results });
    }
  });
});

app.post('/block-users', checkAuth, async (req, res) => {
  const { emailList } = req.body;

  try {
    await Promise.all(
      emailList.map(async (email) => {
        await db.query('UPDATE users SET status = ? WHERE email = ?', [
          'blocked',
          email,
        ]);
      })
    );

    return res.json({ status: 200, message: 'Users successfully blocked' });
  } catch (error) {
    return res.json({ status: 400, message: error });
  }
});

app.post('/unblock-users', checkAuth, async (req, res) => {
  const { emailList } = req.body;

  try {
    await Promise.all(
      emailList.map(async (email) => {
        await db.query('UPDATE users SET status = ? WHERE email = ?', [
          'active',
          email,
        ]);
      })
    );

    return res.json({ status: 200, message: 'Users successfully unblocked' });
  } catch (error) {
    return res.json({ status: 400, message: error });
  }
});

app.post('/delete-users', checkAuth, async (req, res) => {
  const { emailList } = req.body;

  try {
    await Promise.all(
      emailList.map(async (email) => {
        await db.query('DELETE FROM users WHERE email = ?', [email]);
      })
    );

    return res.json({ status: 200, message: 'Users successfully deleted' });
  } catch (error) {
    return res.json({ status: 400, message: error });
  }
});
const port = process.env.PORT || 5001;
app.listen(port, () => {
  console.log('server is listening to port: 5001');
});
