const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config({ path: '../.env' });

module.exports = async (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(401).json({
      errors: [{ msg: 'No token found' }],
    });
  }
  try {
    let user = await jwt.verify(token, process.env.MY_SECRET);
    req.user = user;
    next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({
      errors: [{ msg: 'Invalid token' }],
    });
  }
};
