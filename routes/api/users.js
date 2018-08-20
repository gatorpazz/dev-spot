const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('../../config/keys');
const passport = require('passport');

// Load User model
const User = require('../../models/User');

// @route   GET api/users/test
// @desc    Tests users route
// @access  Public
router.get('/test', (req, res) => res.json({msg: "Users Works"}));

// @route   GET api/users/register
// @desc    Register user
// @access  Public
router.post('/register', (req, res) => {
  User.findOne({ email: req.body.email })
    .then(user => {
      if(user) {
        return res.status(400).json({ email: 'Email already exists' });
      } else {
        const { name, email, password } = req.body;
        const avatar = gravatar.url(email, {
          s: '200',
          r: 'pg',
          d: 'mm'
        });
        const newUser = new User({
          name,
          email,
          avatar,
          password
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if(err) throw err;
            newUser.password = hash;
            newUser.save()
              .then(user => res.json(user))
              .catch(err => console.log(err))
          });
        })
      }
    })
});

// @route   GET api/users/login
// @desc    Login User / Returning JWT Token
// @access  Public
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  User.findOne({email})
    .then(user => {
      if(!user) {
        return res.status(404).json({email: 'User not found'});
      }

      // Check Password
      bcrypt.compare(password, user.password)
        .then(isMatch => {
          if(isMatch) {
            // User Matched
            const { id, name, avatar } = user;
            const payload = { id, name, avatar };

            // Sign Token
            jwt.sign(
              payload,
              keys.secretOrKey,
              { expiresIn: 3600 },
              (err, token) => {
                res.json({
                  success: true,
                  token: `Bearer ${token}`
                });
              });
          } else {
            return res.status(400).json({password: 'Password incorrect'})
          }
        });
    });
});

// @route   GET api/users/current
// @desc    Return current user
// @access  Private
router.get('/current', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.json(req.user);
});

module.exports = router;