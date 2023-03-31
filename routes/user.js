const User = require("../models/User");
const router = require("express").Router();
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");
const { verifyTokenAndAuthorization, verifyTokenAndAdmin } = require("./verifyToken");

//CREATE A USER ACCOUNT
router.post("/register", async (req, res) => {
    const newUser = new User({
      username: req.body.username,
      password: CryptoJS.AES.encrypt(
        req.body.password,
        process.env.password_key
      ).toString(),
    });

    try {
        const savedUser = await newUser.save();
        res.status(200).json(savedUser);
      } catch (err) {
        res.status(500).json(err);
      }
});

//LOGIN TO USER ACCOUNT
router.post('/login', async (req, res) => {
  try{
      const user = await User.findOne({username : req.body.username});

      if(!user) { return res.status(401).json("Wrong User Name") }

      const hashedPassword = CryptoJS.AES.decrypt(
          user.password,
          process.env.password_key
      );

      const originalPassword = hashedPassword.toString(CryptoJS.enc.Utf8);

      const inputPassword = req.body.password;
      
      if(originalPassword != inputPassword) { 
        return res.status(401).json("Wrong Password")
      }

      const accessToken = jwt.sign(
      {
          id: user._id,
          isAdmin: user.isAdmin,
      },
      process.env.jwt_key,
          {expiresIn:"3d"}
      );

      const { password, ...others } = user._doc;  
      res.status(200).json({...others, accessToken});
  }catch(err){
      res.status(500).json(err);
  }
});

//UPDATE A USER
router.put("/:id", verifyTokenAndAuthorization, async (req, res) => {
  if (req.body.password) {
    req.body.password = CryptoJS.AES.encrypt(
      req.body.password,
      process.env.PASS_SEC
    ).toString();
  }

  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      {
        $set: req.body,
      },
      { new: true }
    );
    res.status(200).json(updatedUser);
  } catch (err) {
    res.status(500).json(err);
  }
});

//DELETE USER
router.delete("/:id", verifyTokenAndAuthorization, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.status(200).json("User has been deleted...");
  } catch (err) {
    res.status(500).json(err);
  }
});

//GET A USER
router.get("/find/:id", verifyTokenAndAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    const { password, ...others } = user._doc;
    res.status(200).json(others);
  } catch (err) {
    res.status(500).json(err);
  }
});

//GET ALL USERS
router.get("/", verifyTokenAndAdmin, async (req, res) => {
  const query = req.query.new;
  try {
    const users = query
      ? await User.find().sort({ _id: -1 }).limit(5)
      : await User.find();
    res.status(200).json(users);
  } catch (err) {
    res.status(500).json(err);
  }
});

module.exports = router;