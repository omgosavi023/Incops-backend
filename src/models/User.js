const mongoose = require('mongoose');



const userSchema = new mongoose.Schema({

    username: { type: String, required true ,

    email:  type tring, required: true, unique: true ,

    password:  type tring, required true ,

    role  type tring, default 'user' ,

    createdt  type ate, default ate.now 

;



module.exports = mongoose.model'ser', userchema;
