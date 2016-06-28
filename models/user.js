const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define our model
const userSchema = new Schema({
    email: { type: String, unique: true, lowercase: true },
    password: String
});

// On Save Hook, encrypt password.
// Before saving a model, run this function.
userSchema.pre('save', function(next) {
    // Sets the context for the user model
    // gaining access to the user model.
    const user = this;
    
    // Generates a salt, then run a callback
    bcrypt.genSalt(10, function(err, salt) {
        if (err) { return next(err); }
        
        // Hash (encrypt) the password using the salt, run another callback
        // for duration of this encryption
        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) { return next(err); }
            
            // overwrite plain text password with encrypted password. 
            // Now you have the go ahead!
            user.password = hash;
            next();
        });
    });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
       if (err) { return callback(err); }
       
       callback(null, isMatch);
    });    
}

// create the model class
const ModelClass = mongoose.model('user', userSchema);


// Export the model
module.exports = ModelClass;