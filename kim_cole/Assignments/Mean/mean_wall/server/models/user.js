var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,4})+$/,
	passRegex  = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?!\s){8,32}/;

var UserSchema = new mongoose.Schema({
	email: {
		type:	String,
		lowercase: true,
		required: [true, 'Email is required for registration!'],
		unique: 	true,
		trim: 		true,
		validate: {
			validator: function(emailStr){
				return emailRegex.test(emailStr);
			},
			message: 'Please enter a valid email address'
		}
	},
	first_name: {
		type: 		String,
		required: [true, 'First name is required'],
		trim: 		true,
	},
	last_name: {
		type: 		String,
		required: [true, 'Last name is required'],
		trim: 		true
	},
	password: {
		type: 		String,
		required: [true, 'Password is required!'],
		validate: {
			validator: function(pass){
				return passRegex.test(pass);
			},
			message: 'Passwords must be between 8 and 32 characters, contain 1 uppercase, 1 lower case and 1 number.  Spaces are not allowed.'
		}
	},
	message: [{
		type: mongoose.Schema.Types.ObjectId,
		ref: 'Message'
	}],
	comments: [{
		type: mongoose.Schema.Types.ObjectId,
		ref: 'Comment'
	}],
	birthday: {
		type: 		Date,
		required: [true, 'Your Birthday is required for registration']
	},
}, {timestamps: true});

UserSchema.methods.hashPassword = function(password){
	this.password = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
}
UserSchema.methods.authenticate = function(password){
	return bcrypt.compareSync(password, this.password);
}

UserSchema.pre('save', function(callback){
	this.hashPassword(this.password);
	callback();
});

UserSchema.pre('remove', function(callback){
	var self = this;
	Message.remove({ user: self._id }, function(){
	}).then(function(){
		Comment.remove({ user: self._id}, callback)
	})
})

mongoose.model('User', UserSchema);