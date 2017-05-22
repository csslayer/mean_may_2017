console.log('friends controller');
// WE NEED TO ADD A FEW lines of code here!
// How does a controller talk to mongoose and get a model?
// Build out the methods in the friendsControllers below
var mongoose = require('mongoose')
var Friend = mongoose.model('Friend');
function FriendsController(){
  this.index = function(req,res){
    //your code here
    Friend.find({}, function(err, results){

      return res.json(results);
    })
  };
  this.create = function(req,res){
    //your code here
    Friend.create(req.body, function(err, result){
      if(err){
        return res.json(err);
      }else{
        return res.json(result)
      }
    })
  };
  this.update = function(req,res){
    //your code here
    Friend.findOne({_id: req.params.id}, function(err, friend){
      if(err){
        console.log(err);
      }else{
        friend.name = req.body.name;
        friend.favoriteLanguage = req.body.favoriteLanguage;
        friend.save(function(err, updatedFriend){
          if (err){
            return res.json(err);
          }else{
            return res.json(updatedFriend);
          }
        })
      }
    })
  };
  this.delete = function(req,res){
    //your code here
    Friend.remove({_id: req.params.id}, function(err){
      if(err){
        return res.json(err);
      }else{
        return res.json({message: "Friend deleted!"});
      }
    })
  };
  this.show = function(req,res){
    //your code here
    Friend.findOne({_id: req.params.id}, function(err, result){

      return res.json(result);
    })
  };
}
module.exports = new FriendsController(); // what does this export?