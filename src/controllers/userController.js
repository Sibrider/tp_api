const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const saltRounds = 10;

exports.userRegister = (req, res) => {
    let newUser = new User(req.body);

    // hash le password
    bcrypt.hash(newUser.password, saltRounds, function (err, hash) {
        // on remplace le password de l'objet par celui hashé
        newUser.password = hash;
        newUser.save((error, user) => {
            if (error) {
                res.status(500);
                console.log(error);
                res.json({
                    message: "Erreur serveur."
                });
            } else {
                res.status(201);
                res.json({
                    message: `Utilisateur crée : ${user.email}`
                });
            }
        });
    });

}

exports.userLogin = (req, res) => {
    // Rechercher l'utilisateur
    User.findOne({
        email: req.body.email
    }, (error, user) => {
        // Si l'utilisateur n'est pas trouvé
        if (error) {
            res.status(500);
            console.log(error);
            res.json({
                message: "Erreur serveur."
            });
        }
        // Si l'utilisateur est trouvé
        else {
            // Si l'email et le mot de passe correspondent
            if (user != null) {
                bcrypt.compare(req.body.password, user.password, function (err, result) {
                    if (result === true && user.email === req.body.email) {
                        jwt.sign({
                            user: {
                                id: user._id,
                                email: user.email,
                                role: user.role
                            }
                        }, process.env.JWT_KEY, {
                            expiresIn: "30 days"
                        }, (error, token) => {
                            if (error) {
                                res.status(500);
                                console.log(error);
                                res.json({
                                    message: "Erreur serveur."
                                });
                            } else {
                                res.status(200);
                                res.json({
                                    token
                                });
                            }
                        })
                    } else {
                        res.status(403);
                        console.log(error);
                        res.json({
                            message: "Authentification incorrect."
                        });
                    }
                });
            }
            // Si l'email et le mot de passe ne correspondent pas
            else {
                res.status(403);
                console.log(error);
                res.json({
                    message: "Authentification incorrect."
                });
            }
        }
    });
}