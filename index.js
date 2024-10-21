require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();
const port = 5000;

// Connexion à MongoDB
mongoose.connect('mongodb://localhost/meteo', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connexion à MongoDB réussie'))
  .catch(err => console.error('Erreur de connexion à MongoDB:', 
 err));

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Définition d'un schéma MongoDB
const MeteoSchema = new mongoose.Schema({
    id_station: String,
    dh_utc: String,
    temperature: String,
    pression: String,
    humidite: String,
    point_de_rosee: String,
    vent_moyen: String,
    vent_rafales: String,
    vent_direction: String,
    pluie_3h: String,
    pluie_1h: String
});

const Meteo = mongoose.model('Meteo', MeteoSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User',userSchema);

//JWT token
// Fonction pour générer un JWT
function generateAccessToken(user) {
    return jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1h' });
}
// Middleware pour vérifier le JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (token == null) return res.sendStatus(401); 
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403); 
      req.user = user;
      next();
  
    });
  }

// Routes
app.get('/data',authenticateToken, async (req, res) => {
  const meteo = await Meteo.find();
  res.json(meteo);
});

app.post('/data',authenticateToken, async (req, res) => {
  const newMeteo = new Meteo(req.body); 
  console.log(newMeteo);

  const savedMeteo = await newMeteo.save();
  res.json(savedMeteo);
});

app.get('/data/:id',authenticateToken, (req, res) => {
    const id = req.params.id;
    console.log(id)
    Meteo.find({ id_station:id })
        .then(documents => {
            res.json(documents);
        })
        .catch(error => {
            console.error(error);
            res.status(500).json({ error: 'Erreur lors de la récupération des données' });
        });
});


app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    console.log(req.body);
    try {
        // Hasher le mot de passe avant de l'enregistrer
        const saltRounds = 10; // Ajustez le nombre de rounds selon vos besoins de sécurité
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Utilisateur créé avec succès' });
    } catch (err) {
        // Mongoose gère les erreurs de validation et d'unicité
        console.error(err);
        res.status(400).json({ message: err.message });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ 
                message: 'Utilisateur introuvable' });
        }
    
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Mot de passe incorrect' });
        }
    
            // Générer un JWT
            const token = generateAccessToken({ userId: user._id });
            res.json({ token });
        } catch (err) {
            console.error(err);
            res.status(500).json({ message: 'Erreur lors de la connexion' });
        }
});
  
app.listen(port, () => {
  console.log(`Serveur en écoute sur le port ${port}`);
});