const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'votre_secret_jwt'; // À stocker dans les variables d'environnement

app.use(cors());
app.use(bodyParser.json());

// Base de données en mémoire pour l'exemple
const users = [];

// Route d'inscription
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
        return res.status(400).json({ message: 'Utilisateur déjà existant.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { id: users.length + 1, username, password: hashedPassword };
    users.push(user);
    res.status(201).json({ message: 'Utilisateur créé avec succès.' });
});

// Route de connexion
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Utilisateur non trouvé.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Mot de passe incorrect.' });
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Middleware de vérification JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Route de mise à jour des informations utilisateur
app.put('/api/auth/user', authenticateToken, async (req, res) => {
    const { oldPassword, username, password } = req.body;
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ message: 'Utilisateur non trouvé.' });
    }

    // Vérifier oldPassword si présent
    if (oldPassword) {
      const isMatch = await bcrypt.compare(oldPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Ancien mot de passe incorrect.' });
      }
    }

    if (username) {
      user.username = username;
    }

    if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        return res.json({ message: 'Mot de passe mis à jour avec succès.' });
    }
    
    // Si on arrive ici, c’est qu’il n’y a pas de nouveau mdp, mais peut-être juste un nouveau username
    return res.json({ message: 'Utilisateur mis à jour avec succès.' });
});

// Démarrage du serveur
app.listen(PORT, () => {
    console.log(`Serveur démarré sur le port ${PORT}`);
});
