require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT;

// JWT için kullanılacak gizli anahtar
const secretKey = process.env.JWT_SECRET;

// MySQL veritabanı bağlantısı oluştur
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASSWORD,
  database: 'databaseJWT',
});

// MySQL bağlantısını kontrol et
connection.connect((err) => {
  if (err) {
    console.error('MySQL bağlantısı başarısız: ' + err.stack);
    return;
  }
  console.log('MySQL bağlantısı başarıyla gerçekleştirildi. Bağlantı ID: ' + connection.threadId);
});


// JSON verilerini işleyebilmek için middleware kullan
app.use(express.json());


// Dashboard sayfası
app.get('/dashboard', (req, res) => {
  res.send('<h1>Dashboard Sayfasındasınız</h1>');
});

/**
 * Kullanıcı kaydı endpoint'i
 * @param {string} email - Kullanıcının e-posta adresi
 * @param {string} password - Kullanıcının parolası
 * @param {boolean} is_verified - Kullanıcının doğrulama durumu
 * @returns {Object} - Başarı durumunu içeren JSON objesi
 */
app.post('/register', async (req, res) => {
  const { email, password, is_verified } = req.body;

 // Parolayı hashle
 const hashedPassword = await bcrypt.hash(password, 10);

// Kullanıcıyı veritabanına ekle
connection.query('INSERT INTO user (email, password, is_verified) VALUES (?,?,?)', [email, hashedPassword, is_verified], (error, results) => {
  if (error) throw error;
  res.json({ message: 'Kullanıcı başarıyla kaydedildi.' });
});
});

/**
 * Kullanıcı girişi ve JWT oluşturma endpoint'i
 * @param {string} email - Kullanıcının e-posta adresi
 * @param {string} password - Kullanıcının parolası
 * @returns {Object} - JWT tokenini içeren JSON objesi
 */
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
    // Kullanıcıyı veritabanından sorgula
    connection.query('SELECT * FROM user WHERE email = ?', [email], async (error, results) => {
      if (error) throw error;
  
      if (results.length > 0) {
        const user = results[0];
  
        // Parolayı karşılaştır
        const passwordMatch = await bcrypt.compare(password, user.password);
  
        if (passwordMatch) {
          // JWT oluştur
          const token = jwt.sign({ userId: user.id, email: user.email }, secretKey, { expiresIn: '1h' });
          res.json({ token });
        } else {
          res.status(401).json({ message: 'Kullanıcı adı veya parola geçersiz.' });
        }
      } else {
        res.status(401).json({ message: 'Kullanıcı adı veya parola geçersiz.' });
      }
    });
  });

/**
 * Korumalı bir endpoint örneği
 * @param {Object} req - Express request objesi
 * @param {Object} res - Express response objesi
 * @param {Function} next - Express next fonksiyonu
 * @returns {Object} - Başarı durumunu içeren JSON objesi
 */
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Bu endpointe erişim sağlandı.' });
});

/**
 * JWT doğrulama fonksiyonu
 * @param {Object} req - Express request objesi
 * @param {Object} res - Express response objesi
 * @param {Function} next - Express next fonksiyonu
 * @returns {Object} - Başarı durumunu içeren JSON objesi veya hata durumunu içeren JSON objesi
 */
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(403).json({ message: 'Yetkilendirme başarısız. Token bulunamadı.' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Yetkilendirme başarısız. Geçersiz token.' });
    }

    req.user = decoded;
    next();
  });
}


// Uygulamayı belirtilen portta dinle
app.listen(port, () => {
  console.log(`Server ${port} portunda çalışıyor`);
});