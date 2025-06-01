// Импорт зависимостей
const express = require('express'); // Веб-фреймворк для Node.js
const sqlite3 = require('sqlite3').verbose(); // Работа с SQLite БД
const bcrypt = require('bcrypt'); // Хэширование паролей
const jwt = require('jsonwebtoken'); // Генерация и валидация JWT-токенов
const path = require('path'); // Работа с путями файловой системы
const fs = require('fs').promises; // Асинхронный API для работы с файловой системой
const multer = require('multer'); // Мидлвар для загрузки файлов
const contentDisposition = require('content-disposition'); // Для установки заголовка Content-Disposition

// Кастомный модуль логирования
const logger = require('./server_modules/loging/logger.js');

const app = express(); // Создание экземпляра Express
const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret_key'; // Секретный ключ для подписи JWT (заменить в продакшене)

// Включаем поддержку JSON-запросов
app.use(express.json());

// Настройка хранилища для загружаемых файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Папка для сохранения файлов
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9); // Генерация уникального имени
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});

// Конфигурация загрузки файлов через multer
const upload = multer({
  storage,
  limits: { fileSize: 800 * 1024 * 1024 }, // Общий лимит: 800 МБ
  fileFilter: (req, file, cb) => {
    const allowedExtensions = [
      '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.rtf', '.txt',
      '.7z', '.zip', '.rar', '.jpg', '.jpeg', '.png', '.gif'
    ];
    const ext = path.extname(file.originalname).toLowerCase();
    // Проверка расширения
    if (!allowedExtensions.includes(ext)) {
      return cb(new Error('Недопустимый формат файла. Разрешены: doc, docx, ppt, pptx, xls, xlsx, rtf, txt, 7z, zip, rar, jpg, jpeg, png, gif'));
    }

    // Лимиты по типам файлов
    const sizeLimits = {
      '.doc': 300 * 1024 * 1024,
      '.docx': 300 * 1024 * 1024,
      '.ppt': 300 * 1024 * 1024,
      '.pptx': 300 * 1024 * 1024,
      '.xls': 300 * 1024 * 1024,
      '.xlsx': 300 * 1024 * 1024,
      '.7z': 800 * 1024 * 1024,
      '.zip': 800 * 1024 * 1024,
      '.rar': 800 * 1024 * 1024,
      '.rtf': 500 * 1024 * 1024,
      '.txt': 500 * 1024 * 1024,
      '.jpg': 10 * 1024 * 1024,
      '.jpeg': 10 * 1024 * 1024,
      '.png': 10 * 1024 * 1024,
      '.gif': 10 * 1024 * 1024,
    };
    const maxSize = sizeLimits[ext];
    // multer сам не передаёт `file.size` в fileFilter, это условие не сработает
    // Надо переместить проверку размера в middleware после загрузки

    cb(null, true); // Если всё ок
  },
});

// Логирование каждого входящего запроса
app.use((req, res, next) => {
  logger.logMessage(`Получен запрос: ${req.method} ${req.url}`);
  next();
});

// Middleware для проверки JWT-токена
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Получаем токен из заголовка Authorization
  if (!token) {
    logger.logMessage(`[ERROR] Токен отсутствует: ${req.method} ${req.url}`);
    return res.status(401).json({ error: 'Токен отсутствует' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logger.logMessage(`[ERROR] Недействительный токен: ${req.method} ${req.url}, ошибка: ${err.message}`);
      return res.status(401).json({ error: 'Недействительный токен', details: err.message });
    }
    req.user = user; // Добавляем пользователя в объект запроса
    logger.logMessage(`Пользователь аутентифицирован: ID ${req.user.id}, роль ${req.user.role}`);
    next();
  });
}

// Создание папки
app.post('/api/folder', authenticateToken, (req, res) => {
  const { name } = req.body;
  if (!name) {
    logger.logMessage(`[ERROR] Название папки обязательно`);
    return res.status(400).json({ error: 'Название папки обязательно' });
  }
  const validNameRegex = /^[а-яА-Яa-zA-Z0-9№;%:?*()_+\-=\., ]+$/;
  if (!validNameRegex.test(name)) {
    logger.logMessage(`[ERROR] Недопустимое название папки: ${name}`);
    return res.status(400).json({ error: 'Название папки содержит недопустимые символы' });
  }
  logger.logMessage(`Запрос на создание папки "${name}" от ID ${req.user.id}`);
  db.run(
    `INSERT INTO folders (name, created_by_id, created_at) VALUES (?, ?, ?)`,
    [name, req.user.id, new Date().toISOString()],
    function (err) {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка создания папки ${name}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      logger.logMessage(`Пользователь ID ${req.user.id} создал папку ${name} с ID ${this.lastID}`);
      res.json({ success: true, folderId: this.lastID });
    }
  );
});

// Получение списка папок
app.get('/api/folders', authenticateToken, (req, res) => {
  const { search } = req.query;
  let query = `
    SELECT f.id, f.name, f.created_at, u.username as created_by
    FROM folders f
    JOIN users u ON f.created_by_id = u.id
    WHERE f.created_by_id = ?
  `;
  let params = [req.user.id];
  if (search) {
    query += ` AND f.name LIKE ?`;
    params.push(`%${search}%`);
    logger.logMessage(`Поиск папок для ID ${req.user.id} с параметром search: ${search}`);
  }
  logger.logMessage(`Выполняется запрос к БД: ${query} с параметрами ${params.join(', ')}`);
  db.all(query, params, (err, folders) => {
    if (err) {
      logger.logMessage(`[ERROR] Ошибка получения списка папок: ${err.message}`);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    logger.logMessage(`Отправлен список папок (${folders.length}) для ID ${req.user.id}`);
    res.json(folders);
  });
});

// Обработка ошибок multer
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    logger.logMessage(`[ERROR] Ошибка загрузки файла: ${err.message}`);
    return res.status(400).json({ error: err.message });
  } else if (err) {
    logger.logMessage(`[ERROR] Ошибка: ${err.message}`);
    return res.status(400).json({ error: err.message });
  }
  next();
});

// Загрузка файла
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  const { filename, folder_id } = req.body;
  if (!req.file || !filename) {
    logger.logMessage(`[ERROR] Отсутствует файл или название: filename=${filename}`);
    return res.status(400).json({ error: 'Файл и название обязательны' });
  }
  const validNameRegex = /^[а-яА-Яa-zA-Z0-9№;%:?*()_+\-=\., ]+$/;
  if (!validNameRegex.test(filename)) {
    logger.logMessage(`[ERROR] Недопустимое название файла: ${filename}`);
    await fs.unlink(req.file.path).catch(err => logger.logMessage(`[ERROR] Ошибка удаления файла: ${err.message}`));
    return res.status(400).json({ error: 'Название файла содержит недопустимые символы' });
  }
  if (folder_id) {
    const folder = await new Promise((resolve, reject) => {
      logger.logMessage(`Проверка существования папки ID ${folder_id} для ID ${req.user.id}`);
      db.get(`SELECT id FROM folders WHERE id = ? AND created_by_id = ?`, [folder_id, req.user.id], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
    if (!folder) {
      logger.logMessage(`[ERROR] Папка ID ${folder_id} не найдена или не принадлежит пользователю ID ${req.user.id}`);
      await fs.unlink(req.file.path).catch(err => logger.logMessage(`[ERROR] Ошибка удаления файла: ${err.message}`));
      return res.status(404).json({ error: 'Папка не найдена' });
    }
  }

  // Добавляем проверку на существование файла с таким именем
  const existingFile = await new Promise((resolve, reject) => {
    logger.logMessage(`Проверка наличия файла с именем "${filename}" для ID ${req.user.id}`);
    db.get(
      `SELECT id FROM files WHERE filename = ? AND uploaded_by_id = ? AND (folder_id = ? OR (folder_id IS NULL AND ? IS NULL))`,
      [filename, req.user.id, folder_id || null, folder_id || null],
      (err, row) => {
        if (err) reject(err);
        else resolve(row);
      }
    );
  });

  if (existingFile) {
    logger.logMessage(`[ERROR] Файл с именем "${filename}" уже существует для ID ${req.user.id}`);
    await fs.unlink(req.file.path).catch(err => logger.logMessage(`[ERROR] Ошибка удаления файла: ${err.message}`));
    return res.status(400).json({ error: 'Файл с таким именем уже существует' });
  }

  const ext = path.extname(req.file.originalname).toLowerCase();
  try {
    logger.logMessage(`Сохранение файла "${filename}" в БД для ID ${req.user.id}, folder_id: ${folder_id || 'нет'}`);
    db.run(
      `INSERT INTO files (filename, originalname, path, format, size, uploaded_by_id, uploaded_at, folder_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        filename,
        req.file.originalname,
        req.file.path,
        ext.slice(1),
        req.file.size,
        req.user.id,
        new Date().toISOString(),
        folder_id || null,
      ],
      function (err) {
        if (err) {
          logger.logMessage(`[ERROR] Ошибка сохранения файла в БД: ${err.message}`);
          fs.unlink(req.file.path).catch(e => logger.logMessage(`[ERROR] Ошибка удаления файла: ${e.message}`));
          return res.status(500).json({ error: 'Ошибка сохранения файла' });
        }
        logger.logMessage(`Пользователь ID ${req.user.id} загрузил файл "${filename}" (ID ${this.lastID})`);
        res.json({ success: true, fileId: this.lastID });
      }
    );
  } catch (err) {
    logger.logMessage(`[ERROR] Ошибка обработки загрузки: ${err.message}`);
    fs.unlink(req.file.path).catch(e => logger.logMessage(`[ERROR] Ошибка удаления файла: ${e.message}`));
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Переименование файла
app.put('/api/file/:id/rename', authenticateToken, (req, res) => {
  const { filename } = req.body;
  const fileId = req.params.id;
  if (!filename) {
    logger.logMessage(`[ERROR] Название файла обязательно для ID ${fileId}`);
    return res.status(400).json({ error: 'Название файла обязательно' });
  }
  const validNameRegex = /^[а-яА-Яa-zA-Z0-9№;%:?*()_+\-=\., ]+$/;
  if (!validNameRegex.test(filename)) {
    logger.logMessage(`[ERROR] Недопустимое название файла: ${filename}`);
    return res.status(400).json({ error: 'Название файла содержит недопустимые символы' });
  }
  db.get(
    `SELECT uploaded_by_id FROM files WHERE id = ?`,
    [fileId],
    (err, file) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка проверки файла ID ${fileId}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (!file) {
        logger.logMessage(`[ERROR] Файл ID ${fileId} не найден`);
        return res.status(404).json({ error: 'Файл не найден' });
      }
      if (req.user.role !== 'admin' && req.user.id !== file.uploaded_by_id) {
        logger.logMessage(`[ERROR] Доступ запрещён для ID ${req.user.id}: требуется роль admin или быть владельцем файла`);
        return res.status(403).json({ error: 'Доступ запрещён' });
      }
      logger.logMessage(`Обновление имени файла ID ${fileId} на "${filename}" пользователем ID ${req.user.id}`);
      db.run(
        `UPDATE files SET filename = ? WHERE id = ?`,
        [filename, fileId],
        function (err) {
          if (err) {
            logger.logMessage(`[ERROR] Ошибка переименования файла ID ${fileId}: ${err.message}`);
            return res.status(500).json({ error: 'Ошибка сервера' });
          }
          if (this.changes === 0) {
            logger.logMessage(`[ERROR] Файл ID ${fileId} не найден для переименования`);
            return res.status(404).json({ error: 'Файл не найден' });
          }
          logger.logMessage(`Пользователь ID ${req.user.id} переименовал файл ID ${fileId} в "${filename}"`);
          res.json({ success: true });
        }
      );
    }
  );
});

// Получение списка файлов
app.get('/api/files', authenticateToken, async (req, res) => {
  const { folder_id, search } = req.query;
  try {
    await new Promise((resolve, reject) => {
      db.run('PRAGMA encoding = "UTF-8";', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    let query = `
      SELECT f.id, f.filename, f.format, f.size, f.uploaded_at, u.username as uploaded_by, f.folder_id
      FROM files f
      JOIN users u ON f.uploaded_by_id = u.id
      WHERE f.uploaded_by_id = ?
    `;
    let params = [req.user.id];
    if (folder_id) {
      query += ` AND f.folder_id = ?`;
      params.push(folder_id);
    } else {
      query += ` AND f.folder_id IS NULL`;
    }
    if (search) {
      query += ` AND f.filename LIKE ?`;
      params.push(`%${search}%`);
      logger.logMessage(`Поиск файлов для ID ${req.user.id} с параметром search: ${search}`);
    }
    logger.logMessage(`Выполняется запрос к БД: ${query} с параметрами ${params.join(', ')}`);
    db.all(query, params, (err, files) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка получения списка файлов: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      logger.logMessage(`Отправлен список файлов (${files.length}) для ID ${req.user.id}`);
      res.json(files);
    });
  } catch (err) {
    logger.logMessage(`[ERROR] Ошибка установки кодировки или получения списка файлов: ${err.message}`);
    return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
  }
});

// Получение списка всех файлов для общего доступа
app.get('/api/shared-files', authenticateToken, async (req, res) => {
  const { search } = req.query;
  try {
    await new Promise((resolve, reject) => {
      db.run('PRAGMA encoding = "UTF-8";', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    let query = `
      SELECT f.id, f.filename, f.format, f.size, f.uploaded_at, u.username as uploaded_by, f.folder_id
      FROM files f
      JOIN users u ON f.uploaded_by_id = u.id
    `;
    let params = [];
    if (search) {
      query += ` WHERE f.filename LIKE ?`;
      params.push(`%${search}%`);
      logger.logMessage(`Поиск общих файлов для ID ${req.user.id} с параметром search: ${search}`);
    }
    logger.logMessage(`Выполняется запрос к БД для общих файлов: ${query} с параметрами ${params.join(', ')}`);
    db.all(query, params, (err, files) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка получения списка общих файлов: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      logger.logMessage(`Отправлен список общих файлов (${files.length}) для ID ${req.user.id}`);
      res.json(files);
    });
  } catch (err) {
    logger.logMessage(`[ERROR] Ошибка установки кодировки или получения списка общих файлов: ${err.message}`);
    return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
  }
});

// Поиск файлов по имени для прикрепления в чат
app.get('/api/search-files', authenticateToken, (req, res) => {
  const { name } = req.query;
  if (!name) {
    logger.logMessage(`[ERROR] Название файла для поиска обязательно для ID ${req.user.id}`);
    return res.status(400).json({ error: 'Название файла обязательно' });
  }
  logger.logMessage(`Поиск файлов с именем "${name}" для ID ${req.user.id}`);
  db.all(
    `SELECT f.id, f.filename, f.format, f.size, f.uploaded_at, u.username as uploaded_by
     FROM files f
     JOIN users u ON f.uploaded_by_id = u.id
     WHERE f.uploaded_by_id = ? AND f.filename LIKE ?`,
    [req.user.id, `%${name}%`],
    (err, files) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка поиска файлов с именем "${name}": ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      logger.logMessage(`Найдено ${files.length} файлов с именем "${name}" для ID ${req.user.id}`);
      res.json(files);
    }
  );
});

// Скачивание файла
app.get('/api/download/:id', authenticateToken, async (req, res) => {
  const fileId = req.params.id;
  if (!fileId || isNaN(fileId)) {
    logger.logMessage(`[ERROR] Неверный ID файла: ${fileId}`);
    return res.status(400).json({ error: 'Неверный ID файла' });
  }
  try {
    logger.logMessage(`Запрос данных файла ID ${fileId} для скачивания пользователем ID ${req.user.id}`);
    const file = await new Promise((resolve, reject) => {
      db.get(
        `SELECT f.filename, f.path, f.format, u.username
         FROM files f
         JOIN users u ON f.uploaded_by_id = u.id
         WHERE f.id = ?`,
        [fileId],
        (err, file) => {
          if (err) reject(err);
          else resolve(file);
        }
      );
    });
    if (!file) {
      logger.logMessage(`[ERROR] Файл ID ${fileId} не найден в базе данных`);
      return res.status(404).json({ error: 'Файл не найден' });
    }
    try {
      await fs.access(file.path, fs.constants.F_OK | fs.constants.R_OK);
    } catch (err) {
      logger.logMessage(`[ERROR] Файл по пути ${file.path} недоступен: ${err.message}`);
      return res.status(500).json({ error: 'Файл недоступен на сервере', details: err.message });
    }
    const downloadName = file.filename;
    logger.logMessage(`Формируем заголовок Content-Disposition для файла "${downloadName}" (ID ${fileId})`);
    res.setHeader('Content-Disposition', contentDisposition(downloadName, {
      type: 'attachment',
      fallback: true,
    }));
    const mimeTypes = {
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'ppt': 'application/vnd.ms-powerpoint',
      'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'xls': 'application/vnd.ms-excel',
      'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'rtf': 'application/rtf',
      'txt': 'text/plain',
      '7z': 'application/x-7z-compressed',
      'zip': 'application/zip',
      'rar': 'application/x-rar-compressed',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
    };
    res.setHeader('Content-Type', mimeTypes[file.format] || 'application/octet-stream');
    res.sendFile(path.resolve(file.path), (err) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка отправки файла ID ${fileId} по пути ${file.path}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка скачивания файла', details: err.message });
      }
      logger.logMessage(`Пользователь ID ${req.user.id} скачал файл "${file.filename}" (ID ${fileId})`);
    });
  } catch (err) {
    logger.logMessage(`[ERROR] Ошибка обработки запроса скачивания файла ID ${fileId}: ${err.message}`);
    return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
  }
});

// Удаление файла
app.delete('/api/file/:id', authenticateToken, (req, res) => {
  logger.logMessage(`Запрос на удаление файла ID ${req.params.id} от пользователя ID ${req.user.id}`);
  db.get(
    `SELECT f.path, f.uploaded_by_id, f.filename, u.username
     FROM files f
     JOIN users u ON f.uploaded_by_id = u.id
     WHERE f.id = ?`,
    [req.params.id],
    (err, file) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка проверки файла ID ${req.params.id}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (!file) {
        logger.logMessage(`[ERROR] Файл ID ${req.params.id} не найден`);
        return res.status(404).json({ error: 'Файл не найден' });
      }
      if (req.user.role !== 'admin' && req.user.id !== file.uploaded_by_id) {
        logger.logMessage(`[ERROR] Доступ запрещён для ID ${req.user.id}: требуется роль admin или быть владельцем файла`);
        return res.status(403).json({ error: 'Доступ запрещён' });
      }
      db.run(`DELETE FROM files WHERE id = ?`, [req.params.id], async function (err) {
        if (err) {
          logger.logMessage(`[ERROR] Ошибка удаления файла ID ${req.params.id} из БД: ${err.message}`);
          return res.status(500).json({ error: 'Ошибка сервера' });
        }
        if (this.changes === 0) {
          logger.logMessage(`[ERROR] Файл ID ${req.params.id} не найден для удаления`);
          return res.status(404).json({ error: 'Файл не найден' });
        }
        try {
          await fs.unlink(file.path);
          logger.logMessage(`Пользователь ID ${req.user.id} удалил файл "${file.filename}" (ID ${req.params.id})`);
          res.json({ success: true });
        } catch (e) {
          logger.logMessage(`[ERROR] Ошибка удаления файла ${file.path}: ${e.message}`);
          res.status(500).json({ error: 'Ошибка удаления файла с сервера' });
        }
      });
    }
  );
});

// Получение списка пользователей (id и username) для фильтра
app.get('/api/users/list', authenticateToken, (req, res) => {
  logger.logMessage(`Запрос списка пользователей для фильтра от ID ${req.user.id}`);
  db.all(`SELECT id, username FROM users WHERE id != ? ORDER BY username`, [req.user.id], (err, users) => {
    if (err) {
      logger.logMessage(`[ERROR] Ошибка получения списка пользователей: ${err.message}`);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    logger.logMessage(`Отправлен список пользователей (${users.length}) для ID ${req.user.id}`);
    res.json(users);
  });
});

// Регистрация пользователя
app.post('/api/register', authenticateToken, (req, res) => {
  const { username, password, number, name, surname } = req.body;
  if (req.user.role !== 'admin') {
    logger.logMessage(`[ERROR] Доступ запрещён для ID ${req.user.id}: требуется роль admin`);
    return res.status(403).json({ error: 'Требуется роль администратора' });
  }
  if (!username || !password || !number) {
    logger.logMessage(`[ERROR] Недостаточно данных для регистрации: username=${username}, number=${number}`);
    return res.status(400).json({ error: 'Все поля обязательны' });
  }
  logger.logMessage(`Админ ID ${req.user.id} регистрирует нового пользователя: ${username}`);
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      logger.logMessage(`[ERROR] Ошибка хеширования пароля: ${err.message}`);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    db.run(
      `INSERT INTO users (username, password, number, name, surname, role) VALUES (?, ?, ?, ?, ?, ?)`,
      [username, hash, number, name || null, surname || null, 'user'],
      function (err) {
        if (err) {
          logger.logMessage(`[ERROR] Ошибка регистрации пользователя ${username}: ${err.message}`);
          return res.status(400).json({ error: 'Пользователь уже существует или ошибка данных' });
        }
        logger.logMessage(`Пользователь ${username} зарегистрирован админом ID ${req.user.id} с ID ${this.lastID}`);
        res.json({ success: true });
      }
    );
  });
});

// Авторизация пользователя
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    logger.logMessage(`[ERROR] Недостаточно данных для входа: username=${username}`);
    return res.status(400).json({ error: 'Логин и пароль обязательны' });
  }
  logger.logMessage(`Попытка входа пользователя ${username}`);
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) {
      logger.logMessage(`[ERROR] Ошибка базы данных при входе: ${err.message}`);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (!user) {
      logger.logMessage(`[ERROR] Пользователь ${username} не найден`);
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка сравнения паролей для ${username}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (!result) {
        logger.logMessage(`[ERROR] Неверный пароль для ${username}`);
        return res.status(401).json({ error: 'Неверный логин или пароль' });
      }
      const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
      logger.logMessage(`Пользователь ${username} (ID ${user.id}) вошёл в систему`);
      res.json({ token });
    });
  });
});

// Выход пользователя
app.post('/api/logout', authenticateToken, (req, res) => {
  logger.logMessage(`Пользователь ID ${req.user.id} вышел из системы`);
  res.json({ success: true });
});

// Получение информации о текущем пользователе
app.get('/api/user', authenticateToken, (req, res) => {
  logger.logMessage(`Запрос информации о пользователе ID ${req.user.id}`);
  db.get(
    `SELECT id, username, number, name, surname, role FROM users WHERE id = ?`,
    [req.user.id],
    (err, user) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка базы данных при получении пользователя ID ${req.user.id}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
      }
      if (!user) {
        logger.logMessage(`[ERROR] Пользователь ID ${req.user.id} не найден`);
        return res.status(404).json({ error: 'Пользователь не найден' });
      }
      logger.logMessage(`Информация о пользователе ID ${req.user.id} отправлена`);
      res.json(user);
    }
  );
});

// Проверка прав администратора
app.get('/api/check-admin', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    logger.logMessage(`[ERROR] Доступ запрещён для ID ${req.user.id}: требуется роль admin`);
    return res.status(403).json({ error: 'Требуется роль администратора' });
  }
  logger.logMessage(`Админ-доступ подтверждён для ID ${req.user.id}`);
  res.json({ success: true });
});

// Получение списка пользователей
app.get('/api/users', authenticateToken, (req, res) => {
  logger.logMessage(`Запрос списка всех пользователей от ID ${req.user.id}`);
  db.all(`SELECT id, username, number, name, surname FROM users`, [], (err, users) => {
    if (err) {
      logger.logMessage(`[ERROR] Ошибка базы данных при получении пользователей: ${err.message}`);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    logger.logMessage(`Список пользователей отправлен для ID ${req.user.id} (кол-во: ${users.length})`);
    res.json(users);
  });
});

// Получение данных пользователя по ID
app.get('/api/user/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    logger.logMessage(`[ERROR] Доступ запрещён для ID ${req.user.id}: требуется роль admin`);
    return res.status(403).json({ error: 'Требуется роль администратора' });
  }
  logger.logMessage(`Запрос данных пользователя ID ${req.params.id} от админа ID ${req.user.id}`);
  db.get(
    `SELECT id, username, number, surname FROM users WHERE id = ?`,
    [req.params.id],
    (err, user) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка базы данных при получении пользователя ID ${req.params.id}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (!user) {
        logger.logMessage(`[ERROR] Пользователь ID ${req.params.id} не найден`);
        return res.status(404).json({ error: 'Пользователь не найден' });
      }
      logger.logMessage(`Данные пользователя ID ${req.params.id} отправлены для ID ${req.user.id}`);
      res.json(user);
    }
  );
});

// Обновление данных пользователя
app.put('/api/user/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    logger.logMessage(`[ERROR] Доступ запрещён для ID ${req.user.id}: требуется роль admin`);
    return res.status(403).json({ error: 'Требуется роль администратора' });
  }
  const { username, password, number, name, surname } = req.body;
  if (!username || !number) {
    logger.logMessage(`[ERROR] Недостаточно данных для обновления пользователя ID ${req.params.id}`);
    return res.status(400).json({ error: 'Логин и номер телефона обязательны' });
  }
  const query = password
    ? `UPDATE users SET username = ?, password = ?, number = ?, name = ?, surname = ? WHERE id = ?`
    : `UPDATE users SET username = ?, number = ?, name = ?, surname = ? WHERE id = ?`;
  const params = password
    ? [username, bcrypt.hashSync(password, 10), number, name || null, surname || null, req.params.id]
    : [username, number, name || null, surname || null, req.params.id];
  logger.logMessage(`Обновление данных пользователя ID ${req.params.id} админом ID ${req.user.id}: ${query}`);
  db.run(query, params, function (err) {
    if (err) {
      logger.logMessage(`[ERROR] Ошибка обновления пользователя ID ${req.params.id}: ${err.message}`);
      return res.status(400).json({ error: 'Ошибка обновления данных' });
    }
    if (this.changes === 0) {
      logger.logMessage(`[ERROR] Пользователь ID ${req.params.id} не найден для обновления`);
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    logger.logMessage(`Пользователь ${username} обновлён админом ID ${req.user.id}`);
    res.json({ success: true });
  });
});

// Удаление пользователя
app.delete('/api/user/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    logger.logMessage(`[ERROR] Доступ запрещён для ID ${req.user.id}: требуется роль admin`);
    return res.status(403).json({ error: 'Требуется роль администратора' });
  }
  logger.logMessage(`Админ ID ${req.user.id} запрашивает удаление пользователя ID ${req.params.id}`);
  db.get(`SELECT id, username FROM users WHERE id = ?`, [req.params.id], (err, user) => {
    if (err) {
      logger.logMessage(`[ERROR] Ошибка базы данных при проверке пользователя ID ${req.params.id}: ${err.message}`);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (!user) {
      logger.logMessage(`[ERROR] Пользователь ID ${req.params.id} не найден`);
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    if (user.username === 'admin') {
      logger.logMessage(`[ERROR] Попытка удаления защищённого пользователя admin админом ID ${req.user.id}`);
      return res.status(403).json({ error: 'Нельзя удалить администратора' });
    }
    db.run(
      `DELETE FROM messages WHERE from_user_id = ? OR to_user_id = ?`,
      [user.id, user.id],
      function (err) {
        if (err) {
          logger.logMessage(`[ERROR] Ошибка удаления сообщений пользователя ID ${user.id}: ${err.message}`);
          return res.status(500).json({ error: 'Ошибка сервера' });
        }
        logger.logMessage(`Удалено ${this.changes} сообщений для пользователя ID ${user.id}`);
        db.run(`DELETE FROM group_members WHERE user_id = ?`, [user.id], function (err) {
          if (err) {
            logger.logMessage(`[ERROR] Ошибка удаления пользователя ID ${user.id} из групповых чатов: ${err.message}`);
            return res.status(500).json({ error: 'Ошибка сервера' });
          }
          db.run(`DELETE FROM files WHERE uploaded_by_id = ?`, [user.id], function (err) {
            if (err) {
              logger.logMessage(`[ERROR] Ошибка удаления файлов пользователя ID ${user.id}: ${err.message}`);
              return res.status(500).json({ error: 'Ошибка сервера' });
            }
            db.run(`DELETE FROM folders WHERE created_by_id = ?`, [user.id], function (err) {
              if (err) {
                logger.logMessage(`[ERROR] Ошибка удаления папок пользователя ID ${user.id}: ${err.message}`);
                return res.status(500).json({ error: 'Ошибка сервера' });
              }
              db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], function (err) {
                if (err) {
                  logger.logMessage(`[ERROR] Ошибка удаления пользователя ID ${req.params.id}: ${err.message}`);
                  return res.status(500).json({ error: 'Ошибка сервера' });
                }
                if (this.changes === 0) {
                  logger.logMessage(`[ERROR] Пользователь ID ${req.params.id} не найден для удаления`);
                  return res.status(404).json({ error: 'Пользователь не найден' });
                }
                logger.logMessage(`Пользователь ${user.username} и его данные удалены админом ID ${req.user.id}`);
                res.json({ success: true });
              });
            });
          });
        });
      }
    );
  });
});

// Создание группового чата
app.post('/api/group-chat', authenticateToken, (req, res) => {
  const { name, member_ids } = req.body;
  if (!name || !Array.isArray(member_ids) || member_ids.length > 100 || member_ids.length < 2) {
    logger.logMessage(`[ERROR] Недостаточно данных или превышен лимит участников для группы ${name}`);
    return res.status(400).json({ error: 'Название и участники (2-100) обязательны' });
  }
  logger.logMessage(`Создание группы "${name}" пользователем ID ${req.user.id} с участниками: ${member_ids.join(', ')}`);
  db.all(
    `SELECT id FROM users WHERE id IN (${member_ids.map(() => '?').join(',')})`,
    member_ids,
    (err, users) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка проверки участников группы: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (users.length !== member_ids.length) {
        logger.logMessage(`[ERROR] Один или несколько участников группы не найдены: ${member_ids.join(', ')}`);
        return res.status(400).json({ error: 'Один или несколько участников не найдены' });
      }
      db.run(
        `INSERT INTO group_chats (name, creator_id) VALUES (?, ?)`,
        [name, req.user.id],
        function (err) {
          if (err) {
            logger.logMessage(`[ERROR] Ошибка создания группового чата ${name}: ${err.message}`);
            return res.status(500).json({ error: 'Ошибка сервера' });
          }
          const groupId = this.lastID;
          const placeholders = member_ids.map(() => '(?, ?)').concat('(?, ?)').join(', ');
          const values = member_ids
            .reduce((acc, id) => [...acc, groupId, id], [])
            .concat([groupId, req.user.id]);
          db.run(
            `INSERT INTO group_members (group_id, user_id) VALUES ${placeholders}`,
            values,
            function (err) {
              if (err) {
                logger.logMessage(`[ERROR] Ошибка добавления участников в группу ${groupId}: ${err.message}`);
                return res.status(500).json({ error: 'Ошибка сервера' });
              }
              logger.logMessage(`Пользователь ID ${req.user.id} создал группу ${name} с ID ${groupId}`);
              res.json({ success: true, groupId });
            }
          );
        }
      );
    }
  );
});

// Получение списка групповых чатов пользователя
app.get('/api/group-chats', authenticateToken, (req, res) => {
  logger.logMessage(`Запрос списка групповых чатов от ID ${req.user.id}`);
  db.all(
    `SELECT gc.id, gc.name, gc.creator_id
     FROM group_chats gc
     JOIN group_members gm ON gc.id = gm.group_id
     WHERE gm.user_id = ?`,
    [req.user.id],
    (err, groups) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка получения групповых чатов для ID ${req.user.id}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      logger.logMessage(`Отправлено ${groups.length} групповых чатов для ID ${req.user.id}`);
      res.json(groups);
    }
  );
});

// Отправка сообщения (личного или группового) с возможностью прикрепления файла
app.post('/api/message', authenticateToken, (req, res) => {
  const { to_user_id, group_id, message, timestamp, attached_file_id } = req.body;
  const from_user_id = req.user.id;
  if (!message || !timestamp) {
    logger.logMessage(`[ERROR] Отсутствуют обязательные поля для сообщения от ID ${from_user_id}: message=${message}, timestamp=${timestamp}`);
    return res.status(400).json({ error: 'Сообщение и временная метка обязательны' });
  }
  if (!to_user_id && !group_id) {
    logger.logMessage(`[ERROR] Не указан получатель для сообщения от ID ${from_user_id}: to_user_id=${to_user_id}, group_id=${group_id}`);
    return res.status(400).json({ error: 'Укажите получателя (to_user_id или group_id)' });
  }
  if (to_user_id && group_id) {
    logger.logMessage(`[ERROR] Указаны одновременно to_user_id=${to_user_id} и group_id=${group_id} для сообщения от ID ${from_user_id}`);
    return res.status(400).json({ error: 'Укажите только одного получателя: to_user_id или group_id' });
  }

  // Если есть attached_file_id, проверяем, что файл принадлежит отправителю
  if (attached_file_id) {
    logger.logMessage(`Проверка файла ID ${attached_file_id} для прикрепления в сообщение от ID ${from_user_id}`);
    db.get(
      `SELECT id FROM files WHERE id = ? AND uploaded_by_id = ?`,
      [attached_file_id, from_user_id],
      (err, file) => {
        if (err) {
          logger.logMessage(`[ERROR] Ошибка проверки файла ID ${attached_file_id}: ${err.message}`);
          return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
        }
        if (!file) {
          logger.logMessage(`[ERROR] Файл ID ${attached_file_id} не найден или не принадлежит ID ${from_user_id}`);
          return res.status(404).json({ error: 'Файл не найден или доступ запрещён' });
        }
        sendMessage();
      }
    );
  } else {
    sendMessage();
  }

  function sendMessage() {
    if (to_user_id) {
      logger.logMessage(`Отправка личного сообщения от ID ${from_user_id} пользователю ID ${to_user_id}`);
      db.get(`SELECT id FROM users WHERE id = ?`, [to_user_id], (err, user) => {
        if (err) {
          logger.logMessage(`[ERROR] Ошибка проверки получателя ID ${to_user_id}: ${err.message}`);
          return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
        }
        if (!user) {
          logger.logMessage(`[ERROR] Получатель ID ${to_user_id} не найден`);
          return res.status(404).json({ error: 'Получатель не найден' });
        }
        db.run(
          `INSERT INTO messages (from_user_id, to_user_id, message, timestamp, is_read, attached_file_id) VALUES (?, ?, ?, ?, ?, ?)`,
          [from_user_id, to_user_id, message, timestamp, 0, attached_file_id || null],
          function (err) {
            if (err) {
              logger.logMessage(`[ERROR] Ошибка сохранения личного сообщения от ID ${from_user_id} для ID ${to_user_id}: ${err.message}`);
              return res.status(500).json({ error: 'Ошибка сохранения сообщения', details: err.message });
            }
            logger.logMessage(`Пользователь ID ${from_user_id} отправил сообщение пользователю ID ${to_user_id}: ${message}${attached_file_id ? ` (с файлом ID ${attached_file_id})` : ''}`);
            res.json({ success: true, messageId: this.lastID });
          }
        );
      });
    } else if (group_id) {
      logger.logMessage(`Отправка группового сообщения от ID ${from_user_id} в группу ID ${group_id}`);
      db.get(`SELECT id FROM group_chats WHERE id = ?`, [group_id], (err, group) => {
        if (err) {
          logger.logMessage(`[ERROR] Ошибка проверки группы ${group_id}: ${err.message}`);
          return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
        }
        if (!group) {
          logger.logMessage(`[ERROR] Группа ${group_id} не найдена`);
          return res.status(404).json({ error: 'Группа не найдена' });
        }
        db.get(
          `SELECT user_id FROM group_members WHERE group_id = ? AND user_id = ?`,
          [group_id, from_user_id],
          (err, member) => {
            if (err) {
              logger.logMessage(`[ERROR] Ошибка проверки участника группы ${group_id} для ID ${from_user_id}: ${err.message}`);
              return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
            }
            if (!member) {
              logger.logMessage(`[ERROR] Пользователь ID ${from_user_id} не является участником группы ${group_id}`);
              return res.status(403).json({ error: 'Вы не участник этой группы' });
            }
            db.run(
              `INSERT INTO messages (from_user_id, group_id, message, timestamp, is_read, attached_file_id) VALUES (?, ?, ?, ?, ?, ?)`,
              [from_user_id, group_id, message, timestamp, 0, attached_file_id || null],
              function (err) {
                if (err) {
                  logger.logMessage(`[ERROR] Ошибка сохранения группового сообщения в группу ${group_id} от ID ${from_user_id}: ${err.message}`);
                  return res.status(500).json({ error: 'Ошибка сохранения сообщения', details: err.message });
                }
                logger.logMessage(`Пользователь ID ${from_user_id} отправил сообщение в группу ${group_id}: ${message}${attached_file_id ? ` (с файлом ID ${attached_file_id})` : ''}`);
                res.json({ success: true, messageId: this.lastID });
              }
            );
          }
        );
      });
    }
  }
});

// Получение сообщений (личных или групповых)
app.get('/api/messages', authenticateToken, (req, res) => {
  const { with: withUserId, group_id } = req.query;
  const currentUserId = req.user.id;

  if (!withUserId && !group_id) {
    logger.logMessage(`[ERROR] Параметр with или group_id обязателен для ID ${currentUserId}`);
    return res.status(400).json({ error: 'Параметр with или group_id обязателен' });
  }

  if (withUserId === '*') {
    logger.logMessage(`Запрос всех сообщений для ID ${currentUserId}`);
    db.all(
      `SELECT m.id, m.from_user_id, m.to_user_id, m.group_id, m.message, m.timestamp, m.is_read, u1.username as from_username, u2.username as to_username
       FROM messages m
       LEFT JOIN users u1 ON m.from_user_id = u1.id
       LEFT JOIN users u2 ON m.to_user_id = u2.id
       WHERE (m.to_user_id = ? OR m.from_user_id = ? OR m.group_id IN (
         SELECT group_id FROM group_members WHERE user_id = ?
       ))
       ORDER BY m.timestamp ASC`,
      [currentUserId, currentUserId, currentUserId],
      (err, messages) => {
        if (err) {
          logger.logMessage(`[ERROR] Ошибка получения всех сообщений для ID ${currentUserId}: ${err.message}`);
          return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
        }
        logger.logMessage(`Отправлено ${messages.length} сообщений для ID ${currentUserId} (все чаты)`);
        res.json(messages);
      }
    );
  } else if (withUserId) {
    logger.logMessage(`Запрос личных сообщений между ID ${currentUserId} и ID ${withUserId}`);
    db.get(`SELECT id FROM users WHERE id = ?`, [withUserId], (err, user) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка проверки пользователя ID ${withUserId}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
      }
      if (!user) {
        logger.logMessage(`[ERROR] Пользователь ID ${withUserId} не найден`);
        return res.status(404).json({ error: 'Пользователь не найден' });
      }
      db.all(
        `SELECT m.id, m.from_user_id, m.to_user_id, m.message, m.timestamp, m.is_read, u1.username as from_username, u2.username as to_username
         FROM messages m
         LEFT JOIN users u1 ON m.from_user_id = u1.id
         LEFT JOIN users u2 ON m.to_user_id = u2.id
         WHERE (m.from_user_id = ? AND m.to_user_id = ?) OR (m.from_user_id = ? AND m.to_user_id = ?)
         ORDER BY m.timestamp ASC`,
        [currentUserId, withUserId, withUserId, currentUserId],
        (err, messages) => {
          if (err) {
            logger.logMessage(`[ERROR] Ошибка получения личных сообщений для ID ${currentUserId} и ID ${withUserId}: ${err.message}`);
            return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
          }
          logger.logMessage(`Обновление статуса прочтения сообщений для ID ${currentUserId} от ID ${withUserId}`);
          db.run(
            `UPDATE messages 
             SET is_read = 1 
             WHERE to_user_id = ? AND from_user_id = ? AND is_read = 0`,
            [currentUserId, withUserId],
            function (err) {
              if (err) {
                logger.logMessage(`[ERROR] Ошибка обновления статуса прочтения для ID ${currentUserId} и ID ${withUserId}: ${err.message}`);
              } else {
                logger.logMessage(`Обновлено ${this.changes} сообщений как прочитанные для ID ${currentUserId} от ID ${withUserId}`);
              }
              logger.logMessage(`Отправлено ${messages.length} личных сообщений для ID ${currentUserId} и ID ${withUserId}`);
              res.json(messages);
            }
          );
        }
      );
    });
  } else if (group_id) {
    logger.logMessage(`Запрос групповых сообщений для группы ${group_id} от ID ${currentUserId}`);
    db.get(`SELECT id FROM group_chats WHERE id = ?`, [group_id], (err, group) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка проверки группы ${group_id}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
      }
      if (!group) {
        logger.logMessage(`[ERROR] Группа ${group_id} не найдена`);
        return res.status(404).json({ error: 'Группа не найдена' });
      }
      db.get(
        `SELECT user_id FROM group_members WHERE group_id = ? AND user_id = ?`,
        [group_id, currentUserId],
        (err, member) => {
          if (err) {
            logger.logMessage(`[ERROR] Ошибка проверки участника группы ${group_id} для ID ${currentUserId}: ${err.message}`);
            return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
          }
          if (!member) {
            logger.logMessage(`[ERROR] Пользователь ID ${currentUserId} не является участником группы ${group_id}`);
            return res.status(403).json({ error: 'Вы не участник этой группы' });
          }
          db.all(
            `SELECT m.id, m.from_user_id, m.group_id, m.message, m.timestamp, m.is_read, u.username as from_username
             FROM messages m
             LEFT JOIN users u ON m.from_user_id = u.id
             WHERE m.group_id = ?
             ORDER BY m.timestamp ASC`,
            [group_id],
            (err, messages) => {
              if (err) {
                logger.logMessage(`[ERROR] Ошибка получения групповых сообщений для группы ${group_id}: ${err.message}`);
                return res.status(500).json({ error: 'Ошибка сервера', details: err.message });
              }
              logger.logMessage(`Обновление статуса прочтения сообщений в группе ${group_id} для ID ${currentUserId}`);
              db.run(
                `UPDATE messages 
                 SET is_read = 1 
                 WHERE group_id = ? AND from_user_id != ? AND is_read = 0`,
                [group_id, currentUserId],
                function (err) {
                  if (err) {
                    logger.logMessage(`[ERROR] Ошибка обновления статуса прочтения для группы ${group_id}: ${err.message}`);
                  } else {
                    logger.logMessage(`Обновлено ${this.changes} сообщений как прочитанные в группе ${group_id} для ID ${currentUserId}`);
                  }
                  logger.logMessage(`Отправлено ${messages.length} групповых сообщений для группы ${group_id}`);
                  res.json(messages);
                }
              );
            }
          );
        }
      );
    });
  }
});

// Получение количества непрочитанных сообщений
app.get('/api/unread-messages', authenticateToken, (req, res) => {
  const currentUserId = req.user.id;
  logger.logMessage(`Запрос количества непрочитанных сообщений для ID ${currentUserId}`);
  db.all(
    `SELECT m.from_user_id, u.username as from_username, COUNT(*) as count
     FROM messages m
     JOIN users u ON m.from_user_id = u.id
     WHERE m.to_user_id = ? AND m.is_read = 0
     GROUP BY m.from_user_id`,
    [currentUserId],
    (err, unreadPersonal) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка получения непрочитанных личных сообщений для ID ${currentUserId}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      db.all(
        `SELECT m.group_id, COUNT(*) as count
         FROM messages m
         JOIN group_members gm ON m.group_id = gm.group_id
         WHERE gm.user_id = ? AND m.is_read = 0 AND m.from_user_id != ?
         GROUP BY m.group_id`,
        [currentUserId, currentUserId],
        (err, unreadGroup) => {
          if (err) {
            logger.logMessage(`[ERROR] Ошибка получения непрочитанных групповых сообщений для ID ${currentUserId}: ${err.message}`);
            return res.status(500).json({ error: 'Ошибка сервера' });
          }
          if (unreadPersonal.length > 0 || unreadGroup.length > 0) {
            logger.logMessage(
              `Отправлены данные о непрочитанных сообщениях для ID ${currentUserId}: ` +
              `личных=${unreadPersonal.length}, групповых=${unreadGroup.length}`
            );
          }
          res.json({ personal: unreadPersonal, group: unreadGroup });
        }
      );
    }
  );
});

// Удаление чата (личного или группового)
app.post('/api/delete-chat', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    logger.logMessage(`[ERROR] Доступ запрещён для ID ${req.user.id}: требуется роль admin`);
    return res.status(403).json({ error: 'Требуется роль администратора' });
  }
  const { user_id, group_id } = req.body;
  const currentUserId = req.user.id;

  if (!user_id && !group_id) {
    logger.logMessage(`[ERROR] Не указан user_id или group_id для удаления чата админом ID ${currentUserId}`);
    return res.status(400).json({ error: 'Укажите user_id или group_id' });
  }
  if (user_id && group_id) {
    logger.logMessage(`[ERROR] Указаны одновременно user_id=${user_id} и group_id=${group_id} для удаления чата`);
    return res.status(400).json({ error: 'Укажите только один параметр: user_id или group_id' });
  }

  if (user_id) {
    logger.logMessage(`Админ ID ${currentUserId} запрашивает удаление чата с пользователем ID ${user_id}`);
    db.get(`SELECT id FROM users WHERE id = ?`, [user_id], (err, user) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка проверки пользователя ID ${user_id} для удаления чата: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (!user) {
        logger.logMessage(`[ERROR] Пользователь ID ${user_id} не найден для удаления чата`);
        return res.status(404).json({ error: 'Пользователь не найден' });
      }
      db.run(
        `DELETE FROM messages 
         WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)`,
        [currentUserId, user_id, user_id, currentUserId],
        function (err) {
          if (err) {
            logger.logMessage(`[ERROR] Ошибка удаления чата между ID ${currentUserId} и ID ${user_id}: ${err.message}`);
            return res.status(500).json({ error: 'Ошибка сервера' });
          }
          logger.logMessage(`Админ ID ${currentUserId} удалил чат с пользователем ID ${user_id} (${this.changes} сообщений)`);
          res.json({ success: true });
        }
      );
    });
  } else if (group_id) {
    logger.logMessage(`Админ ID ${currentUserId} запрашивает удаление группы ${group_id}`);
    db.get(`SELECT id FROM group_chats WHERE id = ?`, [group_id], (err, group) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка проверки группы ${group_id} для удаления: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (!group) {
        logger.logMessage(`[ERROR] Группа ${group_id} не найдена для удаления`);
        return res.status(404).json({ error: 'Группа не найдена' });
      }
      db.run(`DELETE FROM messages WHERE group_id = ?`, [group_id], function (err) {
        if (err) {
          logger.logMessage(`[ERROR] Ошибка удаления сообщений группы ${group_id}: ${err.message}`);
          return res.status(500).json({ error: 'Ошибка сервера' });
        }
        logger.logMessage(`Удалено ${this.changes} сообщений для группы ${group_id}`);
        db.run(`DELETE FROM group_members WHERE group_id = ?`, [group_id], function (err) {
          if (err) {
            logger.logMessage(`[ERROR] Ошибка удаления участников группы ${group_id}: ${err.message}`);
            return res.status(500).json({ error: 'Ошибка сервера' });
          }
          db.run(`DELETE FROM group_chats WHERE id = ?`, [group_id], function (err) {
            if (err) {
              logger.logMessage(`[ERROR] Ошибка удаления группы ${group_id}: ${err.message}`);
              return res.status(500).json({ error: 'Ошибка сервера' });
            }
            logger.logMessage(`Админ ID ${currentUserId} удалил группу ${group_id}`);
            res.json({ success: true });
          });
        });
      });
    });
  }
});

// Очистка всех сообщений (только для админа)
app.post('/api/clear-messages', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    logger.logMessage(`[ERROR] Доступ запрещён для ID ${req.user.id}: требуется роль admin`);
    return res.status(403).json({ error: 'Требуется роль администратора' });
  }
  logger.logMessage(`Админ ID ${req.user.id} запрашивает очистку всех сообщений`);
  db.run(`DELETE FROM messages`, [], function (err) {
    if (err) {
      logger.logMessage(`[ERROR] Ошибка очистки сообщений: ${err.message}`);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    logger.logMessage(`Админ ID ${req.user.id} удалил все сообщения (${this.changes})`);
    res.json({ success: true });
  });
});

// Предпросмотр изображения (с авторизацией)
app.get('/api/preview/:id', authenticateToken, async (req, res) => {
  const fileId = req.params.id;
  if (!fileId || isNaN(fileId)) {
    logger.logMessage(`[ERROR] Неверный ID файла для предпросмотра: ${fileId}`);
    return res.status(400).json({ error: 'Неверный ID файла' });
  }
  try {
    logger.logMessage(`Запрос предпросмотра файла ID ${fileId} пользователем ID ${req.user.id}`);
    const file = await new Promise((resolve, reject) => {
      db.get(
        `SELECT f.filename, f.path, f.format
         FROM files f
         WHERE f.id = ? AND f.uploaded_by_id = ?`,
        [fileId, req.user.id],
        (err, file) => {
          if (err) reject(err);
          else resolve(file);
        }
      );
    });
    if (!file) {
      logger.logMessage(`[ERROR] Файл ID ${fileId} не найден или не принадлежит ID ${req.user.id}`);
      return res.status(404).json({ error: 'Файл не найден' });
    }
    const allowedFormats = ['jpg', 'jpeg', 'png', 'gif'];
    if (!allowedFormats.includes(file.format.toLowerCase())) {
      logger.logMessage(`[ERROR] Файл ID ${fileId} не является изображением`);
      return res.status(400).json({ error: 'Файл не является изображением' });
    }
    try {
      await fs.access(file.path, fs.constants.F_OK | fs.constants.R_OK);
    } catch (err) {
      logger.logMessage(`[ERROR] Файл по пути ${file.path} недоступен: ${err.message}`);
      return res.status(500).json({ error: 'Файл недоступен на сервере' });
    }
    const mimeTypes = {
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
    };
    res.setHeader('Content-Type', mimeTypes[file.format.toLowerCase()] || 'application/octet-stream');
    res.sendFile(path.resolve(file.path), (err) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка отправки файла ID ${fileId}: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка отправки файла' });
      }
      logger.logMessage(`Пользователь ID ${req.user.id} просмотрел файл ID ${fileId}`);
    });
  } catch (err) {
    logger.logMessage(`[ERROR] Ошибка обработки предпросмотра файла ID ${fileId}: ${err.message}`);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Публичный предпросмотр изображения (без авторизации)
app.get('/api/public/preview/:id', async (req, res) => {
  const fileId = req.params.id;
  if (!fileId || isNaN(fileId)) {
    logger.logMessage(`[ERROR] Неверный ID файла для публичного предпросмотра: ${fileId}`);
    return res.status(400).json({ error: 'Неверный ID файла' });
  }
  try {
    logger.logMessage(`Запрос публичного предпросмотра файла ID ${fileId}`);
    const file = await new Promise((resolve, reject) => {
      db.get(
        `SELECT f.filename, f.path, f.format
         FROM files f
         WHERE f.id = ?`,
        [fileId],
        (err, file) => {
          if (err) reject(err);
          else resolve(file);
        }
      );
    });
    if (!file) {
      logger.logMessage(`[ERROR] Файл ID ${fileId} не найден для публичного предпросмотра`);
      return res.status(404).json({ error: 'Файл не найден' });
    }
    const allowedFormats = ['jpg', 'jpeg', 'png', 'gif'];
    if (!allowedFormats.includes(file.format.toLowerCase())) {
      logger.logMessage(`[ERROR] Файл ID ${fileId} не является изображением`);
      return res.status(400).json({ error: 'Файл не является изображением' });
    }
    try {
      await fs.access(file.path, fs.constants.F_OK | fs.constants.R_OK);
    } catch (err) {
      logger.logMessage(`[ERROR] Файл по пути ${file.path} недоступен: ${err.message}`);
      return res.status(500).json({ error: 'Файл недоступен на сервере' });
    }
    const mimeTypes = {
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
    };
    res.setHeader('Content-Type', mimeTypes[file.format.toLowerCase()] || 'application/octet-stream');
    res.sendFile(path.resolve(file.path), (err) => {
      if (err) {
        logger.logMessage(`[ERROR] Ошибка отправки файла ID ${fileId} для публичного предпросмотра: ${err.message}`);
        return res.status(500).json({ error: 'Ошибка отправки файла' });
      }
      logger.logMessage(`Публичный предпросмотр файла ID ${fileId} выполнен`);
    });
  } catch (err) {
    logger.logMessage(`[ERROR] Ошибка обработки публичного предпросмотра файла ID ${fileId}: ${err.message}`);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Обслуживание корневого маршрута
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'indexmain.html'));
});

// Статические файлы
app.use(express.static(path.join(__dirname, 'public')));

// Дополнительный маршрут для иконок с логированием (только ошибки)
app.use('/public/icons', (req, res, next) => {
  express.static(path.join(__dirname, 'public', 'icons'))(req, res, (err) => {
    if (err) {
      logger.logMessage(`[ERROR] Ошибка доступа к иконке ${req.originalUrl}: ${err.message}`);
      return res.status(404).json({ error: 'Иконка не найдена' });
    }
    next();
  });
});

// Подключение к базе данных
const db = require('./database.js');

// Создание папки uploads
fs.mkdir(path.join(__dirname, 'uploads'), { recursive: true }).catch(err => {
  logger.logMessage(`[ERROR] Ошибка создания папки uploads: ${err.message}`);
});

// Запуск сервера
logger.rotateLogs().then(() => {
  const server = app.listen(PORT, () => {
    logger.logMessage(`Сервер запущен на порту ${PORT}`);
    console.log(`Сервер запущен на порту ${PORT}`);
  });

  // Обработка остановки сервера
  process.on('SIGINT', () => {
    console.log('Сервер останавливается...');
    logger.logMessage('Сервер остановлен')
      .then(() => {
        db.close((err) => {
          if (err) {
            console.error('Ошибка закрытия базы данных:', err.message);
          }
          console.log('База данных закрыта.');
          server.close(() => {
            console.log('Сервер полностью остановлен.');
            process.exit(0);
          });
        });
      })
      .catch(err => {
        console.error('Ошибка записи лога при остановке:', err.message);
        db.close();
        server.close(() => process.exit(1));
      });
  });
});