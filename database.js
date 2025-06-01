// Импорт библиотеки SQLite3 и активация режима подробных сообщений об ошибках
const sqlite3 = require('sqlite3').verbose();

// Импорт библиотеки bcrypt для хеширования паролей
const bcrypt = require('bcrypt');

// Открытие или создание базы данных corpportal.db
const db = new sqlite3.Database('./corpportal.db', (err) => {
  if (err) console.error('Error opening database:', err.message);
  else console.log('Connected to SQLite database.');
});

// Последовательное выполнение запросов (гарантирует порядок)
db.serialize(() => {
  // Создание таблицы пользователей, если она ещё не существует
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,         -- Уникальный идентификатор пользователя
      username TEXT NOT NULL UNIQUE,                -- Логин (уникальный)
      password TEXT NOT NULL,                       -- Хешированный пароль
      number TEXT NOT NULL,                         -- Телефонный номер
      role TEXT NOT NULL CHECK(role IN ('admin', 'user')), -- Роль (админ или обычный пользователь)
      name TEXT,                                    -- Имя пользователя (опционально)
      surname TEXT                                  -- Фамилия пользователя (опционально)
    )
  `);

  // Проверка наличия пользователя "admin"
  db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
    // Если админа нет — создаём его
    if (!row) {
      // Хешируем пароль 'admin123'
      bcrypt.hash('admin123', 10, (err, hash) => {
        if (err) return console.error('Error hashing admin password:', err);

        // Вставка нового пользователя-админа в базу
        db.run(
          'INSERT INTO users (username, password, number, role) VALUES (?, ?, ?, ?)',
          ['admin', hash, '1234567890', 'admin'],
          (err) => {
            if (err) console.error('Error inserting admin:', err);
            else console.log('Default admin created: admin/admin123');
          }
        );
      });
    }
  });

  // Создание таблицы сообщений, если не существует
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,         -- Уникальный ID сообщения
      from_user_id INTEGER NOT NULL,                -- Отправитель (ID пользователя)
      to_user_id INTEGER,                           -- Получатель (опционально)
      group_id INTEGER,                             -- ID группового чата (если сообщение в группе)
      message TEXT NOT NULL,                        -- Текст сообщения
      timestamp TEXT NOT NULL,                      -- Время отправки (строка)
      is_read INTEGER DEFAULT 0,                    -- Признак прочтения (0 — не прочитано)
      attached_file_id INTEGER,                     -- ID вложенного файла (если есть)
      FOREIGN KEY (from_user_id) REFERENCES users(id),
      FOREIGN KEY (to_user_id) REFERENCES users(id),
      FOREIGN KEY (group_id) REFERENCES group_chats(id),
      FOREIGN KEY (attached_file_id) REFERENCES files(id)
    )
  `);

  // Проверка и добавление столбца attached_file_id, если его нет
  db.all(`PRAGMA table_info(messages)`, (err, columns) => {
    if (err) {
      console.error('Error checking messages table:', err);
      return;
    }
    const hasAttachedFileId = Array.isArray(columns) && columns.some(col => col.name === 'attached_file_id');
    if (!hasAttachedFileId) {
      db.run(`ALTER TABLE messages ADD COLUMN attached_file_id INTEGER REFERENCES files(id)`, (err) => {
        if (err) console.error('Error adding attached_file_id column:', err);
        else console.log('Added attached_file_id column to messages table');
      });
    } else {
      console.log('Column attached_file_id already exists in messages table');
    }
  });

  // Таблица групповых чатов
  db.run(`
    CREATE TABLE IF NOT EXISTS group_chats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,     -- ID группы
      name TEXT NOT NULL,                       -- Название группы
      creator_id INTEGER NOT NULL,              -- Создатель группы
      FOREIGN KEY (creator_id) REFERENCES users(id)
    )
  `);

  // Таблица участников групп
  db.run(`
    CREATE TABLE IF NOT EXISTS group_members (
      group_id INTEGER,                         -- ID группы
      user_id INTEGER,                          -- ID пользователя
      PRIMARY KEY (group_id, user_id),          -- Составной первичный ключ (уникальность пары)
      FOREIGN KEY (group_id) REFERENCES group_chats(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Таблица папок для хранения файлов
  db.run(`
    CREATE TABLE IF NOT EXISTS folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,     -- ID папки
      name TEXT NOT NULL,                       -- Название папки
      created_by_id INTEGER NOT NULL,           -- Кто создал папку
      created_at TEXT NOT NULL,                 -- Дата создания
      FOREIGN KEY (created_by_id) REFERENCES users(id)
    )
  `);

  // Таблица загруженных файлов
  db.run(`
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,     -- ID файла
      filename TEXT NOT NULL,                   -- Уникальное имя файла на сервере
      originalname TEXT NOT NULL,               -- Имя файла, присвоенное пользователем
      path TEXT NOT NULL,                       -- Путь к файлу на диске
      format TEXT NOT NULL,                     -- Формат файла (например, .jpg, .pdf)
      size INTEGER NOT NULL,                    -- Размер файла в байтах
      uploaded_by_id INTEGER NOT NULL,          -- Кто загрузил файл
      uploaded_at TEXT NOT NULL,                -- Когда файл был загружен
      folder_id INTEGER,                        -- ID папки (если файл размещён в папке)
      FOREIGN KEY (uploaded_by_id) REFERENCES users(id),
      FOREIGN KEY (folder_id) REFERENCES folders(id)
    )
  `);

  // Проверка и добавление folder_id, если столбец отсутствует
  db.all(`PRAGMA table_info(files)`, (err, columns) => {
    if (err) {
      console.error('Error checking files table:', err);
      return;
    }
    const hasFolderId = Array.isArray(columns) && columns.some(col => col.name === 'folder_id');
    if (!hasFolderId) {
      db.run(`ALTER TABLE files ADD COLUMN folder_id INTEGER REFERENCES folders(id)`, (err) => {
        if (err) console.error('Error adding folder_id column:', err);
        else console.log('Added folder_id column to files table');
      });
    } else {
      console.log('Column folder_id already exists in files table');
    }
  });
});

// Экспорт подключения к базе данных для использования в других частях приложения
module.exports = db;
